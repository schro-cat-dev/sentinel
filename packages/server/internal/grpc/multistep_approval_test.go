package grpc

import (
	"context"
	"strings"
	"testing"

	"github.com/schro-cat-dev/sentinel-server/internal/domain"
	"github.com/schro-cat-dev/sentinel-server/internal/engine"
	pb "github.com/schro-cat-dev/sentinel-server/internal/grpc/pb"
	"github.com/schro-cat-dev/sentinel-server/internal/security"
	"github.com/schro-cat-dev/sentinel-server/internal/store"
	"github.com/schro-cat-dev/sentinel-server/internal/task"

	ggrpc "google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
)

// startMultiStepServer は3段階承認ルーティングルール付きテストサーバ
func startMultiStepServer(t *testing.T) (pb.SentinelServiceClient, *store.SQLiteStore, func()) {
	t.Helper()

	rules := []domain.TaskRule{
		{
			RuleID: "manual-comp", EventName: "COMPLIANCE_VIOLATION",
			Severity: domain.SeverityMedium, ActionType: domain.ActionEscalate,
			ExecutionLevel: domain.ExecLevelManual, Priority: 1,
			Description: "Escalate compliance",
			Guardrails:  domain.Guardrails{RequireHumanApproval: true},
		},
	}

	// ルーティングルール: level 4-5 → 2ステップ、level 6 → 3ステップ
	routingRules := []domain.ApprovalRoutingRule{
		{
			RuleID: "med-review", MinLevel: domain.LogLevelWarn, MaxLevel: domain.LogLevelError,
			Chain: []domain.ApprovalChainStep{
				{StepOrder: 1, Role: "team_lead", Required: true},
				{StepOrder: 2, Role: "manager", Required: true},
			},
		},
		{
			RuleID: "crit-review", MinLevel: domain.LogLevelCritical, MaxLevel: domain.LogLevelCritical,
			Chain: []domain.ApprovalChainStep{
				{StepOrder: 1, Role: "team_lead", Required: true},
				{StepOrder: 2, Role: "manager", Required: true},
				{StepOrder: 3, Role: "ciso", Required: true},
			},
		},
	}

	cfg := engine.PipelineConfig{
		ServiceID: "multistep-test", EnableHashChain: true, EnableMasking: true,
		TaskRules: rules, HMACKey: []byte("multistep-test-hmac-32-bytes-key!"),
		MaskingRules:  []security.MaskingRule{{Type: "PII_TYPE", Category: "EMAIL"}},
		RoutingRules: routingRules,
	}

	st, _ := store.NewSQLiteStore(":memory:")
	executor := task.NewTaskExecutor(nil)

	srv, lis, _ := StartServer("localhost:0", cfg, executor, st, nil)
	go srv.Serve(lis)

	conn, _ := ggrpc.NewClient(lis.Addr().String(), ggrpc.WithTransportCredentials(insecure.NewCredentials()))
	client := pb.NewSentinelServiceClient(conn)
	cleanup := func() { conn.Close(); srv.Stop(); st.Close() }
	return client, st, cleanup
}

// E2E: 2ステップ承認チェーン (level 4 compliance → 2 approvals → execute)
func TestE2E_MultiStepApproval_2Steps(t *testing.T) {
	client, st, cleanup := startMultiStepServer(t)
	defer cleanup()
	ctx := context.Background()

	// 1. Ingest compliance violation (level 4 → 2-step chain)
	resp, _ := client.Ingest(ctx, &pb.IngestRequest{
		Message: "Data retention policy violation detected",
		Type: "COMPLIANCE", Level: 4,
	})
	if len(resp.TasksGenerated) == 0 {
		t.Fatal("expected blocked task")
	}
	taskID := resp.TasksGenerated[0].TaskId

	// Verify approval has 2 steps
	approval, _ := st.GetApprovalByTaskID(ctx, taskID)
	if approval == nil {
		t.Fatal("expected approval")
	}
	if approval.TotalSteps != 2 {
		t.Errorf("expected 2 total steps, got %d", approval.TotalSteps)
	}
	if approval.CurrentStep != 1 {
		t.Errorf("expected current step 1, got %d", approval.CurrentStep)
	}
	if approval.ContentHash == "" {
		t.Error("expected content hash to be set")
	}

	// 2. Step 1 approval (team_lead)
	approveResp1, err := client.ApproveTask(ctx, &pb.ApproveTaskRequest{
		TaskId: taskID, ApproverId: "team-lead-001", Reason: "Verified by team lead",
	})
	if err != nil {
		t.Fatalf("step 1 approve error: %v", err)
	}
	if !strings.Contains(approveResp1.Status, "step_1_of_2") {
		t.Errorf("expected step_1_of_2 status, got %s", approveResp1.Status)
	}

	// Verify step record was created
	records, _ := st.GetApprovalStepRecords(ctx, approval.ApprovalID)
	if len(records) != 1 {
		t.Fatalf("expected 1 step record, got %d", len(records))
	}
	if records[0].ActorID != "team-lead-001" {
		t.Errorf("expected team-lead-001, got %s", records[0].ActorID)
	}
	if records[0].ContentHash != approval.ContentHash {
		t.Error("step record should contain content hash")
	}

	// 3. Step 2 approval (manager) → final → dispatched
	approveResp2, err := client.ApproveTask(ctx, &pb.ApproveTaskRequest{
		TaskId: taskID, ApproverId: "manager-001", Reason: "Confirmed by manager",
	})
	if err != nil {
		t.Fatalf("step 2 approve error: %v", err)
	}
	if approveResp2.Status != "dispatched" {
		t.Errorf("expected dispatched, got %s", approveResp2.Status)
	}

	// Verify 2 step records total
	records2, _ := st.GetApprovalStepRecords(ctx, approval.ApprovalID)
	if len(records2) != 2 {
		t.Fatalf("expected 2 step records, got %d", len(records2))
	}

	// Verify task is dispatched
	task, _ := st.GetTask(ctx, taskID)
	if task.Status != domain.StatusDispatched {
		t.Errorf("expected dispatched, got %s", task.Status)
	}
}

// E2E: 2ステップ承認でstep1で却下 → 全体却下
func TestE2E_MultiStepApproval_RejectAtStep1(t *testing.T) {
	client, st, cleanup := startMultiStepServer(t)
	defer cleanup()
	ctx := context.Background()

	resp, _ := client.Ingest(ctx, &pb.IngestRequest{
		Message: "Compliance violation detected", Type: "COMPLIANCE", Level: 4,
	})
	taskID := resp.TasksGenerated[0].TaskId

	// Reject at step 1
	rejectResp, err := client.RejectTask(ctx, &pb.RejectTaskRequest{
		TaskId: taskID, RejectorId: "team-lead-001", Reason: "False positive",
	})
	if err != nil {
		t.Fatalf("reject error: %v", err)
	}
	if rejectResp.Status != "rejected" {
		t.Errorf("expected rejected, got %s", rejectResp.Status)
	}

	// Verify rejection step record
	approval, _ := st.GetApprovalByTaskID(ctx, taskID)
	records, _ := st.GetApprovalStepRecords(ctx, approval.ApprovalID)
	if len(records) != 1 {
		t.Fatalf("expected 1 record, got %d", len(records))
	}
	if records[0].Action != "rejected" {
		t.Errorf("expected rejected action, got %s", records[0].Action)
	}

	// Cannot approve after rejection
	_, err = client.ApproveTask(ctx, &pb.ApproveTaskRequest{
		TaskId: taskID, ApproverId: "manager", Reason: "override",
	})
	if err == nil {
		t.Error("should not approve rejected task")
	}
}

// E2E: コンテンツハッシュ検証
func TestE2E_ContentHashVerification(t *testing.T) {
	client, st, cleanup := startMultiStepServer(t)
	defer cleanup()
	ctx := context.Background()

	resp, _ := client.Ingest(ctx, &pb.IngestRequest{
		Message: "Compliance violation detected", Type: "COMPLIANCE", Level: 4,
	})
	taskID := resp.TasksGenerated[0].TaskId

	// Verify content hash was set
	approval, _ := st.GetApprovalByTaskID(ctx, taskID)
	if approval.ContentHash == "" {
		t.Fatal("content hash should be set")
	}

	// Normal approval should work (hash matches)
	_, err := client.ApproveTask(ctx, &pb.ApproveTaskRequest{
		TaskId: taskID, ApproverId: "lead", Reason: "ok",
	})
	if err != nil {
		t.Fatalf("normal approve should work: %v", err)
	}
}

// E2E: ルーティングルールなし → デフォルト1ステップ
func TestE2E_DefaultSingleStep(t *testing.T) {
	// Use original test server (no routing rules)
	client, st, cleanup := startTestServer(t)
	defer cleanup()
	ctx := context.Background()

	resp, _ := client.Ingest(ctx, &pb.IngestRequest{
		Message: "Compliance violation detected", Type: "COMPLIANCE", Level: 4,
	})
	taskID := resp.TasksGenerated[0].TaskId

	approval, _ := st.GetApprovalByTaskID(ctx, taskID)
	if approval == nil {
		t.Fatal("expected approval")
	}
	// No routing rules → default 1 step
	if approval.TotalSteps != 1 {
		t.Errorf("expected 1 step (default), got %d", approval.TotalSteps)
	}

	// Single approve → dispatched
	approveResp, _ := client.ApproveTask(ctx, &pb.ApproveTaskRequest{
		TaskId: taskID, ApproverId: "admin", Reason: "ok",
	})
	if approveResp.Status != "dispatched" {
		t.Errorf("expected dispatched, got %s", approveResp.Status)
	}
}
