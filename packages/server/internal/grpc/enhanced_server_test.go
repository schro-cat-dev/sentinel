package grpc

import (
	"context"
	"strings"
	"testing"

	ggrpc "google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"

	"github.com/schro-cat-dev/sentinel-server/internal/detection"
	"github.com/schro-cat-dev/sentinel-server/internal/domain"
	"github.com/schro-cat-dev/sentinel-server/internal/engine"
	pb "github.com/schro-cat-dev/sentinel-server/internal/grpc/pb"
	"github.com/schro-cat-dev/sentinel-server/internal/security"
	"github.com/schro-cat-dev/sentinel-server/internal/store"
	"github.com/schro-cat-dev/sentinel-server/internal/task"
)

func startEnhancedTestServer(t *testing.T) (pb.SentinelServiceClient, *store.SQLiteStore, func()) {
	t.Helper()

	cfg := engine.PipelineConfig{
		ServiceID: "grpc-enhanced", EnableHashChain: true, EnableMasking: true,
		HMACKey: []byte("grpc-enhanced-hmac-32-bytes-ok!!x"),
		MaskingRules: []security.MaskingRule{
			{Type: "PII_TYPE", Category: "EMAIL"},
			{Type: "PII_TYPE", Category: "PHONE"},
		},
		TaskRules: []domain.TaskRule{
			{
				RuleID: "sec-ai", EventName: "SECURITY_INTRUSION_DETECTED",
				Severity: domain.SeverityHigh, ActionType: domain.ActionAIAnalyze,
				ExecutionLevel: domain.ExecLevelAuto, Priority: 1,
				Description: "AI analyze intrusion",
			},
			{
				RuleID: "crit-notify", EventName: "SYSTEM_CRITICAL_FAILURE",
				Severity: domain.SeverityHigh, ActionType: domain.ActionSystemNotification,
				ExecutionLevel: domain.ExecLevelAuto, Priority: 1,
				Description: "Notify critical",
			},
		},

		// Ensemble
		EnableEnsemble:    true,
		EnsembleThreshold: 0.5,
		DynamicDetectionRules: []detection.DynamicRuleConfig{
			{
				RuleID: "dyn-brute", EventName: "SECURITY_INTRUSION_DETECTED",
				Priority: "HIGH", Score: 0.95,
				Conditions: detection.DynamicRuleConditions{
					LogTypes: []string{"SECURITY"}, MinLevel: 4,
					MessagePattern: `(?i)brute\s*force`,
				},
				PayloadBuilder: "security_intrusion",
			},
		},

		// Masking verification
		EnableMaskingVerification: true,
	}

	st, _ := store.NewSQLiteStore(":memory:")
	executor := task.NewTaskExecutor(nil)

	srv, lis, err := StartServer("localhost:0", cfg, executor, st, nil)
	if err != nil {
		t.Fatalf("start: %v", err)
	}
	go srv.Serve(lis)

	// Setup threat response on the pipeline
	// (We need to access the pipeline through the server, but StartServer creates it internally.
	// For this test, the threat response orchestrator isn't wired through StartServer.
	// That's actually a valid finding: StartServer doesn't expose Pipeline for post-init config.)

	conn, err := ggrpc.NewClient(lis.Addr().String(), ggrpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		t.Fatalf("dial: %v", err)
	}

	return pb.NewSentinelServiceClient(conn), st, func() { conn.Close(); srv.Stop(); st.Close() }
}

func TestGRPCEnhanced_Ingest_EnsembleDetection(t *testing.T) {
	client, _, cleanup := startEnhancedTestServer(t)
	defer cleanup()

	t.Run("critical log triggers ensemble detection and task generation", func(t *testing.T) {
		resp, err := client.Ingest(context.Background(), &pb.IngestRequest{
			Message: "DB pool exhausted", Type: "SYSTEM", Level: 6,
			IsCritical: true, Boundary: "db-svc",
		})
		if err != nil {
			t.Fatalf("error: %v", err)
		}
		if len(resp.TasksGenerated) == 0 {
			t.Fatal("expected tasks via ensemble")
		}
		if resp.TasksGenerated[0].RuleId != "crit-notify" {
			t.Errorf("expected crit-notify, got %s", resp.TasksGenerated[0].RuleId)
		}
	})

	t.Run("security intrusion via ensemble", func(t *testing.T) {
		resp, err := client.Ingest(context.Background(), &pb.IngestRequest{
			Message: "Suspicious login attempt", Type: "SECURITY", Level: 5,
			Boundary: "auth-svc",
			Tags: []*pb.LogTag{{Key: "ip", Category: "192.168.1.100"}},
		})
		if err != nil {
			t.Fatalf("error: %v", err)
		}
		if len(resp.TasksGenerated) == 0 {
			t.Fatal("expected tasks for security intrusion")
		}
	})

	t.Run("dynamic rule detects brute force via gRPC", func(t *testing.T) {
		resp, err := client.Ingest(context.Background(), &pb.IngestRequest{
			Message: "Brute force attack detected", Type: "SECURITY", Level: 4,
			Boundary: "auth-svc",
		})
		if err != nil {
			t.Fatalf("error: %v", err)
		}
		if len(resp.TasksGenerated) == 0 {
			t.Fatal("expected tasks from dynamic brute force rule")
		}
	})
}

func TestGRPCEnhanced_Ingest_PIIMasking(t *testing.T) {
	client, st, cleanup := startEnhancedTestServer(t)
	defer cleanup()

	resp, err := client.Ingest(context.Background(), &pb.IngestRequest{
		Message: "Contact admin@evil.com phone 090-1234-5678",
		Type: "SECURITY", Level: 5, Boundary: "auth-svc",
	})
	if err != nil {
		t.Fatalf("error: %v", err)
	}
	if !resp.Masked {
		t.Error("expected masked")
	}

	stored, _ := st.GetLogByTraceID(context.Background(), resp.TraceId)
	if stored != nil {
		if strings.Contains(stored.Message, "admin@evil.com") {
			t.Error("email PII leaked through gRPC pipeline")
		}
		if strings.Contains(stored.Message, "090-1234") {
			t.Error("phone PII leaked through gRPC pipeline")
		}
	}
}

func TestGRPCEnhanced_Ingest_HashChain(t *testing.T) {
	client, _, cleanup := startEnhancedTestServer(t)
	defer cleanup()

	traceIDs := make(map[string]bool)
	for i := 0; i < 5; i++ {
		resp, err := client.Ingest(context.Background(), &pb.IngestRequest{
			Message: "Hash chain test", Type: "SYSTEM", Level: 3,
		})
		if err != nil {
			t.Fatalf("error: %v", err)
		}
		if !resp.HashChainValid {
			t.Error("expected hash chain valid")
		}
		if traceIDs[resp.TraceId] {
			t.Error("duplicate traceID")
		}
		traceIDs[resp.TraceId] = true
	}
}

func TestGRPCEnhanced_Ingest_NormalLogNoTasks(t *testing.T) {
	client, _, cleanup := startEnhancedTestServer(t)
	defer cleanup()

	resp, err := client.Ingest(context.Background(), &pb.IngestRequest{
		Message: "All systems operational", Type: "SYSTEM", Level: 3,
	})
	if err != nil {
		t.Fatalf("error: %v", err)
	}
	if len(resp.TasksGenerated) != 0 {
		t.Error("normal log should not generate tasks")
	}
}

func TestGRPCEnhanced_Ingest_AIAgentSkipped(t *testing.T) {
	client, _, cleanup := startEnhancedTestServer(t)
	defer cleanup()

	resp, err := client.Ingest(context.Background(), &pb.IngestRequest{
		Message: "Agent analysis result", Type: "SECURITY", Level: 5,
		Origin: "AI_AGENT",
	})
	if err != nil {
		t.Fatalf("error: %v", err)
	}
	if len(resp.TasksGenerated) != 0 {
		t.Error("AI_AGENT log should not trigger tasks")
	}
}

func TestGRPCEnhanced_Ingest_WithAllFields(t *testing.T) {
	client, st, cleanup := startEnhancedTestServer(t)
	defer cleanup()

	resp, err := client.Ingest(context.Background(), &pb.IngestRequest{
		TraceId: "custom-trace-001",
		Message: "Full field test",
		Type:    "SECURITY", Level: 5,
		Boundary:  "test-svc",
		ServiceId: "svc-001",
		ActorId:   "user-123",
		SpanId:    "span-001",
		Origin:    "SYSTEM",
		Tags: []*pb.LogTag{
			{Key: "ip", Category: "10.0.0.1"},
			{Key: "user_agent", Category: "curl/7.0"},
		},
		ResourceIds: []string{"res-1", "res-2"},
		Input:       "some input data",
		Details:     map[string]string{"key1": "val1", "key2": "val2"},
		AiContext: &pb.AIContext{
			AgentId: "agent-1", TaskId: "task-1",
			LoopDepth: 0, Model: "gpt-4",
			Confidence: 0.95, ReasoningTrace: "analyzed pattern",
		},
		AgentBackLog: []*pb.AgentBackLogEntry{
			{AgentId: "agent-1", Action: "analyze", Status: "success", Result: "clean"},
		},
	})
	if err != nil {
		t.Fatalf("error: %v", err)
	}
	if resp.TraceId != "custom-trace-001" {
		t.Errorf("expected custom trace ID, got %s", resp.TraceId)
	}

	stored, _ := st.GetLogByTraceID(context.Background(), resp.TraceId)
	if stored == nil {
		t.Fatal("should be persisted")
	}
	if stored.ActorID != "user-123" {
		t.Errorf("actorId mismatch: %s", stored.ActorID)
	}
	if stored.ServiceID != "grpc-enhanced" { // normalized to pipeline service_id
		t.Errorf("serviceId should be normalized: %s", stored.ServiceID)
	}
}

func TestGRPCEnhanced_Pentest_NullByte(t *testing.T) {
	client, _, cleanup := startEnhancedTestServer(t)
	defer cleanup()

	_, err := client.Ingest(context.Background(), &pb.IngestRequest{
		Message: "hello\x00world",
	})
	if err == nil {
		t.Error("null byte should be rejected at pipeline level")
	}
}

func TestGRPCEnhanced_Pentest_SQLInjection(t *testing.T) {
	client, st, cleanup := startEnhancedTestServer(t)
	defer cleanup()

	resp, err := client.Ingest(context.Background(), &pb.IngestRequest{
		Message: "'; DROP TABLE logs; --",
	})
	if err != nil {
		t.Fatalf("SQL injection should be safely stored: %v", err)
	}
	stored, _ := st.GetLogByTraceID(context.Background(), resp.TraceId)
	if stored == nil {
		t.Error("SQL injection should be stored safely (parameterized queries)")
	}
}

func TestGRPCEnhanced_ApprovalWorkflow_FullCycle(t *testing.T) {
	st, _ := store.NewSQLiteStore(":memory:")
	defer st.Close()

	cfg := engine.PipelineConfig{
		ServiceID: "approval-test", EnableHashChain: true,
		HMACKey: []byte("approval-test-hmac-32-bytes-ok!!x"),
		TaskRules: []domain.TaskRule{
			{
				RuleID: "comp-manual", EventName: "COMPLIANCE_VIOLATION",
				Severity: domain.SeverityMedium, ActionType: domain.ActionEscalate,
				ExecutionLevel: domain.ExecLevelManual, Priority: 1,
				Description: "Manual compliance", Guardrails: domain.Guardrails{RequireHumanApproval: true},
			},
		},
		RoutingRules: []domain.ApprovalRoutingRule{
			{
				RuleID: "comp-route", MinLevel: 1, MaxLevel: 6,
				EventName: "COMPLIANCE_VIOLATION",
				Chain: []domain.ApprovalChainStep{
					{StepOrder: 1, Role: "team_lead", Required: true},
					{StepOrder: 2, Role: "manager", Required: true},
				},
			},
		},
	}

	executor := task.NewTaskExecutor(nil)
	srv, lis, _ := StartServer("localhost:0", cfg, executor, st, nil)
	go srv.Serve(lis)
	defer srv.Stop()

	conn, _ := ggrpc.NewClient(lis.Addr().String(), ggrpc.WithTransportCredentials(insecure.NewCredentials()))
	defer conn.Close()
	client := pb.NewSentinelServiceClient(conn)
	ctx := context.Background()

	// 1. Ingest compliance violation
	ingestResp, err := client.Ingest(ctx, &pb.IngestRequest{
		Message: "Data retention policy violation detected",
		Type: "COMPLIANCE", Level: 4,
	})
	if err != nil {
		t.Fatalf("ingest: %v", err)
	}
	if len(ingestResp.TasksGenerated) == 0 {
		t.Fatal("expected blocked task")
	}
	taskID := ingestResp.TasksGenerated[0].TaskId
	if ingestResp.TasksGenerated[0].Status != "blocked_approval" {
		t.Fatalf("expected blocked_approval, got %s", ingestResp.TasksGenerated[0].Status)
	}

	// 2. Check task status
	statusResp, err := client.GetTaskStatus(ctx, &pb.GetTaskStatusRequest{TaskId: taskID})
	if err != nil {
		t.Fatalf("get status: %v", err)
	}
	if statusResp.Status != "blocked_approval" {
		t.Errorf("expected blocked_approval, got %s", statusResp.Status)
	}

	// 3. Approve step 1 (team_lead)
	approveResp1, err := client.ApproveTask(ctx, &pb.ApproveTaskRequest{
		TaskId: taskID, ApproverId: "lead-1", Reason: "Verified",
	})
	if err != nil {
		t.Fatalf("approve step 1: %v", err)
	}
	if !strings.Contains(approveResp1.Status, "step_1_of_2") {
		t.Errorf("expected step 1 of 2, got %s", approveResp1.Status)
	}

	// 4. Approve step 2 (manager) → task should execute
	approveResp2, err := client.ApproveTask(ctx, &pb.ApproveTaskRequest{
		TaskId: taskID, ApproverId: "mgr-1", Reason: "Final approval",
	})
	if err != nil {
		t.Fatalf("approve step 2: %v", err)
	}
	if approveResp2.Status != "dispatched" {
		t.Errorf("expected dispatched after final approval, got %s", approveResp2.Status)
	}

	// 5. Verify final task status
	finalStatus, _ := client.GetTaskStatus(ctx, &pb.GetTaskStatusRequest{TaskId: taskID})
	if finalStatus.Status != "dispatched" {
		t.Errorf("final status should be dispatched, got %s", finalStatus.Status)
	}
}

func TestGRPCEnhanced_RejectWorkflow(t *testing.T) {
	st, _ := store.NewSQLiteStore(":memory:")
	defer st.Close()

	cfg := engine.PipelineConfig{
		ServiceID: "reject-test", EnableHashChain: true,
		HMACKey: []byte("reject-test-hmac-key-32-bytes-ok!"),
		TaskRules: []domain.TaskRule{
			{
				RuleID: "comp-manual", EventName: "COMPLIANCE_VIOLATION",
				Severity: domain.SeverityMedium, ActionType: domain.ActionEscalate,
				ExecutionLevel: domain.ExecLevelManual, Priority: 1,
			},
		},
	}

	executor := task.NewTaskExecutor(nil)
	srv, lis, _ := StartServer("localhost:0", cfg, executor, st, nil)
	go srv.Serve(lis)
	defer srv.Stop()

	conn, _ := ggrpc.NewClient(lis.Addr().String(), ggrpc.WithTransportCredentials(insecure.NewCredentials()))
	defer conn.Close()
	client := pb.NewSentinelServiceClient(conn)
	ctx := context.Background()

	// Ingest + block
	ingestResp, _ := client.Ingest(ctx, &pb.IngestRequest{
		Message: "Compliance violation detected", Type: "COMPLIANCE", Level: 4,
	})
	taskID := ingestResp.TasksGenerated[0].TaskId

	// Reject
	rejectResp, err := client.RejectTask(ctx, &pb.RejectTaskRequest{
		TaskId: taskID, RejectorId: "reviewer-1", Reason: "False positive",
	})
	if err != nil {
		t.Fatalf("reject: %v", err)
	}
	if rejectResp.Status != "rejected" {
		t.Errorf("expected rejected, got %s", rejectResp.Status)
	}

	// Verify can't approve after reject
	_, err = client.ApproveTask(ctx, &pb.ApproveTaskRequest{
		TaskId: taskID, ApproverId: "admin",
	})
	if err == nil {
		t.Error("should not approve rejected task")
	}
}

func TestGRPCEnhanced_ListTasks(t *testing.T) {
	client, _, cleanup := startEnhancedTestServer(t)
	defer cleanup()
	ctx := context.Background()

	// Ingest some logs that generate tasks
	for i := 0; i < 3; i++ {
		client.Ingest(ctx, &pb.IngestRequest{
			Message: "Critical failure", IsCritical: true, Level: 6,
		})
	}

	resp, err := client.ListTasks(ctx, &pb.ListTasksRequest{Limit: 10})
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	if resp.TotalCount < 3 {
		t.Errorf("expected at least 3 tasks, got %d", resp.TotalCount)
	}
}

func TestGRPCEnhanced_ThreatResponse_IntegrationViaServer(t *testing.T) {
	// This test verifies that even though StartServer doesn't wire ThreatOrchestrator,
	// the pipeline still processes correctly (threat response is nil → skipped gracefully)
	client, _, cleanup := startEnhancedTestServer(t)
	defer cleanup()

	resp, err := client.Ingest(context.Background(), &pb.IngestRequest{
		Message: "Security intrusion from 10.0.0.99",
		Type: "SECURITY", Level: 5, Boundary: "auth-svc",
		Tags: []*pb.LogTag{{Key: "ip", Category: "10.0.0.99"}},
	})
	if err != nil {
		t.Fatalf("error: %v", err)
	}
	// ThreatResponses not in proto yet, but pipeline should not crash
	if len(resp.TasksGenerated) == 0 {
		t.Fatal("tasks should still be generated")
	}
}

func TestGRPCEnhanced_NewSentinelServer_ExposePipeline(t *testing.T) {
	// Verify that NewSentinelServer can be used to create a server with custom pipeline setup
	cfg := engine.PipelineConfig{
		ServiceID: "custom-test",
		HMACKey:   []byte("custom-test-hmac-key-32-bytes-ok!"),
		EnableHashChain: true,
	}
	st, _ := store.NewSQLiteStore(":memory:")
	defer st.Close()

	executor := task.NewTaskExecutor(nil)
	server, err := NewSentinelServer(cfg, executor, st, nil)
	if err != nil {
		t.Fatalf("error: %v", err)
	}

	// Pipeline accessible for post-init setup (threat orchestrator, agent bridge etc)
	// Currently pipeline is private — this documents the limitation
	_ = server

	// For now, verify the server works via direct call
	resp, err := server.Ingest(context.Background(), &pb.IngestRequest{
		Message: "Direct call test",
	})
	if err != nil {
		t.Fatalf("direct ingest: %v", err)
	}
	if resp.TraceId == "" {
		t.Error("expected traceId")
	}
}
