package grpc

import (
	"context"
	"testing"

	ggrpc "google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"

	"github.com/schro-cat-dev/sentinel-server/internal/domain"
	"github.com/schro-cat-dev/sentinel-server/internal/engine"
	pb "github.com/schro-cat-dev/sentinel-server/internal/grpc/pb"
	"github.com/schro-cat-dev/sentinel-server/internal/security"
	"github.com/schro-cat-dev/sentinel-server/internal/store"
	"github.com/schro-cat-dev/sentinel-server/internal/task"
)

func startTestServer(t *testing.T) (pb.SentinelServiceClient, *store.SQLiteStore, func()) {
	t.Helper()

	rules := []domain.TaskRule{
		{
			RuleID: "crit-notify", EventName: "SYSTEM_CRITICAL_FAILURE",
			Severity: domain.SeverityHigh, ActionType: domain.ActionSystemNotification,
			ExecutionLevel: domain.ExecLevelAuto, Priority: 1,
			Description: "Notify critical failure",
			Guardrails:  domain.Guardrails{TimeoutMs: 30000},
		},
		{
			RuleID: "manual-task", EventName: "COMPLIANCE_VIOLATION",
			Severity: domain.SeverityMedium, ActionType: domain.ActionEscalate,
			ExecutionLevel: domain.ExecLevelManual, Priority: 1,
			Description: "Escalate compliance",
			Guardrails:  domain.Guardrails{RequireHumanApproval: true, TimeoutMs: 30000},
		},
	}

	cfg := engine.PipelineConfig{
		ServiceID: "test-grpc-svc", EnableHashChain: true, EnableMasking: true,
		TaskRules: rules, HMACKey: []byte("test-grpc-hmac-key-32-bytes-long!"),
		MaskingRules: []security.MaskingRule{
			{Type: "PII_TYPE", Category: "EMAIL"},
			{Type: "PII_TYPE", Category: "CREDIT_CARD"},
		},
	}

	st, _ := store.NewSQLiteStore(":memory:")
	executor := task.NewTaskExecutor(nil)

	srv, lis, err := StartServer("localhost:0", cfg, executor, st, nil)
	if err != nil {
		t.Fatalf("start server: %v", err)
	}
	go srv.Serve(lis)

	conn, err := ggrpc.NewClient(lis.Addr().String(), ggrpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		t.Fatalf("dial: %v", err)
	}

	client := pb.NewSentinelServiceClient(conn)
	cleanup := func() { conn.Close(); srv.Stop(); st.Close() }
	return client, st, cleanup
}

func TestGRPC_HealthCheck(t *testing.T) {
	client, _, cleanup := startTestServer(t)
	defer cleanup()

	resp, err := client.HealthCheck(context.Background(), &pb.HealthCheckRequest{})
	if err != nil {
		t.Fatalf("error: %v", err)
	}
	if resp.Status != "SERVING" {
		t.Errorf("expected SERVING, got %s", resp.Status)
	}
	if resp.Version != "0.2.0" {
		t.Errorf("expected 0.2.0, got %s", resp.Version)
	}
}

func TestGRPC_Ingest_SimpleLog(t *testing.T) {
	client, st, cleanup := startTestServer(t)
	defer cleanup()

	resp, err := client.Ingest(context.Background(), &pb.IngestRequest{
		Message: "Hello from gRPC", Type: "SYSTEM", Level: 3,
	})
	if err != nil {
		t.Fatalf("error: %v", err)
	}
	if resp.TraceId == "" {
		t.Error("expected traceId")
	}
	if !resp.HashChainValid {
		t.Error("expected hash chain valid")
	}

	// Verify log persisted
	log, _ := st.GetLogByTraceID(context.Background(), resp.TraceId)
	if log == nil {
		t.Error("log should be persisted in store")
	}
}

func TestGRPC_Ingest_CriticalLog(t *testing.T) {
	client, st, cleanup := startTestServer(t)
	defer cleanup()

	resp, err := client.Ingest(context.Background(), &pb.IngestRequest{
		Message: "DB pool exhausted", Type: "SYSTEM", Level: 6,
		IsCritical: true, Boundary: "db-service:pool",
	})
	if err != nil {
		t.Fatalf("error: %v", err)
	}
	if len(resp.TasksGenerated) == 0 {
		t.Fatal("expected tasks")
	}
	if resp.TasksGenerated[0].RuleId != "crit-notify" {
		t.Errorf("expected crit-notify, got %s", resp.TasksGenerated[0].RuleId)
	}

	// Verify task persisted
	stored, _ := st.GetTask(context.Background(), resp.TasksGenerated[0].TaskId)
	if stored == nil {
		t.Error("task should be persisted")
	}
}

func TestGRPC_Ingest_ComplianceViolation_CreatesApproval(t *testing.T) {
	client, st, cleanup := startTestServer(t)
	defer cleanup()

	resp, err := client.Ingest(context.Background(), &pb.IngestRequest{
		Message: "Data retention policy violation detected",
		Type: "COMPLIANCE", Level: 4,
	})
	if err != nil {
		t.Fatalf("error: %v", err)
	}
	if len(resp.TasksGenerated) == 0 {
		t.Fatal("expected tasks")
	}
	if resp.TasksGenerated[0].Status != "blocked_approval" {
		t.Errorf("expected blocked_approval, got %s", resp.TasksGenerated[0].Status)
	}

	// Verify approval request created
	taskID := resp.TasksGenerated[0].TaskId
	approval, _ := st.GetApprovalByTaskID(context.Background(), taskID)
	if approval == nil {
		t.Fatal("approval request should exist")
	}
	if approval.Status != "pending" {
		t.Errorf("approval should be pending, got %s", approval.Status)
	}
}

func TestGRPC_Ingest_EmptyMessage(t *testing.T) {
	client, _, cleanup := startTestServer(t)
	defer cleanup()

	_, err := client.Ingest(context.Background(), &pb.IngestRequest{Message: ""})
	if err == nil {
		t.Error("expected error")
	}
}

func TestGRPC_Ingest_AIAgentNoRedetect(t *testing.T) {
	client, _, cleanup := startTestServer(t)
	defer cleanup()

	resp, err := client.Ingest(context.Background(), &pb.IngestRequest{
		Message: "Agent report", Type: "SECURITY", Level: 5, Origin: "AI_AGENT",
	})
	if err != nil {
		t.Fatalf("error: %v", err)
	}
	if len(resp.TasksGenerated) != 0 {
		t.Error("AI_AGENT should not trigger tasks")
	}
}
