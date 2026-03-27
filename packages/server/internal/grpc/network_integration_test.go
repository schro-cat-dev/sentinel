package grpc

import (
	"context"
	"strings"
	"testing"

	ggrpc "google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/status"

	"github.com/schro-cat-dev/sentinel-server/internal/detection"
	"github.com/schro-cat-dev/sentinel-server/internal/domain"
	"github.com/schro-cat-dev/sentinel-server/internal/engine"
	pb "github.com/schro-cat-dev/sentinel-server/internal/grpc/pb"
	"github.com/schro-cat-dev/sentinel-server/internal/security"
	"github.com/schro-cat-dev/sentinel-server/internal/store"
	"github.com/schro-cat-dev/sentinel-server/internal/task"
)

// startNetworkTestServer はフル機能サーバを起動しクライアントを返す
func startNetworkTestServer(t *testing.T) (pb.SentinelServiceClient, func()) {
	t.Helper()
	st, _ := store.NewSQLiteStore(":memory:")

	cfg := engine.PipelineConfig{
		ServiceID: "network-test", EnableHashChain: true, EnableMasking: true,
		HMACKey: []byte("network-test-hmac-32-bytes-ok!!xx"),
		MaskingRules: []security.MaskingRule{
			{Type: "PII_TYPE", Category: "EMAIL"},
			{Type: "PII_TYPE", Category: "PHONE"},
		},
		EnableEnsemble: true, EnsembleThreshold: 0.5,
		EnableMaskingVerification: true,
		EnableAnomalyDetection:   true, AnomalyConfig: detection.DefaultAnomalyConfig(),
		TaskRules: []domain.TaskRule{
			{RuleID: "sec-ai", EventName: "SECURITY_INTRUSION_DETECTED", Severity: domain.SeverityHigh,
				ActionType: domain.ActionAIAnalyze, ExecutionLevel: domain.ExecLevelAuto, Priority: 1},
			{RuleID: "crit-notify", EventName: "SYSTEM_CRITICAL_FAILURE", Severity: domain.SeverityHigh,
				ActionType: domain.ActionSystemNotification, ExecutionLevel: domain.ExecLevelAuto, Priority: 1},
		},
	}

	executor := task.NewTaskExecutor(nil)
	srv, lis, _ := StartServer("localhost:0", cfg, executor, st, nil)
	go srv.Serve(lis)

	conn, _ := ggrpc.NewClient(lis.Addr().String(), ggrpc.WithTransportCredentials(insecure.NewCredentials()))
	client := pb.NewSentinelServiceClient(conn)
	return client, func() { conn.Close(); srv.Stop(); st.Close() }
}

func TestNetwork_FullE2E_NormalLog(t *testing.T) {
	client, cleanup := startNetworkTestServer(t)
	defer cleanup()

	resp, err := client.Ingest(context.Background(), &pb.IngestRequest{
		Message: "All systems operational", Type: "SYSTEM", Level: 3,
	})
	if err != nil {
		t.Fatalf("error: %v", err)
	}
	if resp.TraceId == "" {
		t.Error("missing traceId")
	}
	if !resp.HashChainValid {
		t.Error("hash chain should be valid")
	}
	if !resp.Masked {
		t.Error("should be masked")
	}
	if len(resp.TasksGenerated) != 0 {
		t.Error("normal log should not generate tasks")
	}
}

func TestNetwork_FullE2E_SecurityIntrusion(t *testing.T) {
	client, cleanup := startNetworkTestServer(t)
	defer cleanup()

	resp, err := client.Ingest(context.Background(), &pb.IngestRequest{
		Message: "Brute force from admin@evil.com",
		Type: "SECURITY", Level: 5, Boundary: "auth-svc",
		Tags: []*pb.LogTag{{Key: "ip", Category: "10.0.0.99"}},
	})
	if err != nil {
		t.Fatalf("error: %v", err)
	}
	if len(resp.TasksGenerated) == 0 {
		t.Fatal("security intrusion should generate tasks")
	}
	if resp.TasksGenerated[0].Status != "dispatched" {
		t.Errorf("expected dispatched, got %s", resp.TasksGenerated[0].Status)
	}
}

func TestNetwork_FullE2E_PIIMasking(t *testing.T) {
	client, cleanup := startNetworkTestServer(t)
	defer cleanup()

	resp, err := client.Ingest(context.Background(), &pb.IngestRequest{
		Message: "Contact admin@test.com phone 090-1234-5678",
	})
	if err != nil {
		t.Fatalf("error: %v", err)
	}
	if !resp.Masked {
		t.Error("should be masked")
	}
	// Can't directly check stored message from client, but masking should be active
}

func TestNetwork_FullE2E_CriticalLog(t *testing.T) {
	client, cleanup := startNetworkTestServer(t)
	defer cleanup()

	resp, err := client.Ingest(context.Background(), &pb.IngestRequest{
		Message: "DB pool exhausted", IsCritical: true, Level: 6,
	})
	if err != nil {
		t.Fatalf("error: %v", err)
	}
	if len(resp.TasksGenerated) == 0 {
		t.Fatal("critical should generate tasks")
	}
	if resp.TasksGenerated[0].RuleId != "crit-notify" {
		t.Errorf("expected crit-notify, got %s", resp.TasksGenerated[0].RuleId)
	}
}

func TestNetwork_FullE2E_HashChainContinuity(t *testing.T) {
	client, cleanup := startNetworkTestServer(t)
	defer cleanup()

	seen := map[string]bool{}
	for i := 0; i < 10; i++ {
		resp, err := client.Ingest(context.Background(), &pb.IngestRequest{
			Message: "Chain test",
		})
		if err != nil {
			t.Fatalf("error: %v", err)
		}
		if !resp.HashChainValid {
			t.Errorf("chain %d invalid", i)
		}
		if seen[resp.TraceId] {
			t.Error("duplicate traceId")
		}
		seen[resp.TraceId] = true
	}
}

func TestNetwork_FullE2E_AIAgentLoopPrevention(t *testing.T) {
	client, cleanup := startNetworkTestServer(t)
	defer cleanup()

	resp, err := client.Ingest(context.Background(), &pb.IngestRequest{
		Message: "Agent result", Type: "SECURITY", Level: 5, Origin: "AI_AGENT",
	})
	if err != nil {
		t.Fatalf("error: %v", err)
	}
	if len(resp.TasksGenerated) != 0 {
		t.Error("AI_AGENT should not trigger tasks")
	}
}

func TestNetwork_FullE2E_InputValidation(t *testing.T) {
	client, cleanup := startNetworkTestServer(t)
	defer cleanup()

	t.Run("empty message", func(t *testing.T) {
		_, err := client.Ingest(context.Background(), &pb.IngestRequest{Message: ""})
		if err == nil {
			t.Error("expected error")
		}
		st, _ := status.FromError(err)
		if st.Code() != codes.InvalidArgument {
			t.Errorf("expected InvalidArgument, got %v", st.Code())
		}
	})

	t.Run("null byte", func(t *testing.T) {
		_, err := client.Ingest(context.Background(), &pb.IngestRequest{Message: "a\x00b"})
		if err == nil {
			t.Error("expected error")
		}
	})

	t.Run("SQL injection safe", func(t *testing.T) {
		resp, err := client.Ingest(context.Background(), &pb.IngestRequest{
			Message: "'; DROP TABLE logs; --",
		})
		if err != nil {
			t.Fatalf("SQL injection should be safely stored: %v", err)
		}
		if resp.TraceId == "" {
			t.Error("should have traceId")
		}
	})

	t.Run("XSS safe", func(t *testing.T) {
		_, err := client.Ingest(context.Background(), &pb.IngestRequest{
			Message: "<script>alert('xss')</script>",
		})
		if err != nil {
			t.Fatalf("XSS should be safe in gRPC: %v", err)
		}
	})
}

func TestNetwork_FullE2E_LargePayload(t *testing.T) {
	client, cleanup := startNetworkTestServer(t)
	defer cleanup()

	resp, err := client.Ingest(context.Background(), &pb.IngestRequest{
		Message: strings.Repeat("x", 60000), // under 65536 limit
	})
	if err != nil {
		t.Fatalf("large payload should work: %v", err)
	}
	if resp.TraceId == "" {
		t.Error("should have traceId")
	}
}

func TestNetwork_FullE2E_OversizedPayload(t *testing.T) {
	client, cleanup := startNetworkTestServer(t)
	defer cleanup()

	_, err := client.Ingest(context.Background(), &pb.IngestRequest{
		Message: strings.Repeat("x", 70000), // over 65536 limit
	})
	if err == nil {
		t.Error("oversized payload should be rejected")
	}
}

func TestNetwork_FullE2E_AllFields(t *testing.T) {
	client, cleanup := startNetworkTestServer(t)
	defer cleanup()

	resp, err := client.Ingest(context.Background(), &pb.IngestRequest{
		TraceId:   "custom-trace-net",
		Message:   "Full field network test",
		Type:      "SECURITY", Level: 5,
		Boundary:  "test-svc", ServiceId: "svc-001",
		ActorId:   "user-123", SpanId: "span-001",
		Origin:    "SYSTEM", IsCritical: false,
		Tags:      []*pb.LogTag{{Key: "ip", Category: "10.0.0.1"}},
		ResourceIds: []string{"res-1"},
		Input:     "some input",
		Details:   map[string]string{"k": "v"},
		AiContext: &pb.AIContext{AgentId: "a1", TaskId: "t1", LoopDepth: 0},
	})
	if err != nil {
		t.Fatalf("error: %v", err)
	}
	if resp.TraceId != "custom-trace-net" {
		t.Errorf("traceId mismatch: %s", resp.TraceId)
	}
}
