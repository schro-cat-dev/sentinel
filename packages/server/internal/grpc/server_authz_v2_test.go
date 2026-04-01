package grpc

import (
	"context"
	"testing"

	ggrpc "google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/status"

	"github.com/schro-cat-dev/sentinel-server/internal/domain"
	"github.com/schro-cat-dev/sentinel-server/internal/engine"
	pb "github.com/schro-cat-dev/sentinel-server/internal/grpc/pb"
	"github.com/schro-cat-dev/sentinel-server/internal/security"
	"github.com/schro-cat-dev/sentinel-server/internal/store"
	"github.com/schro-cat-dev/sentinel-server/internal/task"
)

// mockAuthorizer はテスト用の AuthorizerForApproval 実装
type mockAuthorizer struct {
	canApprove bool
	canRead    bool
}

func (m *mockAuthorizer) CanApprove(clientID string) bool { return m.canApprove }
func (m *mockAuthorizer) CanRead(clientID string) bool    { return m.canRead }

func startTestServerWithAuthz(t *testing.T, auth AuthorizerForApproval) (pb.SentinelServiceClient, *store.SQLiteStore, func()) {
	t.Helper()

	rules := []domain.TaskRule{
		{
			RuleID: "crit-notify", EventName: "SYSTEM_CRITICAL_FAILURE",
			Severity: domain.SeverityHigh, ActionType: domain.ActionSystemNotification,
			ExecutionLevel: domain.ExecLevelAuto, Priority: 1,
			Guardrails:     domain.Guardrails{TimeoutMs: 30000},
		},
	}

	cfg := engine.PipelineConfig{
		ServiceID: "test-authz", EnableHashChain: true,
		TaskRules: rules, HMACKey: []byte("test-authz-hmac-key-32bytes-ok!!"),
		MaskingRules: []security.MaskingRule{{Type: "PII_TYPE", Category: "EMAIL"}},
	}

	st, _ := store.NewSQLiteStore(":memory:")
	executor := task.NewTaskExecutor(nil)

	sentinel, srv, lis, err := StartServerWithSentinel("localhost:0", cfg, executor, st, nil)
	if err != nil {
		t.Fatalf("start server: %v", err)
	}
	sentinel.authorizer = auth

	go srv.Serve(lis)

	conn, err := ggrpc.NewClient(lis.Addr().String(), ggrpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		t.Fatalf("dial: %v", err)
	}

	return pb.NewSentinelServiceClient(conn), st, func() {
		conn.Close()
		srv.Stop()
	}
}

// =========================================================================
// V-7: RejectTask / RejectBlock 認可チェック
// =========================================================================

func TestV7_RejectTaskRequiresCanApprove(t *testing.T) {
	client, _, cleanup := startTestServerWithAuthz(t, &mockAuthorizer{canApprove: false, canRead: true})
	defer cleanup()

	_, err := client.RejectTask(context.Background(), &pb.RejectTaskRequest{
		TaskId:     "nonexistent",
		RejectorId: "user-1",
		Reason:     "test",
	})

	if err == nil {
		t.Fatal("expected PermissionDenied, got nil")
	}
	if s, ok := status.FromError(err); !ok || s.Code() != codes.PermissionDenied {
		t.Fatalf("expected PermissionDenied, got %v", err)
	}
}

func TestV7_RejectBlockRequiresCanApprove(t *testing.T) {
	client, _, cleanup := startTestServerWithAuthz(t, &mockAuthorizer{canApprove: false, canRead: true})
	defer cleanup()

	_, err := client.RejectBlock(context.Background(), &pb.RejectBlockRequest{
		BlockId:    "block-1",
		RejectorId: "user-1",
	})

	if err == nil {
		t.Fatal("expected PermissionDenied, got nil")
	}
	if s, ok := status.FromError(err); !ok || s.Code() != codes.PermissionDenied {
		t.Fatalf("expected PermissionDenied, got %v", err)
	}
}

func TestV7_RejectTaskAllowedWithCanApprove(t *testing.T) {
	client, _, cleanup := startTestServerWithAuthz(t, &mockAuthorizer{canApprove: true, canRead: true})
	defer cleanup()

	// タスクが存在しないので NotFound になるが、PermissionDenied ではないことを確認
	_, err := client.RejectTask(context.Background(), &pb.RejectTaskRequest{
		TaskId:     "nonexistent",
		RejectorId: "user-1",
		Reason:     "test",
	})

	if err == nil {
		t.Fatal("expected error (NotFound), got nil")
	}
	s, ok := status.FromError(err)
	if !ok {
		t.Fatalf("expected gRPC status error, got %v", err)
	}
	if s.Code() == codes.PermissionDenied {
		t.Fatal("should not be PermissionDenied when CanApprove=true")
	}
	// NotFound は期待通り（タスクが存在しない）
	if s.Code() != codes.NotFound {
		t.Logf("unexpected code %v (expected NotFound for nonexistent task)", s.Code())
	}
}

// =========================================================================
// V-8: ListTasks 認可チェック
// =========================================================================

func TestV8_ListTasksRequiresCanRead(t *testing.T) {
	client, _, cleanup := startTestServerWithAuthz(t, &mockAuthorizer{canApprove: true, canRead: false})
	defer cleanup()

	_, err := client.ListTasks(context.Background(), &pb.ListTasksRequest{})

	if err == nil {
		t.Fatal("expected PermissionDenied, got nil")
	}
	if s, ok := status.FromError(err); !ok || s.Code() != codes.PermissionDenied {
		t.Fatalf("expected PermissionDenied, got %v", err)
	}
}

func TestV8_ListTasksAllowedWithCanRead(t *testing.T) {
	client, _, cleanup := startTestServerWithAuthz(t, &mockAuthorizer{canApprove: false, canRead: true})
	defer cleanup()

	resp, err := client.ListTasks(context.Background(), &pb.ListTasksRequest{})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if resp == nil {
		t.Fatal("expected response, got nil")
	}
}

// =========================================================================
// V-9: GetTaskStatus 認可チェック
// =========================================================================

func TestV9_GetTaskStatusRequiresCanRead(t *testing.T) {
	client, _, cleanup := startTestServerWithAuthz(t, &mockAuthorizer{canApprove: true, canRead: false})
	defer cleanup()

	_, err := client.GetTaskStatus(context.Background(), &pb.GetTaskStatusRequest{TaskId: "test-123"})

	if err == nil {
		t.Fatal("expected PermissionDenied, got nil")
	}
	if s, ok := status.FromError(err); !ok || s.Code() != codes.PermissionDenied {
		t.Fatalf("expected PermissionDenied, got %v", err)
	}
}

// =========================================================================
// V-10: GetThreatResponses 認可チェック
// =========================================================================

func TestV10_GetThreatResponsesRequiresCanRead(t *testing.T) {
	client, _, cleanup := startTestServerWithAuthz(t, &mockAuthorizer{canApprove: true, canRead: false})
	defer cleanup()

	_, err := client.GetThreatResponses(context.Background(), &pb.GetThreatResponsesRequest{TraceId: "trace-123"})

	if err == nil {
		t.Fatal("expected PermissionDenied, got nil")
	}
	if s, ok := status.FromError(err); !ok || s.Code() != codes.PermissionDenied {
		t.Fatalf("expected PermissionDenied, got %v", err)
	}
}

// =========================================================================
// V-11: LoopDepth サーバ側リセット
// =========================================================================

func TestV11_LoopDepthResetForNonAgentOrigin(t *testing.T) {
	client, _, cleanup := startTestServerWithAuthz(t, nil)
	defer cleanup()

	// origin=SYSTEM で LoopDepth=999 を送信 → サーバ側で 0 にリセットされるべき
	resp, err := client.Ingest(context.Background(), &pb.IngestRequest{
		Message: "test with spoofed loop depth",
		Type:    "SYSTEM",
		Level:   3,
		Origin:  "SYSTEM",
		AiContext: &pb.AIContext{
			LoopDepth: 999,
		},
	})
	if err != nil {
		t.Fatalf("ingest failed: %v", err)
	}
	if resp.TraceId == "" {
		t.Fatal("expected trace_id")
	}
	// ログがDBに保存されたら、LoopDepth=0であることを確認
	// (直接的にはresponseに含まれないが、パイプラインが成功すれば999でパニックしない)
}

// =========================================================================
// V-18: ListTasks フィルタ文字列長制限
// =========================================================================

func TestV18_ListTasksRejectsTooLongEventName(t *testing.T) {
	client, _, cleanup := startTestServerWithAuthz(t, &mockAuthorizer{canRead: true})
	defer cleanup()

	longName := ""
	for i := 0; i < 300; i++ {
		longName += "x"
	}
	_, err := client.ListTasks(context.Background(), &pb.ListTasksRequest{EventName: longName})

	if err == nil {
		t.Fatal("expected InvalidArgument, got nil")
	}
	if s, ok := status.FromError(err); !ok || s.Code() != codes.InvalidArgument {
		t.Fatalf("expected InvalidArgument, got %v", err)
	}
}

// =========================================================================
// V-21: 時刻パースエラー
// =========================================================================

func TestV21_ListTasksRejectsInvalidFromTime(t *testing.T) {
	client, _, cleanup := startTestServerWithAuthz(t, &mockAuthorizer{canRead: true})
	defer cleanup()

	_, err := client.ListTasks(context.Background(), &pb.ListTasksRequest{
		FromTime: "not-a-date",
	})

	if err == nil {
		t.Fatal("expected InvalidArgument, got nil")
	}
	if s, ok := status.FromError(err); !ok || s.Code() != codes.InvalidArgument {
		t.Fatalf("expected InvalidArgument, got %v", err)
	}
}

func TestV21_ListTasksRejectsInvalidToTime(t *testing.T) {
	client, _, cleanup := startTestServerWithAuthz(t, &mockAuthorizer{canRead: true})
	defer cleanup()

	_, err := client.ListTasks(context.Background(), &pb.ListTasksRequest{
		ToTime: "invalid-time",
	})

	if err == nil {
		t.Fatal("expected InvalidArgument, got nil")
	}
	if s, ok := status.FromError(err); !ok || s.Code() != codes.InvalidArgument {
		t.Fatalf("expected InvalidArgument, got %v", err)
	}
}

func TestV21_ListTasksAcceptsValidRFC3339Time(t *testing.T) {
	client, _, cleanup := startTestServerWithAuthz(t, &mockAuthorizer{canRead: true})
	defer cleanup()

	resp, err := client.ListTasks(context.Background(), &pb.ListTasksRequest{
		FromTime: "2026-01-01T00:00:00Z",
		ToTime:   "2026-12-31T23:59:59Z",
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if resp == nil {
		t.Fatal("expected response")
	}
}

// =========================================================================
// V-9: GetTaskStatus 正常系
// =========================================================================

func TestV9_GetTaskStatusAllowedWithCanRead(t *testing.T) {
	client, _, cleanup := startTestServerWithAuthz(t, &mockAuthorizer{canApprove: false, canRead: true})
	defer cleanup()

	// タスクが存在しないので NotFound だが、PermissionDenied ではない
	_, err := client.GetTaskStatus(context.Background(), &pb.GetTaskStatusRequest{TaskId: "nonexistent"})
	if err == nil {
		t.Fatal("expected error, got nil")
	}
	s, _ := status.FromError(err)
	if s.Code() == codes.PermissionDenied {
		t.Fatal("should not be PermissionDenied when CanRead=true")
	}
}

// =========================================================================
// V-10: GetThreatResponses 正常系
// =========================================================================

func TestV10_GetThreatResponsesAllowedWithCanRead(t *testing.T) {
	client, _, cleanup := startTestServerWithAuthz(t, &mockAuthorizer{canApprove: false, canRead: true})
	defer cleanup()

	resp, err := client.GetThreatResponses(context.Background(), &pb.GetThreatResponsesRequest{TraceId: "trace-123"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if resp == nil {
		t.Fatal("expected response")
	}
}

// =========================================================================
// V-11: LoopDepth — AI_AGENT origin は保持される
// =========================================================================

func TestV11_LoopDepthPreservedForAIAgentOrigin(t *testing.T) {
	client, st, cleanup := startTestServerWithAuthz(t, nil)
	defer cleanup()

	resp, err := client.Ingest(context.Background(), &pb.IngestRequest{
		Message: "AI agent re-ingested log",
		Type:    "SYSTEM",
		Level:   3,
		Origin:  "AI_AGENT",
		AiContext: &pb.AIContext{
			LoopDepth: 2,
			AgentId:   "agent-1",
		},
	})
	if err != nil {
		t.Fatalf("ingest failed: %v", err)
	}

	// DBに保存されたログのLoopDepthを検証
	log, err := st.GetLogByTraceID(context.Background(), resp.TraceId)
	if err != nil || log == nil {
		t.Fatalf("log not found: %v", err)
	}
	if log.AIContext == nil {
		t.Fatal("expected ai_context in stored log")
	}
	if log.AIContext.LoopDepth != 2 {
		t.Fatalf("expected LoopDepth=2 for AI_AGENT origin, got %d", log.AIContext.LoopDepth)
	}
}

func TestV11_LoopDepthResetForSystemOriginVerifyDB(t *testing.T) {
	client, st, cleanup := startTestServerWithAuthz(t, nil)
	defer cleanup()

	resp, err := client.Ingest(context.Background(), &pb.IngestRequest{
		Message: "spoofed loop depth from external client",
		Type:    "SYSTEM",
		Level:   3,
		Origin:  "SYSTEM",
		AiContext: &pb.AIContext{
			LoopDepth: 50,
		},
	})
	if err != nil {
		t.Fatalf("ingest failed: %v", err)
	}

	log, err := st.GetLogByTraceID(context.Background(), resp.TraceId)
	if err != nil || log == nil {
		t.Fatalf("log not found: %v", err)
	}
	if log.AIContext == nil {
		t.Fatal("expected ai_context in stored log")
	}
	if log.AIContext.LoopDepth != 0 {
		t.Fatalf("expected LoopDepth=0 for SYSTEM origin (spoofing prevented), got %d", log.AIContext.LoopDepth)
	}
}

// =========================================================================
// V-18: Status フィールド長制限
// =========================================================================

func TestV18_ListTasksRejectsTooLongStatus(t *testing.T) {
	client, _, cleanup := startTestServerWithAuthz(t, &mockAuthorizer{canRead: true})
	defer cleanup()

	longStatus := ""
	for i := 0; i < 100; i++ {
		longStatus += "x"
	}
	_, err := client.ListTasks(context.Background(), &pb.ListTasksRequest{Status: longStatus})

	if err == nil {
		t.Fatal("expected InvalidArgument, got nil")
	}
	if s, ok := status.FromError(err); !ok || s.Code() != codes.InvalidArgument {
		t.Fatalf("expected InvalidArgument, got %v", err)
	}
}

// =========================================================================
// 後方互換: authorizer=nil で全RPCが通る
// =========================================================================

func TestBackwardCompat_NilAuthorizerAllowsAll(t *testing.T) {
	client, _, cleanup := startTestServerWithAuthz(t, nil) // authorizer=nil
	defer cleanup()

	// ListTasks should work
	resp, err := client.ListTasks(context.Background(), &pb.ListTasksRequest{})
	if err != nil {
		t.Fatalf("ListTasks should work without authorizer: %v", err)
	}
	if resp == nil {
		t.Fatal("expected response")
	}

	// GetThreatResponses should work
	threatResp, err := client.GetThreatResponses(context.Background(), &pb.GetThreatResponsesRequest{TraceId: "trace-1"})
	if err != nil {
		t.Fatalf("GetThreatResponses should work without authorizer: %v", err)
	}
	if threatResp == nil {
		t.Fatal("expected response")
	}

	// GetTaskStatus — NotFound is OK (not PermissionDenied)
	_, err = client.GetTaskStatus(context.Background(), &pb.GetTaskStatusRequest{TaskId: "no-such-task"})
	if err == nil {
		t.Fatal("expected NotFound, got nil")
	}
	s, _ := status.FromError(err)
	if s.Code() == codes.PermissionDenied {
		t.Fatal("should not get PermissionDenied with nil authorizer")
	}
}
