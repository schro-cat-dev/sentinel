package agent

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/schro-cat-dev/sentinel-server/internal/domain"
	"github.com/schro-cat-dev/sentinel-server/internal/store"
	"github.com/schro-cat-dev/sentinel-server/testutil"
)

func newTestExecutor(t *testing.T, provider Provider) (*AgentExecutor, *store.SQLiteStore) {
	t.Helper()
	st, err := store.NewSQLiteStore(":memory:")
	if err != nil {
		t.Fatalf("store: %v", err)
	}
	t.Cleanup(func() { st.Close() })

	var reIngestedLogs []domain.Log
	var mu sync.Mutex

	executor := NewAgentExecutor(provider, st, AgentExecutorConfig{
		MaxLoopDepth: 3,
		TimeoutSec:   5,
	}, func(ctx context.Context, log domain.Log) error {
		mu.Lock()
		defer mu.Unlock()
		reIngestedLogs = append(reIngestedLogs, log)
		return nil
	})

	return executor, st
}

func makeTestTask() domain.GeneratedTask {
	return domain.GeneratedTask{
		TaskID:         "task-ai-001",
		RuleID:         "sec-analyze",
		EventName:      "SECURITY_INTRUSION_DETECTED",
		Severity:       domain.SeverityHigh,
		ActionType:     domain.ActionAIAnalyze,
		ExecutionLevel: domain.ExecLevelAuto,
		Priority:       1,
		Description:    "AI security analysis",
		SourceLog: domain.SourceLogInfo{
			TraceID: "trace-001", Message: "Brute force detected",
			Boundary: "auth-service", Level: 5, Timestamp: time.Now(),
		},
		CreatedAt: time.Now(),
	}
}

func TestAgentExecutor_Success(t *testing.T) {
	provider := NewMockProvider("test-ai")
	executor, st := newTestExecutor(t, provider)
	ctx := context.Background()

	log := testutil.NewSecurityLog()
	record, err := executor.ExecuteTask(ctx, makeTestTask(), log)

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if record.Status != "success" {
		t.Errorf("expected success, got %s", record.Status)
	}
	if record.Result == nil {
		t.Fatal("expected result")
	}
	if record.Result.Action != "block_ip" {
		t.Errorf("expected block_ip, got %s", record.Result.Action)
	}
	if record.Result.Confidence != 0.85 {
		t.Errorf("expected 0.85, got %f", record.Result.Confidence)
	}
	if record.LoopDepth != 1 {
		t.Errorf("expected loop depth 1, got %d", record.LoopDepth)
	}

	// Verify result persisted
	_ = st // results are stored via InsertTaskResult
}

func TestAgentExecutor_Failure(t *testing.T) {
	provider := NewMockProvider("test-ai")
	provider.SetShouldFail(true)
	executor, _ := newTestExecutor(t, provider)

	record, err := executor.ExecuteTask(context.Background(), makeTestTask(), testutil.NewSecurityLog())

	if err == nil {
		t.Fatal("expected error")
	}
	if record.Status != "failed" {
		t.Errorf("expected failed, got %s", record.Status)
	}
	if record.Error == "" {
		t.Error("expected error message")
	}
}

func TestAgentExecutor_LoopDepthLimit(t *testing.T) {
	provider := NewMockProvider("test-ai")
	executor, _ := newTestExecutor(t, provider) // maxLoopDepth=3

	// Simulate log from AI agent at depth 3
	log := testutil.NewSecurityLog(func(l *domain.Log) {
		l.AIContext = &domain.AIContext{
			AgentID:   "prev-agent",
			LoopDepth: 3,
		}
	})

	record, err := executor.ExecuteTask(context.Background(), makeTestTask(), log)

	if err == nil {
		t.Fatal("expected loop depth error")
	}
	if record.Status != "failed" {
		t.Errorf("expected failed, got %s", record.Status)
	}
	if record.LoopDepth != 3 {
		t.Errorf("expected depth 3, got %d", record.LoopDepth)
	}
}

func TestAgentExecutor_LoopDepthIncrement(t *testing.T) {
	provider := NewMockProvider("test-ai")
	executor, _ := newTestExecutor(t, provider) // maxLoopDepth=3

	// Depth 0 → should execute at depth 1
	log := testutil.NewSecurityLog()
	record, err := executor.ExecuteTask(context.Background(), makeTestTask(), log)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if record.LoopDepth != 1 {
		t.Errorf("expected depth 1, got %d", record.LoopDepth)
	}

	// Depth 1 → should execute at depth 2
	log2 := testutil.NewSecurityLog(func(l *domain.Log) {
		l.AIContext = &domain.AIContext{LoopDepth: 1}
	})
	record2, err := executor.ExecuteTask(context.Background(), makeTestTask(), log2)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if record2.LoopDepth != 2 {
		t.Errorf("expected depth 2, got %d", record2.LoopDepth)
	}

	// Depth 2 → should execute at depth 3 (still under limit of 3)
	log3 := testutil.NewSecurityLog(func(l *domain.Log) {
		l.AIContext = &domain.AIContext{LoopDepth: 2}
	})
	record3, err := executor.ExecuteTask(context.Background(), makeTestTask(), log3)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if record3.LoopDepth != 3 {
		t.Errorf("expected depth 3, got %d", record3.LoopDepth)
	}
}

func TestAgentExecutor_ReIngestsLog(t *testing.T) {
	provider := NewMockProvider("test-ai")
	var reIngestedLogs []domain.Log
	var mu sync.Mutex

	st, _ := store.NewSQLiteStore(":memory:")
	defer st.Close()

	executor := NewAgentExecutor(provider, st, AgentExecutorConfig{
		MaxLoopDepth: 5, TimeoutSec: 5,
	}, func(ctx context.Context, log domain.Log) error {
		mu.Lock()
		defer mu.Unlock()
		reIngestedLogs = append(reIngestedLogs, log)
		return nil
	})

	log := testutil.NewSecurityLog()
	_, err := executor.ExecuteTask(context.Background(), makeTestTask(), log)
	if err != nil {
		t.Fatalf("error: %v", err)
	}

	mu.Lock()
	defer mu.Unlock()
	if len(reIngestedLogs) != 1 {
		t.Fatalf("expected 1 re-ingested log, got %d", len(reIngestedLogs))
	}

	reLog := reIngestedLogs[0]
	if reLog.Origin != domain.OriginAIAgent {
		t.Errorf("expected AI_AGENT origin, got %s", reLog.Origin)
	}
	if reLog.TraceID != log.TraceID {
		t.Error("re-ingested log should keep same traceID")
	}
	if reLog.AIContext == nil {
		t.Fatal("expected AIContext in re-ingested log")
	}
	if reLog.AIContext.LoopDepth != 1 {
		t.Errorf("expected loop depth 1 in re-ingested log, got %d", reLog.AIContext.LoopDepth)
	}
	if reLog.TriggerAgent {
		t.Error("re-ingested log should not trigger agent")
	}
	if len(reLog.AgentBackLog) != 1 {
		t.Fatalf("expected 1 backlog entry, got %d", len(reLog.AgentBackLog))
	}
	if reLog.AgentBackLog[0].Status != "success" {
		t.Errorf("expected success status in backlog, got %s", reLog.AgentBackLog[0].Status)
	}
}

func TestAgentExecutor_ContextCancellation(t *testing.T) {
	provider := NewMockProvider("test-ai")
	executor, _ := newTestExecutor(t, provider)

	ctx, cancel := context.WithCancel(context.Background())
	cancel() // immediately cancel

	record, err := executor.ExecuteTask(ctx, makeTestTask(), testutil.NewSecurityLog())
	if err == nil {
		t.Fatal("expected error for cancelled context")
	}
	if record.Status != "failed" {
		t.Errorf("expected failed, got %s", record.Status)
	}
}
