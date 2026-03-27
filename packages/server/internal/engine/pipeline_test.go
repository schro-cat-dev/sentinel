package engine

import (
	"context"
	"sync"
	"testing"

	"github.com/schro-cat-dev/sentinel-server/internal/domain"
	"github.com/schro-cat-dev/sentinel-server/internal/security"
	"github.com/schro-cat-dev/sentinel-server/internal/store"
	"github.com/schro-cat-dev/sentinel-server/internal/task"
	"github.com/schro-cat-dev/sentinel-server/testutil"
)

var testHMACKey = []byte("test-pipeline-hmac-key-32bytes!!")

func testPipeline(t *testing.T, rules []domain.TaskRule) *Pipeline {
	t.Helper()
	cfg := PipelineConfig{
		ServiceID:       "test-svc",
		EnableHashChain: true,
		EnableMasking:   true,
		MaskingRules: []security.MaskingRule{
			{Type: "PII_TYPE", Category: "EMAIL"},
		},
		PreserveFields: []string{"traceId"},
		TaskRules:      rules,
		HMACKey:        testHMACKey,
	}
	executor := task.NewTaskExecutor(nil)
	st, err := store.NewSQLiteStore(":memory:")
	if err != nil {
		t.Fatalf("store: %v", err)
	}
	t.Cleanup(func() { st.Close() })

	p, err := NewPipeline(cfg, executor, st, nil)
	if err != nil {
		t.Fatalf("NewPipeline: %v", err)
	}
	return p
}

func TestPipeline_BasicIngestion(t *testing.T) {
	p := testPipeline(t, nil)
	ctx := context.Background()

	t.Run("processes simple log", func(t *testing.T) {
		result, err := p.Process(ctx, domain.Log{Message: "Hello world"})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if result.TraceID == "" {
			t.Error("expected traceID")
		}
		if !result.HashChainValid {
			t.Error("expected hash chain valid")
		}
		if !result.Masked {
			t.Error("expected masked")
		}
	})

	t.Run("rejects empty message", func(t *testing.T) {
		_, err := p.Process(ctx, domain.Log{})
		if err == nil {
			t.Error("expected error")
		}
	})

	t.Run("rejects null bytes", func(t *testing.T) {
		_, err := p.Process(ctx, domain.Log{Message: "hello\x00world"})
		if err == nil {
			t.Error("expected error for null bytes")
		}
	})
}

func TestPipeline_TaskGeneration(t *testing.T) {
	rules := []domain.TaskRule{
		testutil.NewTestTaskRule(func(r *domain.TaskRule) {
			r.RuleID = "crit-notify"
			r.EventName = "SYSTEM_CRITICAL_FAILURE"
			r.Severity = domain.SeverityHigh
		}),
	}
	p := testPipeline(t, rules)
	ctx := context.Background()

	t.Run("generates tasks for critical log", func(t *testing.T) {
		result, _ := p.Process(ctx, domain.Log{
			Message: "DB pool exhausted", IsCritical: true, Level: 6, Boundary: "db-service",
		})
		if len(result.TasksGenerated) == 0 {
			t.Fatal("expected tasks")
		}
		if result.TasksGenerated[0].RuleID != "crit-notify" {
			t.Errorf("expected crit-notify, got %s", result.TasksGenerated[0].RuleID)
		}
	})
}

func TestPipeline_PersistsLogs(t *testing.T) {
	p := testPipeline(t, nil)
	ctx := context.Background()

	result, err := p.Process(ctx, domain.Log{Message: "Persisted log"})
	if err != nil {
		t.Fatalf("error: %v", err)
	}

	// Verify log was persisted
	log, err := p.store.GetLogByTraceID(ctx, result.TraceID)
	if err != nil {
		t.Fatalf("get log: %v", err)
	}
	if log == nil {
		t.Fatal("log should be persisted")
	}
	if log.Message != "Persisted log" {
		t.Errorf("message mismatch: %s", log.Message)
	}
}

func TestPipeline_PersistsTasks(t *testing.T) {
	rules := []domain.TaskRule{
		testutil.NewTestTaskRule(func(r *domain.TaskRule) {
			r.RuleID = "persist-test"
			r.EventName = "SYSTEM_CRITICAL_FAILURE"
			r.Severity = domain.SeverityHigh
		}),
	}
	p := testPipeline(t, rules)
	ctx := context.Background()

	result, _ := p.Process(ctx, domain.Log{
		Message: "Critical", IsCritical: true, Level: 6,
	})

	if len(result.TasksGenerated) == 0 {
		t.Fatal("expected tasks")
	}

	// Verify task was persisted
	taskID := result.TasksGenerated[0].TaskID
	stored, err := p.store.GetTask(ctx, taskID)
	if err != nil {
		t.Fatalf("get task: %v", err)
	}
	if stored == nil {
		t.Fatal("task should be persisted")
	}
	if stored.RuleID != "persist-test" {
		t.Errorf("ruleID mismatch: %s", stored.RuleID)
	}
}

func TestPipeline_CreatesApprovalForBlockedTasks(t *testing.T) {
	rules := []domain.TaskRule{
		testutil.NewTestTaskRule(func(r *domain.TaskRule) {
			r.RuleID = "manual-task"
			r.EventName = "SYSTEM_CRITICAL_FAILURE"
			r.Severity = domain.SeverityHigh
			r.ExecutionLevel = domain.ExecLevelManual
		}),
	}
	p := testPipeline(t, rules)
	ctx := context.Background()

	result, _ := p.Process(ctx, domain.Log{
		Message: "Critical", IsCritical: true, Level: 6,
	})

	if len(result.TasksGenerated) == 0 {
		t.Fatal("expected tasks")
	}
	if result.TasksGenerated[0].Status != domain.StatusBlockedApproval {
		t.Errorf("expected blocked_approval, got %s", result.TasksGenerated[0].Status)
	}

	// Verify approval request was created
	taskID := result.TasksGenerated[0].TaskID
	approval, err := p.store.GetApprovalByTaskID(ctx, taskID)
	if err != nil {
		t.Fatalf("get approval: %v", err)
	}
	if approval == nil {
		t.Fatal("approval request should be created for blocked tasks")
	}
	if approval.Status != "pending" {
		t.Errorf("approval status should be pending, got %s", approval.Status)
	}
}

func TestPipeline_ContextCancellation(t *testing.T) {
	p := testPipeline(t, nil)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, err := p.Process(ctx, domain.Log{Message: "should fail"})
	if err == nil {
		t.Error("expected error for cancelled context")
	}
}

func TestPipeline_ConcurrentSafety(t *testing.T) {
	p := testPipeline(t, nil)
	ctx := context.Background()

	var wg sync.WaitGroup
	for i := 0; i < 50; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, err := p.Process(ctx, domain.Log{Message: "concurrent log"})
			if err != nil {
				t.Errorf("concurrent error: %v", err)
			}
		}()
	}
	wg.Wait()
}
