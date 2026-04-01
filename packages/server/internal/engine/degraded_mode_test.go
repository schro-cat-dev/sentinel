package engine

import (
	"context"
	"testing"
	"time"

	"github.com/schro-cat-dev/sentinel-server/internal/domain"
	"github.com/schro-cat-dev/sentinel-server/internal/store"
	"github.com/schro-cat-dev/sentinel-server/internal/task"
)

func newDegradedTestPipeline(t *testing.T, failOnPersist bool) *Pipeline {
	t.Helper()
	st, err := store.NewSQLiteStore("file::memory:?_busy_timeout=5000")
	if err != nil {
		t.Fatal(err)
	}

	executor := task.NewTaskExecutor(nil)
	cfg := PipelineConfig{
		ServiceID:          "test-svc",
		EnableHashChain:    true,
		HMACKey:            []byte("12345678901234567890123456789012"),
		TaskRules:          []domain.TaskRule{},
		FailOnPersistError: failOnPersist,
	}

	p, err := NewPipeline(cfg, executor, st, nil)
	if err != nil {
		t.Fatal(err)
	}
	return p
}

func makeDegradedLog() domain.Log {
	return domain.Log{
		TraceID:   "trace-degraded-1",
		Type:      domain.LogTypeSystem,
		Level:     3,
		Timestamp: time.Now().UTC(),
		Boundary:  "test",
		ServiceID: "test-svc",
		Message:   "degraded mode test",
		Origin:    domain.OriginSystem,
	}
}

func TestDegradedMode_NormalProcessing(t *testing.T) {
	p := newDegradedTestPipeline(t, false)

	result, err := p.Process(context.Background(), makeDegradedLog())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.Degraded {
		t.Error("expected Degraded=false for normal processing")
	}
	if result.TraceID != "trace-degraded-1" {
		t.Errorf("expected traceID preserved, got %s", result.TraceID)
	}
}

func TestDegradedMode_HashChainWorks(t *testing.T) {
	p := newDegradedTestPipeline(t, false)

	result, err := p.Process(context.Background(), makeDegradedLog())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !result.HashChainValid {
		t.Error("expected hash chain to be valid")
	}
}

func TestDegradedMode_FailOnPersistError_FalseByDefault(t *testing.T) {
	// When FailOnPersistError=false (default), pipeline continues even if store works
	p := newDegradedTestPipeline(t, false)

	result, err := p.Process(context.Background(), makeDegradedLog())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.Degraded {
		t.Error("expected not degraded with working store")
	}
}

func TestDegradedMode_ConcurrentProcessing(t *testing.T) {
	p := newDegradedTestPipeline(t, false)
	errs := make(chan error, 50)

	for i := 0; i < 50; i++ {
		go func() {
			_, err := p.Process(context.Background(), makeDegradedLog())
			errs <- err
		}()
	}

	for i := 0; i < 50; i++ {
		if err := <-errs; err != nil {
			t.Errorf("concurrent request %d failed: %v", i, err)
		}
	}
}
