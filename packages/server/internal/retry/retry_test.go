package retry

import (
	"context"
	"errors"
	"testing"
	"time"
)

func TestDo_SucceedsFirstAttempt(t *testing.T) {
	calls := 0
	err := Do(context.Background(), DefaultConfig(), func() error {
		calls++
		return nil
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if calls != 1 {
		t.Errorf("expected 1 call, got %d", calls)
	}
}

func TestDo_RetriesOnFailure(t *testing.T) {
	calls := 0
	err := Do(context.Background(), Config{
		MaxAttempts: 3, BaseDelay: 1 * time.Millisecond, MaxDelay: 10 * time.Millisecond, Multiplier: 2.0,
	}, func() error {
		calls++
		if calls < 3 {
			return errors.New("transient")
		}
		return nil
	})
	if err != nil {
		t.Fatalf("should succeed on 3rd attempt: %v", err)
	}
	if calls != 3 {
		t.Errorf("expected 3 calls, got %d", calls)
	}
}

func TestDo_ExhaustsRetries(t *testing.T) {
	calls := 0
	err := Do(context.Background(), Config{
		MaxAttempts: 3, BaseDelay: 1 * time.Millisecond, MaxDelay: 10 * time.Millisecond, Multiplier: 2.0,
	}, func() error {
		calls++
		return errors.New("permanent")
	})
	if err == nil {
		t.Fatal("expected error after exhausting retries")
	}
	if calls != 3 {
		t.Errorf("expected 3 calls, got %d", calls)
	}
}

func TestDo_CancelledContext(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	err := Do(ctx, Config{
		MaxAttempts: 5, BaseDelay: 1 * time.Second, MaxDelay: 10 * time.Second, Multiplier: 2.0,
	}, func() error {
		return errors.New("fail")
	})
	if err == nil {
		t.Fatal("expected cancellation error")
	}
}

func TestDo_ContextCancelledDuringBackoff(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()

	calls := 0
	err := Do(ctx, Config{
		MaxAttempts: 10, BaseDelay: 1 * time.Second, MaxDelay: 10 * time.Second, Multiplier: 2.0,
	}, func() error {
		calls++
		return errors.New("fail")
	})
	if err == nil {
		t.Fatal("expected error")
	}
	if calls > 2 {
		t.Errorf("should stop early due to context, got %d calls", calls)
	}
}

func TestDo_SingleAttempt(t *testing.T) {
	calls := 0
	err := Do(context.Background(), Config{MaxAttempts: 1}, func() error {
		calls++
		return errors.New("fail")
	})
	if err == nil {
		t.Fatal("expected error")
	}
	if calls != 1 {
		t.Errorf("expected 1 call, got %d", calls)
	}
}

func TestDo_ZeroAttempts(t *testing.T) {
	calls := 0
	Do(context.Background(), Config{MaxAttempts: 0}, func() error {
		calls++
		return nil
	})
	if calls != 1 {
		t.Errorf("MaxAttempts=0 should default to 1, got %d calls", calls)
	}
}

func TestDoWithResult(t *testing.T) {
	calls := 0
	result, err := DoWithResult(context.Background(), Config{
		MaxAttempts: 3, BaseDelay: 1 * time.Millisecond, MaxDelay: 10 * time.Millisecond, Multiplier: 2.0,
	}, func() (string, error) {
		calls++
		if calls < 2 {
			return "", errors.New("fail")
		}
		return "success", nil
	})
	if err != nil {
		t.Fatalf("error: %v", err)
	}
	if result != "success" {
		t.Errorf("expected success, got %s", result)
	}
}

func TestCalculateDelay_Jitter(t *testing.T) {
	cfg := Config{BaseDelay: 100 * time.Millisecond, MaxDelay: 5 * time.Second, Multiplier: 2.0}

	// Attempt 0: delay should be in [0, 100ms]
	for i := 0; i < 100; i++ {
		d := calculateDelay(cfg, 0)
		if d < 0 || d > 100*time.Millisecond {
			t.Errorf("attempt 0: delay %v out of range [0, 100ms]", d)
		}
	}

	// Attempt 3: base * 2^3 = 800ms, jitter in [0, 800ms]
	for i := 0; i < 100; i++ {
		d := calculateDelay(cfg, 3)
		if d < 0 || d > 800*time.Millisecond {
			t.Errorf("attempt 3: delay %v out of range [0, 800ms]", d)
		}
	}

	// Attempt 10: capped at maxDelay
	for i := 0; i < 100; i++ {
		d := calculateDelay(cfg, 10)
		if d > 5*time.Second {
			t.Errorf("attempt 10: delay %v exceeds maxDelay", d)
		}
	}
}

func TestIsRetryable(t *testing.T) {
	if IsRetryable(nil) {
		t.Error("nil should not be retryable")
	}
	if IsRetryable(context.Canceled) {
		t.Error("context.Canceled should not be retryable")
	}
	if IsRetryable(context.DeadlineExceeded) {
		t.Error("DeadlineExceeded should not be retryable")
	}
	if !IsRetryable(errors.New("transient")) {
		t.Error("generic error should be retryable")
	}
}
