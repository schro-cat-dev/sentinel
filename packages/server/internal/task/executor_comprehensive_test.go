package task

import (
	"errors"
	"testing"

	"github.com/schro-cat-dev/sentinel-server/internal/domain"
)

func makeTestTask(opts ...func(*domain.GeneratedTask)) domain.GeneratedTask {
	t := domain.GeneratedTask{
		TaskID:         "task-1",
		RuleID:         "rule-1",
		EventName:      string(domain.EventSystemCriticalFailure),
		Severity:       domain.SeverityCritical,
		ActionType:     domain.ActionSystemNotification,
		ExecutionLevel: domain.ExecLevelAuto,
		Priority:       1,
		Guardrails: domain.Guardrails{
			RequireHumanApproval: false,
			TimeoutMs:            30000,
			MaxRetries:           3,
		},
	}
	for _, o := range opts {
		o(&t)
	}
	return t
}

func TestExecutor_DispatchAuto(t *testing.T) {
	called := false
	exec := NewTaskExecutor(func(task domain.GeneratedTask) error {
		called = true
		return nil
	})

	result := exec.Dispatch(makeTestTask())
	if result.Status != domain.StatusDispatched {
		t.Errorf("expected dispatched, got %s", result.Status)
	}
	if !called {
		t.Error("default handler was not called")
	}
}

func TestExecutor_DispatchManual(t *testing.T) {
	exec := NewTaskExecutor(nil)
	result := exec.Dispatch(makeTestTask(func(task *domain.GeneratedTask) {
		task.ExecutionLevel = domain.ExecLevelManual
	}))
	if result.Status != domain.StatusBlockedApproval {
		t.Errorf("expected blocked_approval, got %s", result.Status)
	}
}

func TestExecutor_DispatchMonitor(t *testing.T) {
	exec := NewTaskExecutor(nil)
	result := exec.Dispatch(makeTestTask(func(task *domain.GeneratedTask) {
		task.ExecutionLevel = domain.ExecLevelMonitor
	}))
	if result.Status != domain.StatusSkipped {
		t.Errorf("expected skipped, got %s", result.Status)
	}
}

func TestExecutor_RequireHumanApproval(t *testing.T) {
	exec := NewTaskExecutor(nil)
	result := exec.Dispatch(makeTestTask(func(task *domain.GeneratedTask) {
		task.Guardrails.RequireHumanApproval = true
	}))
	if result.Status != domain.StatusBlockedApproval {
		t.Errorf("expected blocked_approval, got %s", result.Status)
	}
}

func TestExecutor_RegisterHandler(t *testing.T) {
	handlerCalled := false
	exec := NewTaskExecutor(nil)
	exec.RegisterHandler("SYSTEM_NOTIFICATION", func(task domain.GeneratedTask) error {
		handlerCalled = true
		return nil
	})

	result := exec.Dispatch(makeTestTask())
	if result.Status != domain.StatusDispatched {
		t.Errorf("expected dispatched, got %s", result.Status)
	}
	if !handlerCalled {
		t.Error("registered handler was not called")
	}
}

func TestExecutor_HandlerError(t *testing.T) {
	exec := NewTaskExecutor(nil)
	exec.RegisterHandler("SYSTEM_NOTIFICATION", func(task domain.GeneratedTask) error {
		return errors.New("handler crash")
	})

	result := exec.Dispatch(makeTestTask())
	if result.Status != domain.StatusFailed {
		t.Errorf("expected failed, got %s", result.Status)
	}
	if result.Error == "" {
		t.Error("expected error message")
	}
}

func TestExecutor_CriticalActionNoHandler(t *testing.T) {
	exec := NewTaskExecutor(nil)
	result := exec.Dispatch(makeTestTask(func(task *domain.GeneratedTask) {
		task.ActionType = domain.ActionKillSwitch
	}))
	if result.Status != domain.StatusFailed {
		t.Errorf("expected failed for KILL_SWITCH without handler, got %s", result.Status)
	}
}

func TestExecutor_DefaultHandlerFallback(t *testing.T) {
	defaultCalled := false
	exec := NewTaskExecutor(func(task domain.GeneratedTask) error {
		defaultCalled = true
		return nil
	})
	// No specific handler registered → falls back to default
	result := exec.Dispatch(makeTestTask())
	if !defaultCalled {
		t.Error("default handler should be called when no specific handler")
	}
	if result.Status != domain.StatusDispatched {
		t.Errorf("expected dispatched, got %s", result.Status)
	}
}

func TestExecutor_MultipleHandlers(t *testing.T) {
	callOrder := []string{}
	exec := NewTaskExecutor(nil)
	exec.RegisterHandler("SYSTEM_NOTIFICATION", func(task domain.GeneratedTask) error {
		callOrder = append(callOrder, "first")
		return nil
	})
	exec.RegisterHandler("SYSTEM_NOTIFICATION", func(task domain.GeneratedTask) error {
		callOrder = append(callOrder, "second")
		return nil
	})

	result := exec.Dispatch(makeTestTask())
	if result.Status != domain.StatusDispatched {
		t.Errorf("expected dispatched, got %s", result.Status)
	}
	if len(callOrder) != 2 {
		t.Errorf("expected 2 handler calls, got %d", len(callOrder))
	}
}

func TestExecutor_HandlerErrorStopsChain(t *testing.T) {
	calls := 0
	exec := NewTaskExecutor(nil)
	exec.RegisterHandler("SYSTEM_NOTIFICATION", func(task domain.GeneratedTask) error {
		calls++
		return errors.New("first handler fails")
	})
	exec.RegisterHandler("SYSTEM_NOTIFICATION", func(task domain.GeneratedTask) error {
		calls++
		return nil
	})

	result := exec.Dispatch(makeTestTask())
	if result.Status != domain.StatusFailed {
		t.Errorf("expected failed, got %s", result.Status)
	}
	if calls != 1 {
		t.Errorf("expected 1 call (chain stopped), got %d", calls)
	}
}
