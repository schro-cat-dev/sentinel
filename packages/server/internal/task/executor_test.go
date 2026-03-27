package task

import (
	"errors"
	"testing"
	"time"

	"github.com/schro-cat-dev/sentinel-server/internal/domain"
)

func makeTask(overrides ...func(*domain.GeneratedTask)) domain.GeneratedTask {
	t := domain.GeneratedTask{
		TaskID:         "task-001",
		RuleID:         "rule-001",
		EventName:      "SYSTEM_CRITICAL_FAILURE",
		Severity:       domain.SeverityCritical,
		ActionType:     domain.ActionSystemNotification,
		ExecutionLevel: domain.ExecLevelAuto,
		Priority:       1,
		Description:    "Test task",
		Guardrails:     domain.Guardrails{RequireHumanApproval: false, TimeoutMs: 30000},
		CreatedAt:      time.Now(),
	}
	for _, fn := range overrides {
		fn(&t)
	}
	return t
}

func TestExecutor_Dispatch(t *testing.T) {
	t.Run("dispatches AUTO tasks", func(t *testing.T) {
		ex := NewTaskExecutor(nil)
		result := ex.Dispatch(makeTask())
		if result.Status != domain.StatusDispatched {
			t.Errorf("expected dispatched, got %s", result.Status)
		}
	})

	t.Run("calls registered handler", func(t *testing.T) {
		called := false
		ex := NewTaskExecutor(nil)
		ex.RegisterHandler("SYSTEM_NOTIFICATION", func(_ domain.GeneratedTask) error {
			called = true
			return nil
		})
		ex.Dispatch(makeTask())
		if !called {
			t.Error("handler should be called")
		}
	})

	t.Run("blocks when requireHumanApproval", func(t *testing.T) {
		ex := NewTaskExecutor(nil)
		result := ex.Dispatch(makeTask(func(t *domain.GeneratedTask) {
			t.Guardrails.RequireHumanApproval = true
		}))
		if result.Status != domain.StatusBlockedApproval {
			t.Errorf("expected blocked_approval, got %s", result.Status)
		}
	})

	t.Run("blocks MANUAL tasks", func(t *testing.T) {
		ex := NewTaskExecutor(nil)
		result := ex.Dispatch(makeTask(func(t *domain.GeneratedTask) {
			t.ExecutionLevel = domain.ExecLevelManual
		}))
		if result.Status != domain.StatusBlockedApproval {
			t.Errorf("expected blocked_approval, got %s", result.Status)
		}
	})

	t.Run("skips MONITOR tasks", func(t *testing.T) {
		ex := NewTaskExecutor(nil)
		result := ex.Dispatch(makeTask(func(t *domain.GeneratedTask) {
			t.ExecutionLevel = domain.ExecLevelMonitor
		}))
		if result.Status != domain.StatusSkipped {
			t.Errorf("expected skipped, got %s", result.Status)
		}
	})

	t.Run("returns failed on handler error", func(t *testing.T) {
		ex := NewTaskExecutor(nil)
		ex.RegisterHandler("SYSTEM_NOTIFICATION", func(_ domain.GeneratedTask) error {
			return errors.New("handler failed")
		})
		result := ex.Dispatch(makeTask())
		if result.Status != domain.StatusFailed {
			t.Errorf("expected failed, got %s", result.Status)
		}
		if result.Error == "" {
			t.Error("expected error message")
		}
	})

	t.Run("calls default handler when no specific", func(t *testing.T) {
		called := false
		ex := NewTaskExecutor(func(_ domain.GeneratedTask) error {
			called = true
			return nil
		})
		ex.Dispatch(makeTask(func(t *domain.GeneratedTask) {
			t.ActionType = domain.ActionExternalWebhook
		}))
		if !called {
			t.Error("default handler should be called")
		}
	})
}
