package task

import (
	"fmt"
	"sync"
	"time"

	"github.com/schro-cat-dev/sentinel-server/internal/domain"
)

// TaskHandler はタスクディスパッチ時に呼ばれるコールバック
type TaskHandler func(task domain.GeneratedTask) error

// TaskExecutor はタスクをディスパッチする（goroutine-safe）
type TaskExecutor struct {
	mu             sync.RWMutex
	handlers       map[string][]TaskHandler
	defaultHandler TaskHandler
}

func NewTaskExecutor(defaultHandler TaskHandler) *TaskExecutor {
	return &TaskExecutor{
		handlers:       make(map[string][]TaskHandler),
		defaultHandler: defaultHandler,
	}
}

// RegisterHandler はアクションタイプごとにハンドラを登録する
func (e *TaskExecutor) RegisterHandler(actionType string, handler TaskHandler) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.handlers[actionType] = append(e.handlers[actionType], handler)
}

// Dispatch はタスクをディスパッチし結果を返す
func (e *TaskExecutor) Dispatch(task domain.GeneratedTask) domain.TaskResult {
	base := domain.TaskResult{
		TaskID:       task.TaskID,
		RuleID:       task.RuleID,
		DispatchedAt: time.Now().UTC(),
	}

	status := e.resolveStatus(task)
	if status != domain.StatusDispatched {
		base.Status = status
		return base
	}

	if err := e.invokeHandlers(task); err != nil {
		base.Status = domain.StatusFailed
		base.Error = err.Error()
		return base
	}

	base.Status = domain.StatusDispatched
	return base
}

func (e *TaskExecutor) resolveStatus(task domain.GeneratedTask) domain.TaskDispatchStatus {
	if task.Guardrails.RequireHumanApproval {
		return domain.StatusBlockedApproval
	}
	switch task.ExecutionLevel {
	case domain.ExecLevelAuto:
		return domain.StatusDispatched
	case domain.ExecLevelSemiAuto:
		return domain.StatusDispatched
	case domain.ExecLevelManual:
		return domain.StatusBlockedApproval
	case domain.ExecLevelMonitor:
		return domain.StatusSkipped
	default:
		return domain.StatusSkipped
	}
}

func (e *TaskExecutor) invokeHandlers(t domain.GeneratedTask) error {
	e.mu.RLock()
	handlers := e.handlers[string(t.ActionType)]
	defaultH := e.defaultHandler
	e.mu.RUnlock()

	if len(handlers) == 0 && defaultH != nil {
		return defaultH(t)
	}

	if len(handlers) == 0 {
		// CRITICALアクション（KILL_SWITCH等）にハンドラ未登録は致命的エラー
		if t.ActionType == domain.ActionKillSwitch || t.ActionType == domain.ActionAutomatedRemediate {
			return fmt.Errorf("CRITICAL: no handler registered for %s (task=%s)", t.ActionType, t.TaskID)
		}
		return nil
	}

	for _, h := range handlers {
		if err := h(t); err != nil {
			return fmt.Errorf("handler error: %w", err)
		}
	}
	return nil
}
