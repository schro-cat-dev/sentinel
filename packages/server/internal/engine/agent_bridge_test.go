package engine

import (
	"testing"

	"github.com/schro-cat-dev/sentinel-server/internal/agent"
	"github.com/schro-cat-dev/sentinel-server/internal/domain"
	"github.com/schro-cat-dev/sentinel-server/internal/store"
	"github.com/schro-cat-dev/sentinel-server/internal/task"
)

func TestAgentBridge_DisabledDoesNotExecute(t *testing.T) {
	st, _ := store.NewSQLiteStore(":memory:")
	defer st.Close()

	provider := agent.NewMockProvider("test-ai")
	provider.SetShouldFail(true) // Would fail if called

	agentExec := agent.NewAgentExecutor(provider, st, agent.AgentExecutorConfig{
		MaxLoopDepth: 5, TimeoutSec: 5,
	}, nil)

	bridge := NewAgentBridge(agentExec, nil, AgentBridgeConfig{
		Enabled: false,
	})

	executor := task.NewTaskExecutor(nil)
	bridge.RegisterHandlers(executor)

	result := executor.Dispatch(domain.GeneratedTask{
		TaskID: "t1", ActionType: domain.ActionAIAnalyze,
		ExecutionLevel: domain.ExecLevelAuto,
		Guardrails:     domain.Guardrails{},
	})
	// Should dispatch successfully because handler returns nil (disabled)
	if result.Status != domain.StatusDispatched {
		t.Errorf("disabled bridge should still dispatch (handler returns nil), got %s", result.Status)
	}
}

func TestAgentBridge_ProviderFailure(t *testing.T) {
	st, _ := store.NewSQLiteStore(":memory:")
	defer st.Close()

	provider := agent.NewMockProvider("test-ai")
	provider.SetShouldFail(true)

	agentExec := agent.NewAgentExecutor(provider, st, agent.AgentExecutorConfig{
		MaxLoopDepth: 5, TimeoutSec: 5,
	}, nil)

	bridge := NewAgentBridge(agentExec, nil, AgentBridgeConfig{
		Enabled:      true,
		AllowedActions: []domain.TaskActionType{domain.ActionAIAnalyze},
	})

	executor := task.NewTaskExecutor(nil)
	bridge.RegisterHandlers(executor)

	// Set source log so the bridge can find it
	bridge.SetSourceLog("t-fail", domain.Log{
		TraceID: "trace-1", Message: "test", Boundary: "svc",
		Level: domain.LogLevelError,
	})

	result := executor.Dispatch(domain.GeneratedTask{
		TaskID: "t-fail", ActionType: domain.ActionAIAnalyze,
		ExecutionLevel: domain.ExecLevelAuto,
		Guardrails:     domain.Guardrails{},
		Severity:       domain.SeverityHigh,
		SourceLog: domain.SourceLogInfo{TraceID: "trace-1", Message: "test", Boundary: "svc"},
	})
	if result.Status != domain.StatusFailed {
		t.Errorf("provider failure should result in failed status, got %s", result.Status)
	}
}

func TestAgentBridge_UnallowedActionType(t *testing.T) {
	st, _ := store.NewSQLiteStore(":memory:")
	defer st.Close()

	provider := agent.NewMockProvider("test-ai")
	agentExec := agent.NewAgentExecutor(provider, st, agent.AgentExecutorConfig{
		MaxLoopDepth: 5, TimeoutSec: 5,
	}, nil)

	bridge := NewAgentBridge(agentExec, nil, AgentBridgeConfig{
		Enabled:      true,
		AllowedActions: []domain.TaskActionType{domain.ActionAIAnalyze},
	})

	// KILL_SWITCH is not in AllowedActions, so no handler registered for it
	executor := task.NewTaskExecutor(nil)
	bridge.RegisterHandlers(executor)

	result := executor.Dispatch(domain.GeneratedTask{
		TaskID: "t-kill", ActionType: domain.ActionKillSwitch,
		ExecutionLevel: domain.ExecLevelAuto,
		Guardrails:     domain.Guardrails{},
	})
	// KILL_SWITCH has no handler → TaskExecutor returns CRITICAL error
	if result.Status != domain.StatusFailed {
		t.Errorf("unregistered critical action should fail, got %s", result.Status)
	}
}

func TestAgentBridge_IsEnabled(t *testing.T) {
	st, _ := store.NewSQLiteStore(":memory:")
	defer st.Close()

	provider := agent.NewMockProvider("test-ai")
	agentExec := agent.NewAgentExecutor(provider, st, agent.AgentExecutorConfig{}, nil)

	t.Run("enabled", func(t *testing.T) {
		b := NewAgentBridge(agentExec, nil, AgentBridgeConfig{Enabled: true})
		if !b.IsEnabled() {
			t.Error("should be enabled")
		}
	})

	t.Run("disabled", func(t *testing.T) {
		b := NewAgentBridge(agentExec, nil, AgentBridgeConfig{Enabled: false})
		if b.IsEnabled() {
			t.Error("should be disabled")
		}
	})
}

func TestDefaultAgentBridgeConfig(t *testing.T) {
	cfg := DefaultAgentBridgeConfig()

	if cfg.Enabled {
		t.Error("should be disabled by default")
	}
	if cfg.MaxLoopDepth != 5 {
		t.Errorf("expected max loop depth 5, got %d", cfg.MaxLoopDepth)
	}
	if cfg.TimeoutSec != 60 {
		t.Errorf("expected timeout 60, got %d", cfg.TimeoutSec)
	}
	if len(cfg.AllowedActions) != 1 || cfg.AllowedActions[0] != domain.ActionAIAnalyze {
		t.Error("expected default allowed action AI_ANALYZE")
	}
}
