package engine

import (
	"context"
	"fmt"
	"log/slog"
	"sync"

	"github.com/schro-cat-dev/sentinel-server/internal/agent"
	"github.com/schro-cat-dev/sentinel-server/internal/domain"
	"github.com/schro-cat-dev/sentinel-server/internal/middleware"
	"github.com/schro-cat-dev/sentinel-server/internal/task"
)

// AgentBridgeConfig はエージェントブリッジの設定
type AgentBridgeConfig struct {
	Enabled      bool   // エージェント委任の有効/無効
	MaxLoopDepth int    // 最大ループ深度
	TimeoutSec   int    // タイムアウト秒数
	// AllowedActions は委任可能なアクションタイプ（空=AI_ANALYZEのみ）
	AllowedActions []domain.TaskActionType
	// AllowedSeverities はエージェント実行を許可する最低severity
	MinSeverity domain.TaskSeverity
}

// DefaultAgentBridgeConfig はデフォルト設定を返す
func DefaultAgentBridgeConfig() AgentBridgeConfig {
	return AgentBridgeConfig{
		Enabled:      false,
		MaxLoopDepth: 5,
		TimeoutSec:   60,
		AllowedActions: []domain.TaskActionType{
			domain.ActionAIAnalyze,
		},
		MinSeverity: domain.SeverityLow,
	}
}

// AgentBridge はTaskExecutorとAgentExecutorを接続するブリッジ
// 検知→タスク生成→AI委任の一貫フローを実現する
type AgentBridge struct {
	mu             sync.RWMutex
	agentExecutor  *agent.AgentExecutor
	authorizer     *middleware.Authorizer
	config         AgentBridgeConfig
	allowedActions map[domain.TaskActionType]bool
	// sourceLogCache はDispatch時点でのソースログを一時保持する
	sourceLogCache map[string]domain.Log
}

// NewAgentBridge はAgentBridgeを生成する
func NewAgentBridge(
	agentExec *agent.AgentExecutor,
	authz *middleware.Authorizer,
	cfg AgentBridgeConfig,
) *AgentBridge {
	allowed := make(map[domain.TaskActionType]bool, len(cfg.AllowedActions))
	for _, a := range cfg.AllowedActions {
		allowed[a] = true
	}
	if len(allowed) == 0 {
		allowed[domain.ActionAIAnalyze] = true
	}
	return &AgentBridge{
		agentExecutor:  agentExec,
		authorizer:     authz,
		config:         cfg,
		allowedActions: allowed,
		sourceLogCache: make(map[string]domain.Log),
	}
}

// SetSourceLog はタスクのソースログを一時キャッシュする（Process内で呼ばれる）
func (b *AgentBridge) SetSourceLog(taskID string, log domain.Log) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.sourceLogCache[taskID] = log
}

// ClearSourceLog はキャッシュを削除する
func (b *AgentBridge) ClearSourceLog(taskID string) {
	b.mu.Lock()
	defer b.mu.Unlock()
	delete(b.sourceLogCache, taskID)
}

func (b *AgentBridge) getSourceLog(taskID string) (domain.Log, bool) {
	b.mu.RLock()
	defer b.mu.RUnlock()
	log, ok := b.sourceLogCache[taskID]
	return log, ok
}

// RegisterHandlers はTaskExecutorにエージェント委任ハンドラを登録する
func (b *AgentBridge) RegisterHandlers(executor *task.TaskExecutor) {
	for action := range b.allowedActions {
		act := action
		executor.RegisterHandler(string(act), func(t domain.GeneratedTask) error {
			return b.handleAgentTask(t)
		})
	}
}

// handleAgentTask はAIエージェントタスクを実行する
func (b *AgentBridge) handleAgentTask(t domain.GeneratedTask) error {
	if !b.config.Enabled {
		slog.Info("agent bridge disabled, skipping AI task",
			"taskId", t.TaskID, "action", t.ActionType)
		return nil
	}

	// Severity チェック
	if !domain.SeverityGTE(t.Severity, b.config.MinSeverity) {
		slog.Info("task severity below agent threshold",
			"taskId", t.TaskID, "severity", t.Severity, "min", b.config.MinSeverity)
		return nil
	}

	// アクションタイプチェック
	if !b.allowedActions[t.ActionType] {
		return fmt.Errorf("action type %s not allowed for agent execution", t.ActionType)
	}

	// ソースログの取得
	sourceLog, ok := b.getSourceLog(t.TaskID)
	if !ok {
		sourceLog = domain.Log{
			TraceID:  t.SourceLog.TraceID,
			Message:  t.SourceLog.Message,
			Boundary: t.SourceLog.Boundary,
			Level:    t.SourceLog.Level,
		}
	}
	defer b.ClearSourceLog(t.TaskID)

	// エージェント実行
	ctx := context.Background()
	record, err := b.agentExecutor.ExecuteTask(ctx, t, sourceLog)
	if err != nil {
		slog.Error("agent execution failed",
			"taskId", t.TaskID, "error", err,
			"loopDepth", record.LoopDepth,
		)
		return fmt.Errorf("agent execution: %w", err)
	}

	slog.Info("agent execution completed",
		"taskId", t.TaskID,
		"status", record.Status,
		"provider", record.Provider,
		"loopDepth", record.LoopDepth,
	)

	return nil
}

// IsEnabled はブリッジが有効かを返す
func (b *AgentBridge) IsEnabled() bool {
	return b.config.Enabled
}
