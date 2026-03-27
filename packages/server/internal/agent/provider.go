package agent

import (
	"context"
	"time"

	"github.com/schro-cat-dev/sentinel-server/internal/domain"
)

// InferenceResult はAIエージェントの推論結果
type InferenceResult struct {
	Thought    string  // AIの思考プロセス
	Action     string  // 決定されたアクション
	Confidence float64 // 信頼度 (0.0-1.0)
	Model      string  // 使用モデル
	TokensUsed int     // 消費トークン数
}

// Provider はAIエージェントプロバイダの抽象インターフェース
// OpenAI, Anthropic, ローカルLLM等を差し替え可能
type Provider interface {
	// Execute はタスク定義とログコンテキストからAI推論を実行する
	Execute(ctx context.Context, task domain.GeneratedTask, log domain.Log) (*InferenceResult, error)

	// Name はプロバイダ名を返す
	Name() string
}

// ExecutionRecord はAIエージェント実行の完全な記録（監査用）
type ExecutionRecord struct {
	AgentID     string
	TaskID      string
	Provider    string
	Model       string
	InputHash   string
	Result      *InferenceResult
	StartedAt   time.Time
	CompletedAt time.Time
	Status      string // "success", "failed", "timeout"
	Error       string
	LoopDepth   int
}
