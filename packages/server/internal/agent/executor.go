package agent

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"log/slog"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/schro-cat-dev/sentinel-server/internal/domain"
	"github.com/schro-cat-dev/sentinel-server/internal/store"
)

const (
	DefaultMaxLoopDepth = 5
	DefaultTimeoutSec   = 60
)

// AgentExecutorConfig はエージェント実行設定
type AgentExecutorConfig struct {
	MaxLoopDepth int
	TimeoutSec   int
}

// AgentExecutor はAIエージェントの実行を管理する
// ループ防止、タイムアウト、結果永続化、監査ログを担当
type AgentExecutor struct {
	mu       sync.Mutex
	provider Provider
	store    store.Store
	config   AgentExecutorConfig
	// reIngest はAI実行結果をログとして再投入するコールバック
	reIngest func(ctx context.Context, log domain.Log) error
}

func NewAgentExecutor(provider Provider, st store.Store, cfg AgentExecutorConfig, reIngest func(context.Context, domain.Log) error) *AgentExecutor {
	if cfg.MaxLoopDepth <= 0 {
		cfg.MaxLoopDepth = DefaultMaxLoopDepth
	}
	if cfg.TimeoutSec <= 0 {
		cfg.TimeoutSec = DefaultTimeoutSec
	}
	return &AgentExecutor{
		provider: provider,
		store:    st,
		config:   cfg,
		reIngest: reIngest,
	}
}

// ExecuteTask はAIエージェントタスクを実行する
// ループ深度チェック→タイムアウト付き実行→結果永続化→ログ再投入
func (e *AgentExecutor) ExecuteTask(ctx context.Context, task domain.GeneratedTask, sourceLog domain.Log) (*ExecutionRecord, error) {
	// 1. ループ深度チェック
	currentDepth := 0
	if sourceLog.AIContext != nil {
		currentDepth = sourceLog.AIContext.LoopDepth
	}
	if currentDepth >= e.config.MaxLoopDepth {
		slog.Warn("AI loop depth limit reached",
			"taskId", task.TaskID,
			"depth", currentDepth,
			"maxDepth", e.config.MaxLoopDepth,
			"traceId", sourceLog.TraceID,
		)
		return &ExecutionRecord{
			AgentID:   e.provider.Name(),
			TaskID:    task.TaskID,
			Status:    "failed",
			Error:     fmt.Sprintf("loop depth limit reached (%d/%d)", currentDepth, e.config.MaxLoopDepth),
			LoopDepth: currentDepth,
		}, fmt.Errorf("loop depth limit reached")
	}

	// 2. タイムアウト付きコンテキスト
	execCtx, cancel := context.WithTimeout(ctx, time.Duration(e.config.TimeoutSec)*time.Second)
	defer cancel()

	// 3. 実行記録開始
	record := &ExecutionRecord{
		AgentID:   e.provider.Name(),
		TaskID:    task.TaskID,
		Provider:  e.provider.Name(),
		InputHash: computeInputHash(sourceLog),
		StartedAt: time.Now().UTC(),
		LoopDepth: currentDepth + 1,
	}

	// 4. AI推論実行
	result, err := e.provider.Execute(execCtx, task, sourceLog)
	record.CompletedAt = time.Now().UTC()

	if err != nil {
		record.Status = "failed"
		record.Error = err.Error()
		slog.Error("AI agent execution failed",
			"taskId", task.TaskID, "provider", e.provider.Name(), "error", err,
		)
	} else {
		record.Status = "success"
		record.Result = result
		record.Model = result.Model
		slog.Info("AI agent execution completed",
			"taskId", task.TaskID, "provider", e.provider.Name(),
			"model", result.Model, "confidence", result.Confidence,
			"action", result.Action, "tokens", result.TokensUsed,
		)
	}

	// 5. 結果をログとして再投入（origin: AI_AGENT でループ検知防止）
	if e.reIngest != nil {
		agentLog := domain.Log{
			TraceID:  sourceLog.TraceID, // 同一トレースID保持
			SpanID:   uuid.New().String(),
			ActorID:  e.provider.Name(),
			Type:     domain.LogTypeSystem,
			Level:    agentLogLevel(record.Status),
			Origin:   domain.OriginAIAgent,
			Message:  fmt.Sprintf("AI Agent Result: %s", record.Status),
			Boundary: fmt.Sprintf("agent:%s", e.provider.Name()),
			AIContext: &domain.AIContext{
				AgentID:    e.provider.Name(),
				TaskID:     task.TaskID,
				LoopDepth:  record.LoopDepth,
				Model:      record.Model,
				Confidence: confidenceOrZero(result),
			},
			AgentBackLog: []domain.AgentBackLogEntry{
				{
					AgentID:   e.provider.Name(),
					Action:    actionOrEmpty(result),
					Timestamp: record.CompletedAt,
					Result:    resultSummary(result, err),
					Status:    record.Status,
				},
			},
			TriggerAgent: false, // AI_AGENTログではagent再起動しない
		}

		if reErr := e.reIngest(ctx, agentLog); reErr != nil {
			slog.Error("failed to re-ingest agent log", "error", reErr)
		}
	}

	// 6. 実行結果をStoreに永続化
	if e.store != nil {
		taskResult := domain.TaskResult{
			TaskID:       task.TaskID,
			RuleID:       task.RuleID,
			Status:       mapAgentStatus(record.Status),
			DispatchedAt: record.CompletedAt,
			Error:        record.Error,
		}
		if insertErr := e.store.InsertTaskResult(ctx, taskResult); insertErr != nil {
			slog.Error("failed to persist agent result", "error", insertErr)
		}
	}

	return record, err
}

func computeInputHash(log domain.Log) string {
	data, _ := json.Marshal(map[string]string{
		"traceId": log.TraceID,
		"message": log.Message,
	})
	h := sha256.Sum256(data)
	return fmt.Sprintf("%x", h[:16]) // 短縮ハッシュ
}

func agentLogLevel(status string) domain.LogLevel {
	if status == "failed" {
		return domain.LogLevelError
	}
	return domain.LogLevelInfo
}

func confidenceOrZero(result *InferenceResult) float64 {
	if result != nil {
		return result.Confidence
	}
	return 0
}

func actionOrEmpty(result *InferenceResult) string {
	if result != nil {
		return result.Action
	}
	return ""
}

func resultSummary(result *InferenceResult, err error) string {
	if err != nil {
		return fmt.Sprintf("error: %s", err.Error())
	}
	if result != nil {
		return fmt.Sprintf("action=%s confidence=%.2f", result.Action, result.Confidence)
	}
	return "no result"
}

func mapAgentStatus(status string) domain.TaskDispatchStatus {
	switch status {
	case "success":
		return domain.StatusCompleted
	case "failed", "timeout":
		return domain.StatusFailed
	default:
		return domain.StatusFailed
	}
}
