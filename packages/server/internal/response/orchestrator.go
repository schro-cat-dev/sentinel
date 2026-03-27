package response

import (
	"context"
	"fmt"
	"log/slog"
	"time"

	"github.com/google/uuid"
	"github.com/schro-cat-dev/sentinel-server/internal/domain"
)

// NotifyFunc は通知送信のコールバック
type NotifyFunc func(ctx context.Context, record ThreatResponseRecord) error

// PersistFunc は脅威レスポンス記録の永続化コールバック
type PersistFunc func(ctx context.Context, record ThreatResponseRecord) error

// ThreatResponseOrchestrator は検知→分析→ブロック→通知を統合制御する
type ThreatResponseOrchestrator struct {
	config    ThreatResponseConfig
	blocker   *BlockDispatcher
	analyzer  AnalysisAgent
	notifyFn  NotifyFunc
	persistFn PersistFunc
}

// OrchestratorOption はオーケストレータの設定オプション
type OrchestratorOption func(*ThreatResponseOrchestrator)

// WithNotifyFunc は通知コールバックを設定する
func WithNotifyFunc(fn NotifyFunc) OrchestratorOption {
	return func(o *ThreatResponseOrchestrator) { o.notifyFn = fn }
}

// WithPersistFunc は永続化コールバックを設定する
func WithPersistFunc(fn PersistFunc) OrchestratorOption {
	return func(o *ThreatResponseOrchestrator) { o.persistFn = fn }
}

// NewThreatResponseOrchestrator はオーケストレータを生成する
func NewThreatResponseOrchestrator(
	cfg ThreatResponseConfig,
	blocker *BlockDispatcher,
	analyzer AnalysisAgent,
	opts ...OrchestratorOption,
) *ThreatResponseOrchestrator {
	o := &ThreatResponseOrchestrator{
		config:   cfg,
		blocker:  blocker,
		analyzer: analyzer,
	}
	for _, opt := range opts {
		opt(o)
	}
	return o
}

// Handle は検知結果に対して戦略に基づくレスポンスを実行する
func (o *ThreatResponseOrchestrator) Handle(ctx context.Context, det *domain.DetectionResult, log domain.Log) (*ThreatResponseRecord, error) {
	if !o.config.Enabled {
		return nil, nil
	}

	// 1. 戦略の解決
	strategy := o.config.DefaultStrategy
	var rule *ResponseRuleConfig
	rule = FindResponseRule(o.config, det.EventName, det.Priority)
	if rule != nil {
		strategy = rule.Strategy
	}

	// 2. 脅威対象の抽出
	target := ExtractThreatTarget(det, log)

	// 3. レコード作成
	record := ThreatResponseRecord{
		ResponseID: uuid.New().String(),
		TraceID:    log.TraceID,
		EventName:  det.EventName,
		Strategy:   strategy,
		Target:     target,
		CreatedAt:  time.Now().UTC(),
	}
	if rule != nil && len(rule.NotifyTargets) > 0 {
		record.NotifyTarget = rule.NotifyTargets[0]
	}

	// 4. 戦略に基づく実行
	switch strategy {
	case StrategyBlockAndNotify:
		o.executeAnalysis(ctx, det, log, rule, &record)
		o.executeBlock(ctx, rule, target, &record)
		o.executeNotify(ctx, &record)

	case StrategyAnalyzeAndNotify:
		o.executeAnalysis(ctx, det, log, rule, &record)
		o.executeNotify(ctx, &record)

	case StrategyNotifyOnly:
		o.executeNotify(ctx, &record)

	case StrategyBlockOnly:
		o.executeBlock(ctx, rule, target, &record)

	case StrategyMonitor:
		// ログ記録のみ
		slog.Info("threat monitored",
			"eventName", det.EventName,
			"traceId", log.TraceID,
			"boundary", log.Boundary,
		)
	}

	// 5. 永続化
	if o.persistFn != nil {
		if err := o.persistFn(ctx, record); err != nil {
			slog.Error("failed to persist threat response", "error", err)
		}
	}

	return &record, nil
}

func (o *ThreatResponseOrchestrator) executeAnalysis(
	ctx context.Context,
	det *domain.DetectionResult,
	log domain.Log,
	rule *ResponseRuleConfig,
	record *ThreatResponseRecord,
) {
	if o.analyzer == nil {
		return
	}

	prompt := "Analyze this security detection event and provide risk assessment."
	if rule != nil && rule.AnalysisPrompt != "" {
		prompt = rule.AnalysisPrompt
	}

	result, err := o.analyzer.Analyze(ctx, det, log, prompt)
	if err != nil {
		slog.Error("analysis failed",
			"eventName", det.EventName,
			"traceId", log.TraceID,
			"error", err,
		)
		record.Analysis = &AnalysisResult{
			Error:      fmt.Sprintf("analysis failed: %s", err.Error()),
			AnalyzedAt: time.Now().UTC(),
		}
		return
	}
	record.Analysis = result
}

func (o *ThreatResponseOrchestrator) executeBlock(
	ctx context.Context,
	rule *ResponseRuleConfig,
	target ThreatTarget,
	record *ThreatResponseRecord,
) {
	if o.blocker == nil {
		return
	}

	actionType := "block_ip" // default
	if rule != nil && rule.BlockAction != "" {
		actionType = rule.BlockAction
	}

	result, err := o.blocker.Execute(ctx, actionType, target)
	if err != nil {
		slog.Error("block execution failed",
			"actionType", actionType,
			"target", target.IP,
			"error", err,
		)
	}
	record.Block = result
}

func (o *ThreatResponseOrchestrator) executeNotify(
	ctx context.Context,
	record *ThreatResponseRecord,
) {
	if o.notifyFn == nil {
		record.Notified = false
		return
	}

	if err := o.notifyFn(ctx, *record); err != nil {
		slog.Error("notification failed", "error", err)
		record.Notified = false
		return
	}
	record.Notified = true
}

// IsEnabled はオーケストレータが有効か返す
func (o *ThreatResponseOrchestrator) IsEnabled() bool {
	return o.config.Enabled
}
