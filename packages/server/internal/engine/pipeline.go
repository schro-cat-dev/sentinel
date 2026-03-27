package engine

import (
	"context"
	"fmt"
	"log/slog"
	"time"

	"github.com/google/uuid"
	"github.com/schro-cat-dev/sentinel-server/internal/detection"
	"github.com/schro-cat-dev/sentinel-server/internal/domain"
	"github.com/schro-cat-dev/sentinel-server/internal/middleware"
	"github.com/schro-cat-dev/sentinel-server/internal/response"
	"github.com/schro-cat-dev/sentinel-server/internal/security"
	"github.com/schro-cat-dev/sentinel-server/internal/store"
	"github.com/schro-cat-dev/sentinel-server/internal/task"
	"github.com/schro-cat-dev/sentinel-server/internal/webhook"
)

// PipelineConfig はパイプラインの設定
type PipelineConfig struct {
	ServiceID       string
	EnableHashChain bool
	EnableMasking   bool
	MaskingRules    []security.MaskingRule
	PreserveFields  []string
	TaskRules       []domain.TaskRule
	HMACKey         []byte
	RoutingRules    []domain.ApprovalRoutingRule

	// --- Enhanced security modules ---

	// EnableEnsemble はアンサンブル検知を有効にする
	EnableEnsemble bool
	// EnsembleAggregator はスコア集約方式 (0=Max, 1=Avg, 2=WeightedSum)
	EnsembleAggregator detection.ScoreAggregator
	// EnsembleThreshold はアンサンブル発火閾値 (0.0〜1.0)
	EnsembleThreshold float64
	// DedupWindowSec は重複抑制ウィンドウ秒数 (0=無効)
	DedupWindowSec int
	// DynamicDetectionRules は設定ベースの動的検知ルール
	DynamicDetectionRules []detection.DynamicRuleConfig

	// EnableAnomalyDetection は統計的異常検知を有効にする
	EnableAnomalyDetection bool
	// AnomalyConfig は異常検知設定
	AnomalyConfig detection.AnomalyConfig

	// EnableMaskingPolicy はコンテキスト依存マスクポリシーを有効にする
	EnableMaskingPolicy bool
	// MaskingPolicies はマスクポリシールール
	MaskingPolicies []security.MaskingPolicyRule

	// EnableMaskingVerification はマスク後のPII残留検証を有効にする
	EnableMaskingVerification bool

	// EnableAuthorization はRBAC認可を有効にする
	EnableAuthorization bool
	// AuthzConfig は認可設定
	AuthzConfig middleware.AuthzConfig

	// AgentBridgeConfig はエージェントブリッジ設定
	AgentBridge AgentBridgeConfig

	// FailOnPersistError はtrue時に永続化失敗でエラーを返す（デフォルトfalse=degraded mode）
	FailOnPersistError bool
}

// Pipeline はログ処理パイプライン全体を統合する
type Pipeline struct {
	normalizer   *LogNormalizer
	masking      *security.MaskingService
	signer       *security.IntegritySigner
	detector     *detection.EventDetector
	generator    *task.TaskGenerator
	executor     *task.TaskExecutor
	store        store.Store
	notifier     *webhook.Notifier
	config       PipelineConfig

	// Enhanced modules (nil when disabled)
	ensemble     *detection.EnsembleDetector
	anomaly      *detection.AnomalyDetector
	maskingPolicy *security.MaskingPolicyEngine
	verifier     *security.MaskingVerifier
	authorizer   *middleware.Authorizer
	agentBridge  *AgentBridge
	threatOrch   *response.ThreatResponseOrchestrator
}

// NewPipeline はPipelineを生成する
func NewPipeline(cfg PipelineConfig, executor *task.TaskExecutor, st store.Store, notifier *webhook.Notifier) (*Pipeline, error) {
	var signer *security.IntegritySigner
	if cfg.EnableHashChain {
		var err error
		signer, err = security.NewIntegritySigner(cfg.HMACKey)
		if err != nil {
			return nil, fmt.Errorf("signer init: %w", err)
		}
	}

	p := &Pipeline{
		normalizer: NewLogNormalizer(cfg.ServiceID),
		masking:    security.NewMaskingService(cfg.MaskingRules, cfg.PreserveFields),
		signer:     signer,
		detector:   detection.NewEventDetector(),
		generator:  task.NewTaskGenerator(cfg.TaskRules),
		executor:   executor,
		store:      st,
		notifier:   notifier,
		config:     cfg,
	}

	// --- Initialize enhanced modules ---

	// Ensemble detector
	if cfg.EnableEnsemble {
		rules, err := buildEnsembleRules(cfg)
		if err != nil {
			return nil, fmt.Errorf("ensemble rules: %w", err)
		}
		opts := []detection.EnsembleOption{
			detection.WithAggregator(cfg.EnsembleAggregator),
		}
		if cfg.EnsembleThreshold > 0 {
			opts = append(opts, detection.WithThreshold(&detection.ThresholdPolicy{
				MinScore: cfg.EnsembleThreshold,
			}))
		}
		if cfg.DedupWindowSec > 0 {
			dedup := detection.NewDeduplicator(time.Duration(cfg.DedupWindowSec) * time.Second)
			opts = append(opts, detection.WithDeduplicator(dedup))
		}
		p.ensemble = detection.NewEnsembleDetector(rules, opts...)
	}

	// Anomaly detector
	if cfg.EnableAnomalyDetection {
		acfg := cfg.AnomalyConfig
		if acfg.WindowSize == 0 {
			acfg = detection.DefaultAnomalyConfig()
		}
		p.anomaly = detection.NewAnomalyDetector(acfg)
	}

	// Masking policy engine
	if cfg.EnableMaskingPolicy && len(cfg.MaskingPolicies) > 0 {
		p.maskingPolicy = security.NewMaskingPolicyEngine(
			cfg.MaskingPolicies, cfg.MaskingRules, cfg.PreserveFields,
		)
	}

	// Masking verifier
	if cfg.EnableMaskingVerification {
		p.verifier = security.NewMaskingVerifier()
	}

	// Authorizer
	if cfg.EnableAuthorization {
		p.authorizer = middleware.NewAuthorizer(cfg.AuthzConfig)
	}

	return p, nil
}

// SetAgentBridge はエージェントブリッジを設定する（Pipeline生成後に呼ぶ）
func (p *Pipeline) SetAgentBridge(bridge *AgentBridge) {
	p.agentBridge = bridge
	if bridge != nil {
		bridge.RegisterHandlers(p.executor)
	}
}

// SetThreatOrchestrator は脅威レスポンスオーケストレータを設定する
func (p *Pipeline) SetThreatOrchestrator(orch *response.ThreatResponseOrchestrator) {
	p.threatOrch = orch
}

// buildEnsembleRules はデフォルトルール＋動的ルールからアンサンブルルール群を構築する
func buildEnsembleRules(cfg PipelineConfig) ([]detection.ScoredDetectionRule, error) {
	// デフォルトの4ルールをアダプタでラップ
	rules := []detection.ScoredDetectionRule{
		detection.WrapRule(&detection.CriticalRule{}, "builtin-critical", 1.0),
		detection.WrapRule(&detection.SecurityIntrusionRule{}, "builtin-security", 0.9),
		detection.WrapRule(&detection.ComplianceViolationRule{}, "builtin-compliance", 0.85),
		detection.WrapRule(&detection.SLAViolationRule{}, "builtin-sla", 0.7),
	}

	// 動的ルールの追加
	if len(cfg.DynamicDetectionRules) > 0 {
		dynRules, err := detection.LoadDynamicRules(cfg.DynamicDetectionRules)
		if err != nil {
			return nil, err
		}
		rules = append(rules, dynRules...)
	}

	return rules, nil
}

// Process はログを全パイプラインステージに通す（goroutine-safe）
func (p *Pipeline) Process(ctx context.Context, raw domain.Log) (domain.IngestionResult, error) {
	select {
	case <-ctx.Done():
		return domain.IngestionResult{}, fmt.Errorf("request cancelled: %w", ctx.Err())
	default:
	}

	// 0. Authorization (if enabled)
	if p.authorizer != nil {
		clientID := middleware.ClientIDFromContext(ctx)
		if clientID == "" {
			clientID = "anonymous"
		}
		if err := p.authorizer.CheckWriteLog(clientID, string(raw.Type), int(raw.Level)); err != nil {
			return domain.IngestionResult{}, fmt.Errorf("authorization: %w", err)
		}
	}

	// 1. Normalize
	log, err := p.normalizer.Normalize(raw)
	if err != nil {
		return domain.IngestionResult{}, err
	}

	// 2. Mask PII (with policy engine if available)
	masked := false
	if p.config.EnableMasking {
		if p.maskingPolicy != nil {
			svc := p.maskingPolicy.CreateMaskingService(log)
			svc.MaskLog(&log)
		} else {
			p.masking.MaskLog(&log)
		}
		masked = true

		// 2b. Verification pass (if enabled)
		if p.verifier != nil {
			vResult := p.verifier.VerifyLog(log)
			if !vResult.Clean {
				slog.Warn("PII leak detected after masking",
					"traceId", log.TraceID,
					"leakCount", len(vResult.Leaks),
				)
				// 漏洩検出フィールドのみフォールバック再マスク
				// ただしポリシーで保護されたフィールドはスキップ
				preserveSet := make(map[string]bool)
				if p.maskingPolicy != nil {
					_, preserveFields := p.maskingPolicy.ResolveRules(log)
					for _, f := range preserveFields {
						preserveSet[f] = true
					}
				}
				for _, f := range p.config.PreserveFields {
					preserveSet[f] = true
				}

				for _, leak := range vResult.Leaks {
					if preserveSet[leak.FieldName] {
						continue
					}
					switch leak.FieldName {
					case "message":
						log.Message = security.MaskAllPII(log.Message)
					case "actorId":
						if !preserveSet["actorId"] {
							log.ActorID = security.MaskAllPII(log.ActorID)
						}
					case "input":
						log.Input = security.MaskAllPII(log.Input)
					}
				}
			}
		}
	}

	// 3. Hash-chain
	hashChainValid := false
	if p.config.EnableHashChain && p.signer != nil {
		p.signer.ApplyHashChain(&log)
		hashChainValid = true
	}

	// 4. Persist log (if store available)
	degraded := false
	var warnings []string
	if p.store != nil {
		if _, err := p.store.InsertLog(ctx, log); err != nil {
			slog.Error("failed to persist log", "traceId", log.TraceID, "error", err)
			if p.config.FailOnPersistError {
				return domain.IngestionResult{}, fmt.Errorf("persist log: %w", err)
			}
			degraded = true
			warnings = append(warnings, "log persistence failed: "+err.Error())
		}
	}

	// 5. Detect events (ensemble or legacy)
	var detections []*domain.DetectionResult
	if p.ensemble != nil {
		ensResult := p.ensemble.DetectAll(log)
		if ensResult != nil {
			detections = ensResult.Results
		}
	} else {
		det := p.detector.Detect(log)
		if det != nil {
			detections = []*domain.DetectionResult{det}
		}
	}

	// 5b. Anomaly detection (additive)
	if p.anomaly != nil {
		anomalyResult := p.anomaly.Analyze(log)
		if anomalyResult != nil {
			detections = append(detections, anomalyResult)
		}
	}

	// 5c. Threat response orchestration
	var threatSummaries []domain.ThreatResponseSummary
	if p.threatOrch != nil && p.threatOrch.IsEnabled() {
		for _, det := range detections {
			record, err := p.threatOrch.Handle(ctx, det, log)
			if err != nil {
				slog.Error("threat response failed", "eventName", det.EventName, "error", err)
				continue
			}
			if record != nil {
				summary := domain.ThreatResponseSummary{
					ResponseID: record.ResponseID,
					EventName:  record.EventName,
					Strategy:   string(record.Strategy),
					Notified:   record.Notified,
				}
				if record.Block != nil {
					summary.Blocked = record.Block.Success
					summary.BlockTarget = record.Block.Target
				}
				if record.Analysis != nil && record.Analysis.Error == "" {
					summary.Analyzed = true
					summary.RiskLevel = record.Analysis.RiskLevel
				}
				threatSummaries = append(threatSummaries, summary)
			}
		}
	}

	// 6. Generate + dispatch tasks for all detections
	var taskResults []domain.TaskResult
	for _, det := range detections {
		tasks := p.generator.Generate(det, log)
		for _, t := range tasks {
			// エージェントブリッジ用にソースログをキャッシュ
			if p.agentBridge != nil && p.agentBridge.IsEnabled() {
				p.agentBridge.SetSourceLog(t.TaskID, log)
			}

			result := p.executor.Dispatch(t)

			// Persist task
			if p.store != nil {
				if err := p.store.InsertTask(ctx, t, result.Status); err != nil {
					slog.Error("failed to persist task", "taskId", t.TaskID, "error", err)
					if p.config.FailOnPersistError {
						return domain.IngestionResult{}, fmt.Errorf("persist task: %w", err)
					}
					degraded = true
					warnings = append(warnings, "task persistence failed: "+err.Error())
				}

				// Create approval request for blocked tasks (with routing + content hash)
				if result.Status == domain.StatusBlockedApproval {
					contentHash := domain.ComputeTaskContentHash(t)

					// Determine approval chain from routing rules
					chain := DefaultApprovalChain()
					if rule := FindRoutingRule(p.config.RoutingRules, log.Level, t.EventName); rule != nil {
						chain = rule.Chain
					}

					totalSteps := len(chain)
					if totalSteps == 0 {
						totalSteps = 1
					}

					approval := domain.ApprovalRequest{
						ApprovalID:  uuid.New().String(),
						TaskID:      t.TaskID,
						RequestedAt: time.Now().UTC(),
						Status:      "pending",
						ContentHash: contentHash,
						CurrentStep: 1,
						TotalSteps:  totalSteps,
					}
					if err := p.store.InsertApproval(ctx, approval); err != nil {
						slog.Error("failed to create approval", "taskId", t.TaskID, "error", err)
					}

					// Webhook notification (non-blocking)
					if p.notifier != nil {
						p.notifier.NotifyApprovalRequired(ctx, webhook.ApprovalPayload{
							TaskID:      t.TaskID,
							RuleID:      t.RuleID,
							EventName:   t.EventName,
							Severity:    string(t.Severity),
							ActionType:  string(t.ActionType),
							Description: t.Description,
							RequestedAt: approval.RequestedAt.Format(time.RFC3339),
							SourceLog: struct {
								TraceID  string `json:"trace_id"`
								Message  string `json:"message"`
								Boundary string `json:"boundary"`
							}{
								TraceID:  t.SourceLog.TraceID,
								Message:  t.SourceLog.Message,
								Boundary: t.SourceLog.Boundary,
							},
						})
					}
				}

				// Persist task result
				if err := p.store.InsertTaskResult(ctx, result); err != nil {
					slog.Error("failed to persist task result", "taskId", t.TaskID, "error", err)
				}
			}

			taskResults = append(taskResults, result)
		}
	}

	return domain.IngestionResult{
		TraceID:         log.TraceID,
		HashChainValid:  hashChainValid,
		Masked:          masked,
		Degraded:        degraded,
		Warnings:        warnings,
		TasksGenerated:  taskResults,
		ThreatResponses: threatSummaries,
	}, nil
}
