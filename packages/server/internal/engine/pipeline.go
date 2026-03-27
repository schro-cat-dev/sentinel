package engine

import (
	"context"
	"fmt"
	"log/slog"
	"time"

	"github.com/google/uuid"
	"github.com/schro-cat-dev/sentinel-server/internal/detection"
	"github.com/schro-cat-dev/sentinel-server/internal/domain"
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
}

// Pipeline はログ処理パイプライン全体を統合する
type Pipeline struct {
	normalizer *LogNormalizer
	masking    *security.MaskingService
	signer     *security.IntegritySigner
	detector   *detection.EventDetector
	generator  *task.TaskGenerator
	executor   *task.TaskExecutor
	store      store.Store
	notifier   *webhook.Notifier
	config     PipelineConfig
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

	return &Pipeline{
		normalizer: NewLogNormalizer(cfg.ServiceID),
		masking:    security.NewMaskingService(cfg.MaskingRules, cfg.PreserveFields),
		signer:     signer,
		detector:   detection.NewEventDetector(),
		generator:  task.NewTaskGenerator(cfg.TaskRules),
		executor:   executor,
		store:      st,
		notifier:   notifier,
		config:     cfg,
	}, nil
}

// Process はログを全パイプラインステージに通す（goroutine-safe）
func (p *Pipeline) Process(ctx context.Context, raw domain.Log) (domain.IngestionResult, error) {
	select {
	case <-ctx.Done():
		return domain.IngestionResult{}, fmt.Errorf("request cancelled: %w", ctx.Err())
	default:
	}

	// 1. Normalize
	log, err := p.normalizer.Normalize(raw)
	if err != nil {
		return domain.IngestionResult{}, err
	}

	// 2. Mask PII
	masked := false
	if p.config.EnableMasking {
		p.masking.MaskLog(&log)
		masked = true
	}

	// 3. Hash-chain
	hashChainValid := false
	if p.config.EnableHashChain && p.signer != nil {
		p.signer.ApplyHashChain(&log)
		hashChainValid = true
	}

	// 4. Persist log (if store available)
	if p.store != nil {
		if _, err := p.store.InsertLog(ctx, log); err != nil {
			slog.Error("failed to persist log", "traceId", log.TraceID, "error", err)
		}
	}

	// 5. Detect events
	det := p.detector.Detect(log)

	// 6. Generate + dispatch tasks
	var taskResults []domain.TaskResult
	if det != nil {
		tasks := p.generator.Generate(det, log)
		for _, t := range tasks {
			result := p.executor.Dispatch(t)

			// Persist task
			if p.store != nil {
				if err := p.store.InsertTask(ctx, t, result.Status); err != nil {
					slog.Error("failed to persist task", "taskId", t.TaskID, "error", err)
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
		TraceID:        log.TraceID,
		HashChainValid: hashChainValid,
		Masked:         masked,
		TasksGenerated: taskResults,
	}, nil
}
