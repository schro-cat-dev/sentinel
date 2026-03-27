package main

import (
	"context"
	"flag"
	"log/slog"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/schro-cat-dev/sentinel-server/config"
	"github.com/schro-cat-dev/sentinel-server/internal/agent"
	"github.com/schro-cat-dev/sentinel-server/internal/detection"
	"github.com/schro-cat-dev/sentinel-server/internal/domain"
	"github.com/schro-cat-dev/sentinel-server/internal/engine"
	sentinelgrpc "github.com/schro-cat-dev/sentinel-server/internal/grpc"
	"github.com/schro-cat-dev/sentinel-server/internal/middleware"
	"github.com/schro-cat-dev/sentinel-server/internal/notify"
	"github.com/schro-cat-dev/sentinel-server/internal/response"
	"github.com/schro-cat-dev/sentinel-server/internal/security"
	"github.com/schro-cat-dev/sentinel-server/internal/store"
	"github.com/schro-cat-dev/sentinel-server/internal/task"
	"github.com/schro-cat-dev/sentinel-server/internal/webhook"

	ggrpc "google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
)

func main() {
	configPath := flag.String("config", "config/sentinel.yaml", "path to config file")
	flag.Parse()

	slog.SetDefault(slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelInfo})))

	cfg, err := config.Load(*configPath)
	if err != nil {
		slog.Error("failed to load config", "error", err)
		os.Exit(1)
	}

	// Store（ドライバ選択: sqlite / sqlite_encrypted）
	st, err := store.NewStore(store.StoreConfig{
		Driver:        cfg.Store.Driver,
		DSN:           cfg.Store.DSN,
		EncryptionKey: cfg.Store.EncryptionKey,
	})
	if err != nil {
		slog.Error("failed to init store", "error", err, "driver", cfg.Store.Driver)
		os.Exit(1)
	}
	defer st.Close()
	slog.Info("store initialized", "driver", cfg.Store.Driver)

	// Webhook notifier
	var notifier *webhook.Notifier
	if cfg.Webhook.Enabled && cfg.Webhook.URL != "" {
		notifier = webhook.NewNotifier(cfg.Webhook.URL, cfg.Webhook.TimeoutSec, cfg.Webhook.Secret)
	}

	// Pipeline config — 全モジュールの設定をマッピング
	pipeCfg := engine.PipelineConfig{
		ServiceID:       cfg.Pipeline.ServiceID,
		EnableHashChain: cfg.Security.EnableHashChain,
		EnableMasking:   cfg.Security.EnableMasking,
		HMACKey:         []byte(cfg.Security.HMACKey),
		PreserveFields:  cfg.Security.PreserveFields,
		MaskingRules:    convertMaskingRules(cfg.Security.MaskingRules),
		TaskRules:       convertTaskRules(cfg.Pipeline.Rules),

		// Ensemble detection
		EnableEnsemble:        cfg.Ensemble.Enabled,
		EnsembleAggregator:    convertAggregator(cfg.Ensemble.Aggregator),
		EnsembleThreshold:     cfg.Ensemble.Threshold,
		DedupWindowSec:        cfg.Ensemble.DedupWindowSec,
		DynamicDetectionRules: convertDynamicRules(cfg.Ensemble.DynamicRules),

		// Anomaly detection
		EnableAnomalyDetection: cfg.Anomaly.Enabled,
		AnomalyConfig: detection.AnomalyConfig{
			WindowSize:     time.Duration(cfg.Anomaly.WindowSizeSec) * time.Second,
			BaselineWindow: time.Duration(cfg.Anomaly.BaselineWindowSec) * time.Second,
			ThresholdPct:   cfg.Anomaly.ThresholdPct,
			MinBaseline:    cfg.Anomaly.MinBaseline,
		},

		// Masking verification
		EnableMaskingVerification: cfg.Security.EnableMasking, // 有効ならverificationも有効

		// Authorization
		EnableAuthorization: cfg.Authorization.Enabled,
		AuthzConfig:         convertAuthzConfig(cfg.Authorization),

		// Masking policies (if configured)
		EnableMaskingPolicy: len(cfg.MaskingPolicies) > 0,
		MaskingPolicies:     convertMaskingPolicies(cfg.MaskingPolicies),

		// Approval routing rules
		RoutingRules: convertRoutingRules(cfg.RoutingRules),
	}

	// Executor
	executor := task.NewTaskExecutor(func(t domain.GeneratedTask) error {
		slog.Info("task dispatched",
			"taskId", t.TaskID, "ruleId", t.RuleID,
			"action", string(t.ActionType), "severity", string(t.Severity))
		return nil
	})

	// gRPC interceptors
	var interceptors []ggrpc.UnaryServerInterceptor

	// アクセスログ（常に有効）
	interceptors = append(interceptors, sentinelgrpc.AuditLogUnaryInterceptor())

	if cfg.Auth.Enabled {
		keyMap := make(map[string]bool, len(cfg.Auth.APIKeys))
		for _, k := range cfg.Auth.APIKeys {
			keyMap[k] = true
		}
		interceptors = append(interceptors,
			sentinelgrpc.AuthUnaryInterceptor(keyMap),
			sentinelgrpc.RateLimitUnaryInterceptor(cfg.Auth.RateLimitRPS, cfg.Auth.RateLimitBurst),
		)
	}

	var opts []ggrpc.ServerOption
	if len(interceptors) > 0 {
		opts = append(opts, ggrpc.ChainUnaryInterceptor(interceptors...))
	}

	// TLS
	if cfg.Server.TLSCertFile != "" && cfg.Server.TLSKeyFile != "" {
		creds, err := credentials.NewServerTLSFromFile(cfg.Server.TLSCertFile, cfg.Server.TLSKeyFile)
		if err != nil {
			slog.Error("failed to load TLS credentials", "error", err)
			os.Exit(1)
		}
		opts = append(opts, ggrpc.Creds(creds))
		slog.Info("TLS enabled", "cert", cfg.Server.TLSCertFile)
	}

	sentinel, srv, lis, err := sentinelgrpc.StartServerWithSentinel(cfg.Server.Addr, pipeCfg, executor, st, notifier, opts...)
	if err != nil {
		slog.Error("failed to start server", "error", err)
		os.Exit(1)
	}

	// --- Post-init: Agent Bridge ---
	if cfg.Agent.Enabled {
		provider := agent.NewMockProvider(cfg.Agent.Provider) // 実環境では実プロバイダに差し替え
		agentExec := agent.NewAgentExecutor(provider, st, agent.AgentExecutorConfig{
			MaxLoopDepth: cfg.Agent.MaxLoopDepth,
			TimeoutSec:   cfg.Agent.TimeoutSec,
		}, func(ctx context.Context, log domain.Log) error {
			// AI実行結果のログ再投入（Pipeline.Processを直接呼ぶとループ検知に引っかかる設計）
			slog.Info("agent log re-ingested", "traceId", log.TraceID, "origin", log.Origin)
			return nil
		})

		bridge := engine.NewAgentBridge(agentExec, nil, engine.AgentBridgeConfig{
			Enabled:        true,
			MaxLoopDepth:   cfg.Agent.MaxLoopDepth,
			TimeoutSec:     cfg.Agent.TimeoutSec,
			AllowedActions: convertAllowedActions(cfg.Agent.AllowedActions),
			MinSeverity:    domain.TaskSeverity(cfg.Agent.MinSeverity),
		})
		sentinel.Pipeline().SetAgentBridge(bridge)
		slog.Info("agent bridge enabled", "provider", cfg.Agent.Provider)
	}

	// --- Post-init: Threat Response Orchestrator ---
	if cfg.Response.Enabled {
		blockMode := response.ExecModeImmediate
		if cfg.Response.BlockMode == "REQUIRE_APPROVAL" {
			blockMode = response.ExecModeRequireApproval
		}
		enhancedBlocker := response.NewEnhancedBlockDispatcher(blockMode, nil)
		enhancedBlocker.Register(response.NewIPBlockAction())
		enhancedBlocker.Register(response.NewAccountLockAction())

		analyzer := response.NewMockAnalysisAgent() // 実環境では実プロバイダに差し替え

		respCfg := response.ThreatResponseConfig{
			Enabled:         true,
			DefaultStrategy: response.ResponseStrategy(cfg.Response.DefaultStrategy),
			Rules:           convertResponseRules(cfg.Response.Rules),
		}

		var orchOpts []response.OrchestratorOption

		// 永続化: Store.InsertThreatResponse に接続
		orchOpts = append(orchOpts, response.WithPersistFunc(func(ctx context.Context, record response.ThreatResponseRecord) error {
			storeRecord := domain.ThreatResponseStoreRecord{
				ResponseID: record.ResponseID,
				TraceID:    record.TraceID,
				EventName:  string(record.EventName),
				Strategy:   string(record.Strategy),
				TargetIP:   record.Target.IP,
				TargetUserID: record.Target.UserID,
				Boundary:   record.Target.Boundary,
				Notified:   record.Notified,
				NotifyTarget: record.NotifyTarget,
				CreatedAt:  record.CreatedAt.Format("2006-01-02T15:04:05Z07:00"),
			}
			if record.Block != nil {
				storeRecord.BlockAction = record.Block.ActionType
				storeRecord.BlockSuccess = record.Block.Success
				storeRecord.BlockTarget = record.Block.Target
			}
			if record.Analysis != nil && record.Analysis.Error == "" {
				storeRecord.Analyzed = true
				storeRecord.RiskLevel = record.Analysis.RiskLevel
				storeRecord.Confidence = record.Analysis.Confidence
				storeRecord.AnalysisSummary = record.Analysis.Summary
			}
			return st.InsertThreatResponse(ctx, storeRecord)
		}))

		// 通知: MultiNotifier を構築して接続
		multiNotifier := notify.NewMultiNotifier()
		multiNotifier.Register(notify.NewLogNotifier()) // fallback: 常にログ出力

		if cfg.Webhook.Enabled && cfg.Webhook.URL != "" {
			multiNotifier.Register(notify.NewWebhookNotifier(notify.WebhookConfig{
				URL: cfg.Webhook.URL, TimeoutSec: cfg.Webhook.TimeoutSec, Secret: cfg.Webhook.Secret,
			}))
			multiNotifier.SetRouting("https://", []string{"webhook"})
		}
		// Slack: SENTINEL_SLACK_WEBHOOK_URL 環境変数で設定
		if slackURL := os.Getenv("SENTINEL_SLACK_WEBHOOK_URL"); slackURL != "" {
			multiNotifier.Register(notify.NewSlackNotifier(notify.SlackConfig{WebhookURL: slackURL}))
			multiNotifier.SetRouting("#", []string{"slack"})
			slog.Info("slack notifier registered")
		}
		// Discord: SENTINEL_DISCORD_WEBHOOK_URL 環境変数で設定
		if discordURL := os.Getenv("SENTINEL_DISCORD_WEBHOOK_URL"); discordURL != "" {
			multiNotifier.Register(notify.NewDiscordNotifier(notify.DiscordConfig{WebhookURL: discordURL}))
			slog.Info("discord notifier registered")
		}
		// Gmail: SENTINEL_GMAIL_FROM + SENTINEL_GMAIL_PASSWORD 環境変数で設定
		if gmailFrom := os.Getenv("SENTINEL_GMAIL_FROM"); gmailFrom != "" {
			multiNotifier.Register(notify.NewGmailNotifier(notify.GmailConfig{
				From: gmailFrom, Password: os.Getenv("SENTINEL_GMAIL_PASSWORD"),
			}))
			multiNotifier.SetRouting("@", []string{"gmail"})
			slog.Info("gmail notifier registered")
		}

		orchOpts = append(orchOpts, response.WithNotifyFunc(func(ctx context.Context, record response.ThreatResponseRecord) error {
			n := notify.Notification{
				Channel:   record.NotifyTarget,
				Subject:   "Sentinel: " + string(record.EventName),
				Body:      "Strategy: " + string(record.Strategy),
				Severity:  threatSeverity(record),
				TraceID:   record.TraceID,
				EventName: string(record.EventName),
				Fields:    buildNotifyFields(record),
			}
			return multiNotifier.Send(ctx, n)
		}))

		orch := response.NewThreatResponseOrchestrator(respCfg, enhancedBlocker.BlockDispatcher, analyzer, orchOpts...)
		sentinel.Pipeline().SetThreatOrchestrator(orch)
		sentinel.SetBlockDispatcher(enhancedBlocker)
		slog.Info("threat response orchestrator enabled",
			"defaultStrategy", cfg.Response.DefaultStrategy,
			"blockMode", string(blockMode),
		)
	}

	// Graceful shutdown
	go func() {
		sigCh := make(chan os.Signal, 1)
		signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
		<-sigCh
		slog.Info("shutting down gracefully...")
		ctx, cancel := context.WithTimeout(context.Background(), time.Duration(cfg.Server.GracefulTimeoutSec)*time.Second)
		defer cancel()
		stopped := make(chan struct{})
		go func() { srv.GracefulStop(); close(stopped) }()
		select {
		case <-ctx.Done():
			slog.Warn("graceful shutdown timeout, forcing stop")
			srv.Stop()
		case <-stopped:
			slog.Info("graceful shutdown complete")
		}
	}()

	slog.Info("server listening", "addr", cfg.Server.Addr, "version", "0.3.0",
		"ensemble", cfg.Ensemble.Enabled,
		"anomaly", cfg.Anomaly.Enabled,
		"authz", cfg.Authorization.Enabled,
		"agent", cfg.Agent.Enabled,
		"response", cfg.Response.Enabled,
	)
	if err := srv.Serve(lis); err != nil {
		slog.Error("server error", "error", err)
		os.Exit(1)
	}
}

// --- Conversion helpers ---

func convertMaskingRules(cfgRules []config.MaskingRuleConfig) []security.MaskingRule {
	var rules []security.MaskingRule
	for _, r := range cfgRules {
		rule := security.MaskingRule{
			Type: r.Type, Replacement: r.Replacement,
			Category: r.Category, Keys: r.Keys,
		}
		if r.Pattern != "" {
			rule.Pattern = security.CompilePattern(r.Pattern)
		}
		rules = append(rules, rule)
	}
	return rules
}

func convertTaskRules(cfgRules []config.TaskRuleConfig) []domain.TaskRule {
	var rules []domain.TaskRule
	for _, r := range cfgRules {
		rules = append(rules, domain.TaskRule{
			RuleID: r.RuleID, EventName: r.EventName,
			Severity:       domain.TaskSeverity(r.Severity),
			ActionType:     domain.TaskActionType(r.ActionType),
			ExecutionLevel: domain.TaskExecutionLevel(r.ExecutionLevel),
			Priority:       domain.TaskPriority(r.Priority),
			Description:    r.Description,
			ExecParams: domain.ExecParams{
				TargetEndpoint:      r.ExecParams.TargetEndpoint,
				ScriptIdentifier:    r.ExecParams.ScriptIdentifier,
				NotificationChannel: r.ExecParams.NotificationChannel,
				PromptTemplate:      r.ExecParams.PromptTemplate,
			},
			Guardrails: domain.Guardrails{
				RequireHumanApproval: r.Guardrails.RequireHumanApproval,
				TimeoutMs:            r.Guardrails.TimeoutMs,
				MaxRetries:           r.Guardrails.MaxRetries,
			},
		})
	}
	return rules
}

func convertDynamicRules(cfgRules []config.DynamicRuleConfig) []detection.DynamicRuleConfig {
	var rules []detection.DynamicRuleConfig
	for _, r := range cfgRules {
		rules = append(rules, detection.DynamicRuleConfig{
			RuleID: r.RuleID, EventName: r.EventName,
			Priority: r.Priority, Score: r.Score,
			PayloadBuilder: r.PayloadBuilder,
			Conditions: detection.DynamicRuleConditions{
				LogTypes: r.Conditions.LogTypes, MinLevel: r.Conditions.MinLevel,
				MaxLevel: r.Conditions.MaxLevel, MessagePattern: r.Conditions.MessagePattern,
				RequireCritical: r.Conditions.RequireCritical, TagKeys: r.Conditions.TagKeys,
				Origins: r.Conditions.Origins,
			},
		})
	}
	return rules
}

func convertAggregator(s string) detection.ScoreAggregator {
	switch s {
	case "avg":
		return detection.AggregateAvg
	case "weighted_sum":
		return detection.AggregateWeightedSum
	default:
		return detection.AggregateMax
	}
}

func convertAuthzConfig(cfg config.AuthorizationConfig) middleware.AuthzConfig {
	roles := make(map[string]middleware.Role, len(cfg.Roles))
	for name, r := range cfg.Roles {
		roles[name] = middleware.Role{
			Name: name,
			Permissions: middleware.Permission{
				AllowedLogTypes: r.AllowedLogTypes, DeniedLogTypes: r.DeniedLogTypes,
				MaxLogLevel: r.MaxLogLevel,
				CanWrite: r.CanWrite, CanRead: r.CanRead,
				CanApprove: r.CanApprove, CanAdmin: r.CanAdmin,
			},
		}
	}
	return middleware.AuthzConfig{
		Enabled:     cfg.Enabled,
		DefaultRole: cfg.DefaultRole,
		Roles:       roles,
		ClientRoles: cfg.ClientRoles,
	}
}

func convertAllowedActions(actions []string) []domain.TaskActionType {
	if len(actions) == 0 {
		return []domain.TaskActionType{domain.ActionAIAnalyze}
	}
	result := make([]domain.TaskActionType, len(actions))
	for i, a := range actions {
		result[i] = domain.TaskActionType(a)
	}
	return result
}

func convertResponseRules(cfgRules []config.ResponseRuleConfig) []response.ResponseRuleConfig {
	var rules []response.ResponseRuleConfig
	for _, r := range cfgRules {
		rules = append(rules, response.ResponseRuleConfig{
			EventName:      r.EventName,
			Strategy:       response.ResponseStrategy(r.Strategy),
			BlockAction:    r.BlockAction,
			AnalysisPrompt: r.AnalysisPrompt,
			NotifyTargets:  r.NotifyTargets,
			MinPriority:    r.MinPriority,
		})
	}
	return rules
}

func convertMaskingPolicies(cfgPolicies []config.MaskingPolicyRuleConfig) []security.MaskingPolicyRule {
	var policies []security.MaskingPolicyRule
	for _, p := range cfgPolicies {
		var logTypes []domain.LogType
		for _, lt := range p.LogTypes {
			logTypes = append(logTypes, domain.LogType(lt))
		}
		var origins []domain.Origin
		for _, o := range p.Origins {
			origins = append(origins, domain.Origin(o))
		}
		policies = append(policies, security.MaskingPolicyRule{
			PolicyID: p.PolicyID,
			Condition: security.MaskingPolicyCondition{
				LogTypes: logTypes,
				Origins:  origins,
				MinLevel: domain.LogLevel(p.MinLevel),
				MaxLevel: domain.LogLevel(p.MaxLevel),
			},
			MaskingRules:  convertMaskingRules(p.MaskingRules),
			PreserveExtra: p.PreserveExtra,
		})
	}
	return policies
}

func convertRoutingRules(cfgRules []config.ApprovalRoutingRuleConfig) []domain.ApprovalRoutingRule {
	var rules []domain.ApprovalRoutingRule
	for _, r := range cfgRules {
		var chain []domain.ApprovalChainStep
		for _, s := range r.Chain {
			chain = append(chain, domain.ApprovalChainStep{
				StepOrder: s.StepOrder,
				Role:      s.Role,
				Required:  s.Required,
			})
		}
		rules = append(rules, domain.ApprovalRoutingRule{
			RuleID:    r.RuleID,
			MinLevel:  domain.LogLevel(r.MinLevel),
			MaxLevel:  domain.LogLevel(r.MaxLevel),
			EventName: r.EventName,
			Chain:     chain,
		})
	}
	return rules
}

func threatSeverity(record response.ThreatResponseRecord) string {
	if record.Block != nil && record.Block.Success {
		return "critical"
	}
	if record.Analysis != nil && record.Analysis.RiskLevel != "" {
		return record.Analysis.RiskLevel
	}
	return "medium"
}

func buildNotifyFields(record response.ThreatResponseRecord) map[string]string {
	fields := map[string]string{
		"response_id": record.ResponseID,
		"strategy":    string(record.Strategy),
	}
	if record.Target.IP != "" {
		fields["target_ip"] = record.Target.IP
	}
	if record.Target.UserID != "" {
		fields["target_user"] = record.Target.UserID
	}
	if record.Block != nil {
		fields["block_action"] = record.Block.ActionType
		if record.Block.Success {
			fields["block_status"] = "blocked"
		} else {
			fields["block_status"] = "failed: " + record.Block.Error
		}
	}
	if record.Analysis != nil && record.Analysis.Error == "" {
		fields["risk_level"] = record.Analysis.RiskLevel
		fields["analysis"] = record.Analysis.Summary
	}
	return fields
}
