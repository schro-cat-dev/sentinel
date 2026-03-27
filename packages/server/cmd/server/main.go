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
	"github.com/schro-cat-dev/sentinel-server/internal/domain"
	"github.com/schro-cat-dev/sentinel-server/internal/engine"
	sentinelgrpc "github.com/schro-cat-dev/sentinel-server/internal/grpc"
	"github.com/schro-cat-dev/sentinel-server/internal/security"
	"github.com/schro-cat-dev/sentinel-server/internal/store"
	"github.com/schro-cat-dev/sentinel-server/internal/task"
	"github.com/schro-cat-dev/sentinel-server/internal/webhook"

	ggrpc "google.golang.org/grpc"
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

	// Store
	st, err := store.NewSQLiteStore(cfg.Store.DSN)
	if err != nil {
		slog.Error("failed to init store", "error", err)
		os.Exit(1)
	}
	defer st.Close()

	// Webhook notifier
	var notifier *webhook.Notifier
	if cfg.Webhook.Enabled && cfg.Webhook.URL != "" {
		notifier = webhook.NewNotifier(cfg.Webhook.URL, cfg.Webhook.TimeoutSec, cfg.Webhook.Secret)
	}

	// Pipeline config
	pipeCfg := engine.PipelineConfig{
		ServiceID:       cfg.Pipeline.ServiceID,
		EnableHashChain: cfg.Security.EnableHashChain,
		EnableMasking:   cfg.Security.EnableMasking,
		HMACKey:         []byte(cfg.Security.HMACKey),
		PreserveFields:  cfg.Security.PreserveFields,
		MaskingRules:    convertMaskingRules(cfg.Security.MaskingRules),
		TaskRules:       convertTaskRules(cfg.Pipeline.Rules),
	}

	// Executor
	executor := task.NewTaskExecutor(func(t domain.GeneratedTask) error {
		slog.Info("task dispatched", "taskId", t.TaskID, "ruleId", t.RuleID, "action", string(t.ActionType), "severity", string(t.Severity))
		return nil
	})

	// gRPC interceptors
	var opts []ggrpc.ServerOption
	if cfg.Auth.Enabled {
		keyMap := make(map[string]bool, len(cfg.Auth.APIKeys))
		for _, k := range cfg.Auth.APIKeys {
			keyMap[k] = true
		}
		opts = append(opts,
			ggrpc.ChainUnaryInterceptor(
				sentinelgrpc.AuthUnaryInterceptor(keyMap),
				sentinelgrpc.RateLimitUnaryInterceptor(cfg.Auth.RateLimitRPS, cfg.Auth.RateLimitBurst),
			),
		)
	}

	srv, lis, err := sentinelgrpc.StartServer(cfg.Server.Addr, pipeCfg, executor, st, notifier, opts...)
	if err != nil {
		slog.Error("failed to start server", "error", err)
		os.Exit(1)
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

	slog.Info("server listening", "addr", cfg.Server.Addr, "version", "0.2.0")
	if err := srv.Serve(lis); err != nil {
		slog.Error("server error", "error", err)
		os.Exit(1)
	}
}

func convertMaskingRules(cfgRules []config.MaskingRuleConfig) []security.MaskingRule {
	var rules []security.MaskingRule
	for _, r := range cfgRules {
		rule := security.MaskingRule{
			Type:        r.Type,
			Replacement: r.Replacement,
			Category:    r.Category,
			Keys:        r.Keys,
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
			RuleID:         r.RuleID,
			EventName:      r.EventName,
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
