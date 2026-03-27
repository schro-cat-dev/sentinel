package config

import (
	"fmt"
	"os"
	"strings"

	"gopkg.in/yaml.v3"
)

type Config struct {
	Server        ServerConfig        `yaml:"server"`
	Security      SecurityConfig      `yaml:"security"`
	Pipeline      PipelineConfig      `yaml:"pipeline"`
	Store         StoreConfig         `yaml:"store"`
	Auth          AuthConfig          `yaml:"auth"`
	Webhook       WebhookConfig       `yaml:"webhook"`
	Agent         AgentConfig            `yaml:"agent"`
	Ensemble      EnsembleConfig         `yaml:"ensemble"`
	Authorization AuthorizationConfig    `yaml:"authorization"`
	Anomaly       AnomalyDetectionConfig `yaml:"anomaly"`
	Response        ResponseConfig              `yaml:"response"`
	MaskingPolicies []MaskingPolicyRuleConfig   `yaml:"masking_policies"`
	RoutingRules    []ApprovalRoutingRuleConfig `yaml:"routing_rules"`
}

type ServerConfig struct {
	Addr                 string `yaml:"addr"`
	MaxRecvMsgSizeBytes  int    `yaml:"max_recv_msg_size_bytes"`
	MaxConcurrentStreams uint32 `yaml:"max_concurrent_streams"`
	GracefulTimeoutSec   int    `yaml:"graceful_timeout_sec"`
}

type SecurityConfig struct {
	HMACKey           string   `yaml:"hmac_key"`
	HMACKeyVersion    int      `yaml:"hmac_key_version"` // キーバージョン（ローテーション用、デフォルト1）
	EnableMasking     bool     `yaml:"enable_masking"`
	EnableHashChain   bool     `yaml:"enable_hash_chain"`
	PreserveFields    []string `yaml:"preserve_fields"`
	MaskingDepthLimit int      `yaml:"masking_depth_limit"`
	MaskingRules      []MaskingRuleConfig `yaml:"masking_rules"`
}

type MaskingRuleConfig struct {
	Type        string   `yaml:"type"`
	Pattern     string   `yaml:"pattern"`
	Replacement string   `yaml:"replacement"`
	Category    string   `yaml:"category"`
	Keys        []string `yaml:"keys"`
}

type PipelineConfig struct {
	ServiceID string           `yaml:"service_id"`
	Rules     []TaskRuleConfig `yaml:"rules"`
}

type TaskRuleConfig struct {
	RuleID         string         `yaml:"rule_id"`
	EventName      string         `yaml:"event_name"`
	Severity       string         `yaml:"severity"`
	ActionType     string         `yaml:"action_type"`
	ExecutionLevel string         `yaml:"execution_level"`
	Priority       int            `yaml:"priority"`
	Description    string         `yaml:"description"`
	ExecParams     ExecParamsConfig `yaml:"exec_params"`
	Guardrails     GuardrailsConfig `yaml:"guardrails"`
}

type ExecParamsConfig struct {
	TargetEndpoint      string `yaml:"target_endpoint"`
	ScriptIdentifier    string `yaml:"script_identifier"`
	NotificationChannel string `yaml:"notification_channel"`
	PromptTemplate      string `yaml:"prompt_template"`
}

type GuardrailsConfig struct {
	RequireHumanApproval bool `yaml:"require_human_approval"`
	TimeoutMs            int  `yaml:"timeout_ms"`
	MaxRetries           int  `yaml:"max_retries"`
}

type StoreConfig struct {
	Driver string `yaml:"driver"`
	DSN    string `yaml:"dsn"`
}

type AuthConfig struct {
	Enabled        bool    `yaml:"enabled"`
	APIKeys        []string `yaml:"api_keys"`
	RateLimitRPS   float64 `yaml:"rate_limit_rps"`
	RateLimitBurst int     `yaml:"rate_limit_burst"`
}

type WebhookConfig struct {
	Enabled    bool   `yaml:"enabled"`
	URL        string `yaml:"url"`
	TimeoutSec int    `yaml:"timeout_sec"`
	Secret     string `yaml:"secret"`
}

// AgentConfig はAIエージェント設定
type AgentConfig struct {
	Enabled        bool     `yaml:"enabled"`
	Provider       string   `yaml:"provider"`         // "mock", "anthropic", "openai"
	MaxLoopDepth   int      `yaml:"max_loop_depth"`
	TimeoutSec     int      `yaml:"timeout_sec"`
	AllowedActions []string `yaml:"allowed_actions"`   // "AI_ANALYZE", "AUTOMATED_REMEDIATE"
	MinSeverity    string   `yaml:"min_severity"`      // "LOW", "MEDIUM", "HIGH", "CRITICAL"
}

// EnsembleConfig はアンサンブル検知設定
type EnsembleConfig struct {
	Enabled        bool                   `yaml:"enabled"`
	Aggregator     string                 `yaml:"aggregator"`       // "max", "avg", "weighted_sum"
	Threshold      float64                `yaml:"threshold"`        // 0.0〜1.0
	DedupWindowSec int                    `yaml:"dedup_window_sec"` // 0=無効
	DynamicRules   []DynamicRuleConfig    `yaml:"dynamic_rules"`
}

// DynamicRuleConfig は動的検知ルールの設定
type DynamicRuleConfig struct {
	RuleID         string                 `yaml:"rule_id"`
	EventName      string                 `yaml:"event_name"`
	Priority       string                 `yaml:"priority"`
	Score          float64                `yaml:"score"`
	PayloadBuilder string                 `yaml:"payload_builder"`
	Conditions     DynamicRuleConditions  `yaml:"conditions"`
}

// DynamicRuleConditions は動的ルールの発火条件
type DynamicRuleConditions struct {
	LogTypes       []string `yaml:"log_types"`
	MinLevel       int      `yaml:"min_level"`
	MaxLevel       int      `yaml:"max_level"`
	MessagePattern string   `yaml:"message_pattern"`
	RequireCritical *bool   `yaml:"require_critical"`
	TagKeys        []string `yaml:"tag_keys"`
	Origins        []string `yaml:"origins"`
}

// AuthorizationConfig はRBAC認可設定
type AuthorizationConfig struct {
	Enabled     bool                      `yaml:"enabled"`
	DefaultRole string                    `yaml:"default_role"`
	Roles       map[string]RoleConfig     `yaml:"roles"`
	ClientRoles map[string]string         `yaml:"client_roles"`
}

// RoleConfig はロール設定
type RoleConfig struct {
	AllowedLogTypes []string `yaml:"allowed_log_types"`
	DeniedLogTypes  []string `yaml:"denied_log_types"`
	MaxLogLevel     int      `yaml:"max_log_level"`
	CanWrite        bool     `yaml:"can_write"`
	CanRead         bool     `yaml:"can_read"`
	CanApprove      bool     `yaml:"can_approve"`
	CanAdmin        bool     `yaml:"can_admin"`
}

// AnomalyDetectionConfig は異常検知設定
type AnomalyDetectionConfig struct {
	Enabled        bool    `yaml:"enabled"`
	WindowSizeSec  int     `yaml:"window_size_sec"`
	BaselineWindowSec int  `yaml:"baseline_window_sec"`
	ThresholdPct   float64 `yaml:"threshold_pct"`
	MinBaseline    float64 `yaml:"min_baseline"`
}

// MaskingPolicyConfig はマスクポリシー設定
type MaskingPolicyConfig struct {
	Enabled            bool `yaml:"enabled"`
	EnableVerification bool `yaml:"enable_verification"`
}

// ResponseConfig は脅威レスポンス設定
type ResponseConfig struct {
	Enabled         bool                 `yaml:"enabled"`
	DefaultStrategy string               `yaml:"default_strategy"`
	BlockMode       string               `yaml:"block_mode"` // "IMMEDIATE" or "REQUIRE_APPROVAL" (default: IMMEDIATE)
	Rules           []ResponseRuleConfig `yaml:"rules"`
}

// MaskingPolicyRuleConfig はマスクポリシールールの設定
type MaskingPolicyRuleConfig struct {
	PolicyID      string   `yaml:"policy_id"`
	LogTypes      []string `yaml:"log_types"`
	Origins       []string `yaml:"origins"`
	MinLevel      int      `yaml:"min_level"`
	MaxLevel      int      `yaml:"max_level"`
	MaskingRules  []MaskingRuleConfig `yaml:"masking_rules"`
	PreserveExtra []string `yaml:"preserve_extra"`
}

// ApprovalRoutingRuleConfig は承認ルーティングルールの設定
type ApprovalRoutingRuleConfig struct {
	RuleID    string                      `yaml:"rule_id"`
	MinLevel  int                         `yaml:"min_level"`
	MaxLevel  int                         `yaml:"max_level"`
	EventName string                      `yaml:"event_name"`
	Chain     []ApprovalChainStepConfig   `yaml:"chain"`
}

// ApprovalChainStepConfig は承認チェーンステップの設定
type ApprovalChainStepConfig struct {
	StepOrder int    `yaml:"step_order"`
	Role      string `yaml:"role"`
	Required  bool   `yaml:"required"`
}

// ResponseRuleConfig はレスポンスルール設定
type ResponseRuleConfig struct {
	EventName      string   `yaml:"event_name"`
	Strategy       string   `yaml:"strategy"`
	BlockAction    string   `yaml:"block_action"`
	AnalysisPrompt string   `yaml:"analysis_prompt"`
	NotifyTargets  []string `yaml:"notify_targets"`
	MinPriority    string   `yaml:"min_priority"`
}

// Load はYAMLファイルから設定を読み込み、環境変数でオーバーライドする
func Load(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read config: %w", err)
	}

	cfg := &Config{}
	if err := yaml.Unmarshal(data, cfg); err != nil {
		return nil, fmt.Errorf("parse config: %w", err)
	}

	applyEnvOverrides(cfg)
	applyDefaults(cfg)

	if err := validate(cfg); err != nil {
		return nil, fmt.Errorf("validate config: %w", err)
	}

	return cfg, nil
}

func applyEnvOverrides(cfg *Config) {
	if key := os.Getenv("SENTINEL_HMAC_KEY"); key != "" {
		cfg.Security.HMACKey = key
	}
	if addr := os.Getenv("SENTINEL_ADDR"); addr != "" {
		cfg.Server.Addr = addr
	}
	if keys := os.Getenv("SENTINEL_API_KEYS"); keys != "" {
		cfg.Auth.APIKeys = strings.Split(keys, ",")
	}
	// Agent overrides
	if v := os.Getenv("SENTINEL_AGENT_ENABLED"); v == "true" || v == "1" {
		cfg.Agent.Enabled = true
	}
	if v := os.Getenv("SENTINEL_AGENT_PROVIDER"); v != "" {
		cfg.Agent.Provider = v
	}
	// Ensemble overrides
	if v := os.Getenv("SENTINEL_ENSEMBLE_ENABLED"); v == "true" || v == "1" {
		cfg.Ensemble.Enabled = true
	}
	// Authorization overrides
	if v := os.Getenv("SENTINEL_AUTHZ_ENABLED"); v == "true" || v == "1" {
		cfg.Authorization.Enabled = true
	}
	// Anomaly overrides
	if v := os.Getenv("SENTINEL_ANOMALY_ENABLED"); v == "true" || v == "1" {
		cfg.Anomaly.Enabled = true
	}
	// Response overrides
	if v := os.Getenv("SENTINEL_RESPONSE_ENABLED"); v == "true" || v == "1" {
		cfg.Response.Enabled = true
	}
	if v := os.Getenv("SENTINEL_RESPONSE_DEFAULT_STRATEGY"); v != "" {
		cfg.Response.DefaultStrategy = v
	}
}

func applyDefaults(cfg *Config) {
	if cfg.Server.Addr == "" {
		cfg.Server.Addr = ":50051"
	}
	if cfg.Server.MaxRecvMsgSizeBytes == 0 {
		cfg.Server.MaxRecvMsgSizeBytes = 1024 * 1024
	}
	if cfg.Server.MaxConcurrentStreams == 0 {
		cfg.Server.MaxConcurrentStreams = 1000
	}
	if cfg.Server.GracefulTimeoutSec == 0 {
		cfg.Server.GracefulTimeoutSec = 30
	}
	if cfg.Security.MaskingDepthLimit == 0 {
		cfg.Security.MaskingDepthLimit = 32
	}
	if cfg.Store.Driver == "" {
		cfg.Store.Driver = "sqlite"
	}
	if cfg.Store.DSN == "" {
		cfg.Store.DSN = "file:sentinel.db?_journal=WAL"
	}
	if cfg.Auth.RateLimitRPS == 0 {
		cfg.Auth.RateLimitRPS = 100
	}
	if cfg.Auth.RateLimitBurst == 0 {
		cfg.Auth.RateLimitBurst = 200
	}
	if cfg.Webhook.TimeoutSec == 0 {
		cfg.Webhook.TimeoutSec = 10
	}
	// Agent defaults
	if cfg.Agent.MaxLoopDepth == 0 {
		cfg.Agent.MaxLoopDepth = 5
	}
	if cfg.Agent.TimeoutSec == 0 {
		cfg.Agent.TimeoutSec = 60
	}
	if cfg.Agent.Provider == "" {
		cfg.Agent.Provider = "mock"
	}
	// Ensemble defaults
	if cfg.Ensemble.Threshold == 0 {
		cfg.Ensemble.Threshold = 0.5
	}
	// Authorization defaults
	if cfg.Authorization.DefaultRole == "" {
		cfg.Authorization.DefaultRole = "viewer"
	}
	// Anomaly defaults
	if cfg.Anomaly.WindowSizeSec == 0 {
		cfg.Anomaly.WindowSizeSec = 60
	}
	if cfg.Anomaly.BaselineWindowSec == 0 {
		cfg.Anomaly.BaselineWindowSec = 600
	}
	if cfg.Anomaly.ThresholdPct == 0 {
		cfg.Anomaly.ThresholdPct = 300.0
	}
	if cfg.Anomaly.MinBaseline == 0 {
		cfg.Anomaly.MinBaseline = 3.0
	}
	// Response defaults
	if cfg.Response.DefaultStrategy == "" {
		cfg.Response.DefaultStrategy = "NOTIFY_ONLY"
	}
}

func validate(cfg *Config) error {
	if cfg.Security.EnableHashChain && len(cfg.Security.HMACKey) < 32 {
		return fmt.Errorf("security.hmac_key must be at least 32 bytes when hash chain is enabled (set SENTINEL_HMAC_KEY)")
	}
	if cfg.Pipeline.ServiceID == "" {
		return fmt.Errorf("pipeline.service_id is required")
	}
	if cfg.Auth.Enabled && len(cfg.Auth.APIKeys) == 0 {
		return fmt.Errorf("auth.api_keys must not be empty when auth is enabled (set SENTINEL_API_KEYS)")
	}
	return nil
}
