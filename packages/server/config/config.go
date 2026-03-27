package config

import (
	"fmt"
	"os"
	"strings"

	"gopkg.in/yaml.v3"
)

type Config struct {
	Server   ServerConfig   `yaml:"server"`
	Security SecurityConfig `yaml:"security"`
	Pipeline PipelineConfig `yaml:"pipeline"`
	Store    StoreConfig    `yaml:"store"`
	Auth     AuthConfig     `yaml:"auth"`
	Webhook  WebhookConfig  `yaml:"webhook"`
}

type ServerConfig struct {
	Addr                 string `yaml:"addr"`
	MaxRecvMsgSizeBytes  int    `yaml:"max_recv_msg_size_bytes"`
	MaxConcurrentStreams uint32 `yaml:"max_concurrent_streams"`
	GracefulTimeoutSec   int    `yaml:"graceful_timeout_sec"`
}

type SecurityConfig struct {
	HMACKey           string   `yaml:"hmac_key"`
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
