package config

import (
	"os"
	"path/filepath"
	"testing"
)

func writeTestConfig(t *testing.T, content string) string {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "config.yaml")
	os.WriteFile(path, []byte(content), 0644)
	return path
}

func TestLoad_MinimalConfig(t *testing.T) {
	path := writeTestConfig(t, `
pipeline:
  service_id: "test-svc"
`)
	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("error: %v", err)
	}
	if cfg.Pipeline.ServiceID != "test-svc" {
		t.Errorf("expected test-svc, got %s", cfg.Pipeline.ServiceID)
	}
}

func TestLoad_Defaults(t *testing.T) {
	path := writeTestConfig(t, `
pipeline:
  service_id: "test"
`)
	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("error: %v", err)
	}

	// Server defaults
	if cfg.Server.Addr != ":50051" {
		t.Errorf("expected :50051, got %s", cfg.Server.Addr)
	}
	if cfg.Server.MaxRecvMsgSizeBytes != 1048576 {
		t.Errorf("expected 1048576, got %d", cfg.Server.MaxRecvMsgSizeBytes)
	}
	if cfg.Server.MaxConcurrentStreams != 1000 {
		t.Errorf("expected 1000, got %d", cfg.Server.MaxConcurrentStreams)
	}
	if cfg.Server.GracefulTimeoutSec != 30 {
		t.Errorf("expected 30, got %d", cfg.Server.GracefulTimeoutSec)
	}

	// Store defaults
	if cfg.Store.Driver != "sqlite" {
		t.Errorf("expected sqlite, got %s", cfg.Store.Driver)
	}

	// Agent defaults
	if cfg.Agent.MaxLoopDepth != 5 {
		t.Errorf("expected 5, got %d", cfg.Agent.MaxLoopDepth)
	}
	if cfg.Agent.TimeoutSec != 60 {
		t.Errorf("expected 60, got %d", cfg.Agent.TimeoutSec)
	}
	if cfg.Agent.Provider != "mock" {
		t.Errorf("expected mock, got %s", cfg.Agent.Provider)
	}

	// Ensemble defaults
	if cfg.Ensemble.Threshold != 0.5 {
		t.Errorf("expected 0.5, got %f", cfg.Ensemble.Threshold)
	}

	// Authorization defaults
	if cfg.Authorization.DefaultRole != "viewer" {
		t.Errorf("expected viewer, got %s", cfg.Authorization.DefaultRole)
	}

	// Anomaly defaults
	if cfg.Anomaly.WindowSizeSec != 60 {
		t.Errorf("expected 60, got %d", cfg.Anomaly.WindowSizeSec)
	}
	if cfg.Anomaly.BaselineWindowSec != 600 {
		t.Errorf("expected 600, got %d", cfg.Anomaly.BaselineWindowSec)
	}
	if cfg.Anomaly.ThresholdPct != 300.0 {
		t.Errorf("expected 300, got %f", cfg.Anomaly.ThresholdPct)
	}
	if cfg.Anomaly.MinBaseline != 3.0 {
		t.Errorf("expected 3, got %f", cfg.Anomaly.MinBaseline)
	}

	// Response defaults
	if cfg.Response.DefaultStrategy != "NOTIFY_ONLY" {
		t.Errorf("expected NOTIFY_ONLY, got %s", cfg.Response.DefaultStrategy)
	}
}

func TestLoad_Validation_MissingServiceID(t *testing.T) {
	path := writeTestConfig(t, `
server:
  addr: ":8080"
`)
	_, err := Load(path)
	if err == nil {
		t.Error("expected error for missing service_id")
	}
}

func TestLoad_Validation_HMACKeyTooShort(t *testing.T) {
	path := writeTestConfig(t, `
pipeline:
  service_id: "test"
security:
  enable_hash_chain: true
  hmac_key: "short"
`)
	_, err := Load(path)
	if err == nil {
		t.Error("expected error for short HMAC key")
	}
}

func TestLoad_Validation_AuthWithoutKeys(t *testing.T) {
	path := writeTestConfig(t, `
pipeline:
  service_id: "test"
auth:
  enabled: true
`)
	_, err := Load(path)
	if err == nil {
		t.Error("expected error for auth without keys")
	}
}

func TestLoad_EnvOverrides(t *testing.T) {
	path := writeTestConfig(t, `
pipeline:
  service_id: "test"
`)

	t.Run("SENTINEL_ADDR", func(t *testing.T) {
		t.Setenv("SENTINEL_ADDR", ":9999")
		cfg, _ := Load(path)
		if cfg.Server.Addr != ":9999" {
			t.Errorf("expected :9999, got %s", cfg.Server.Addr)
		}
	})

	t.Run("SENTINEL_AGENT_ENABLED", func(t *testing.T) {
		t.Setenv("SENTINEL_AGENT_ENABLED", "true")
		cfg, _ := Load(path)
		if !cfg.Agent.Enabled {
			t.Error("expected agent enabled")
		}
	})

	t.Run("SENTINEL_AGENT_PROVIDER", func(t *testing.T) {
		t.Setenv("SENTINEL_AGENT_PROVIDER", "anthropic")
		cfg, _ := Load(path)
		if cfg.Agent.Provider != "anthropic" {
			t.Errorf("expected anthropic, got %s", cfg.Agent.Provider)
		}
	})

	t.Run("SENTINEL_ENSEMBLE_ENABLED", func(t *testing.T) {
		t.Setenv("SENTINEL_ENSEMBLE_ENABLED", "1")
		cfg, _ := Load(path)
		if !cfg.Ensemble.Enabled {
			t.Error("expected ensemble enabled")
		}
	})

	t.Run("SENTINEL_AUTHZ_ENABLED", func(t *testing.T) {
		t.Setenv("SENTINEL_AUTHZ_ENABLED", "true")
		cfg, _ := Load(path)
		if !cfg.Authorization.Enabled {
			t.Error("expected authz enabled")
		}
	})

	t.Run("SENTINEL_ANOMALY_ENABLED", func(t *testing.T) {
		t.Setenv("SENTINEL_ANOMALY_ENABLED", "1")
		cfg, _ := Load(path)
		if !cfg.Anomaly.Enabled {
			t.Error("expected anomaly enabled")
		}
	})

	t.Run("SENTINEL_RESPONSE_ENABLED", func(t *testing.T) {
		t.Setenv("SENTINEL_RESPONSE_ENABLED", "true")
		cfg, _ := Load(path)
		if !cfg.Response.Enabled {
			t.Error("expected response enabled")
		}
	})

	t.Run("SENTINEL_RESPONSE_DEFAULT_STRATEGY", func(t *testing.T) {
		t.Setenv("SENTINEL_RESPONSE_DEFAULT_STRATEGY", "BLOCK_AND_NOTIFY")
		cfg, _ := Load(path)
		if cfg.Response.DefaultStrategy != "BLOCK_AND_NOTIFY" {
			t.Errorf("expected BLOCK_AND_NOTIFY, got %s", cfg.Response.DefaultStrategy)
		}
	})
}

func TestLoad_FullConfig(t *testing.T) {
	path := writeTestConfig(t, `
pipeline:
  service_id: "sentinel-prod"
  rules:
    - rule_id: "sec-001"
      event_name: "SECURITY_INTRUSION_DETECTED"
      severity: "CRITICAL"
      action_type: "AI_ANALYZE"
      execution_level: "AUTO"
      priority: 1
      description: "Analyze security intrusion"
security:
  enable_masking: true
  enable_hash_chain: true
  hmac_key: "a-very-long-hmac-key-that-is-at-least-32-bytes"
agent:
  enabled: true
  provider: "anthropic"
  max_loop_depth: 3
  timeout_sec: 30
  allowed_actions: ["AI_ANALYZE"]
  min_severity: "HIGH"
ensemble:
  enabled: true
  aggregator: "max"
  threshold: 0.7
  dedup_window_sec: 10
anomaly:
  enabled: true
  window_size_sec: 120
  baseline_window_sec: 1200
  threshold_pct: 400.0
  min_baseline: 5.0
authorization:
  enabled: true
  default_role: "writer"
  roles:
    admin:
      can_write: true
      can_read: true
      can_approve: true
      can_admin: true
  client_roles:
    client-1: "admin"
response:
  enabled: true
  default_strategy: "BLOCK_AND_NOTIFY"
  rules:
    - event_name: "SECURITY_INTRUSION_DETECTED"
      strategy: "BLOCK_AND_NOTIFY"
      block_action: "block_ip"
      notify_targets: ["#security"]
webhook:
  enabled: true
  url: "https://hooks.example.com/sentinel"
  timeout_sec: 15
  secret: "webhook-secret"
`)

	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("error: %v", err)
	}

	if cfg.Pipeline.ServiceID != "sentinel-prod" {
		t.Error("wrong service_id")
	}
	if len(cfg.Pipeline.Rules) != 1 {
		t.Error("expected 1 pipeline rule")
	}
	if !cfg.Agent.Enabled {
		t.Error("agent should be enabled")
	}
	if cfg.Agent.Provider != "anthropic" {
		t.Error("wrong provider")
	}
	if cfg.Agent.MaxLoopDepth != 3 {
		t.Error("wrong max_loop_depth")
	}
	if !cfg.Ensemble.Enabled {
		t.Error("ensemble should be enabled")
	}
	if cfg.Ensemble.Threshold != 0.7 {
		t.Error("wrong threshold")
	}
	if !cfg.Anomaly.Enabled {
		t.Error("anomaly should be enabled")
	}
	if cfg.Anomaly.WindowSizeSec != 120 {
		t.Error("wrong window_size_sec")
	}
	if !cfg.Authorization.Enabled {
		t.Error("authz should be enabled")
	}
	if cfg.Authorization.DefaultRole != "writer" {
		t.Error("wrong default_role")
	}
	if !cfg.Response.Enabled {
		t.Error("response should be enabled")
	}
	if cfg.Response.DefaultStrategy != "BLOCK_AND_NOTIFY" {
		t.Error("wrong strategy")
	}
	if len(cfg.Response.Rules) != 1 {
		t.Error("expected 1 response rule")
	}
}

func TestLoad_InvalidYAML(t *testing.T) {
	path := writeTestConfig(t, `
invalid: yaml: [broken
`)
	_, err := Load(path)
	if err == nil {
		t.Error("expected error for invalid YAML")
	}
}

func TestLoad_FileNotFound(t *testing.T) {
	_, err := Load("/nonexistent/path/config.yaml")
	if err == nil {
		t.Error("expected error for missing file")
	}
}
