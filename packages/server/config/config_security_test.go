package config

import (
	"os"
	"strings"
	"testing"
)

// ===== Config injection attacks =====

func TestLoad_Security_YAMLSpecialChars(t *testing.T) {
	// YAML values with special characters should be treated as strings
	path := writeYAML(t, `
security:
  hmac_key: "12345678901234567890123456789012"
  enable_hash_chain: true
pipeline:
  service_id: "test: with: colons: and {braces}"
`)
	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	if cfg.Pipeline.ServiceID != "test: with: colons: and {braces}" {
		t.Errorf("unexpected service_id: %s", cfg.Pipeline.ServiceID)
	}
}

func TestLoad_Security_LargeYAML(t *testing.T) {
	// Very large config should not cause OOM
	var sb strings.Builder
	sb.WriteString(`
security:
  hmac_key: "12345678901234567890123456789012"
  enable_hash_chain: true
pipeline:
  service_id: test
  rules:
`)
	for i := 0; i < 1000; i++ {
		sb.WriteString("    - rule_id: rule-" + strings.Repeat("x", 100) + "\n")
		sb.WriteString("      event_name: SYSTEM_CRITICAL_FAILURE\n")
		sb.WriteString("      severity: HIGH\n")
		sb.WriteString("      action_type: SYSTEM_NOTIFICATION\n")
		sb.WriteString("      execution_level: AUTO\n")
		sb.WriteString("      priority: 1\n")
		sb.WriteString("      description: test\n")
	}

	path := writeYAML(t, sb.String())
	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("expected no error for large config, got %v", err)
	}
	if len(cfg.Pipeline.Rules) != 1000 {
		t.Errorf("expected 1000 rules, got %d", len(cfg.Pipeline.Rules))
	}
}

func TestLoad_Security_EnvVarOverrideHMACKey(t *testing.T) {
	// Env var should be able to set HMAC key
	path := writeYAML(t, `
security:
  hmac_key: "short"
  enable_hash_chain: true
pipeline:
  service_id: test
`)
	// Without env override, should fail (key too short)
	_, err := Load(path)
	if err == nil {
		t.Fatal("expected error for short HMAC key")
	}

	// With env override of sufficient length
	os.Setenv("SENTINEL_HMAC_KEY", "12345678901234567890123456789012")
	defer os.Unsetenv("SENTINEL_HMAC_KEY")

	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("expected no error with env override, got %v", err)
	}
	if cfg.Security.HMACKey != "12345678901234567890123456789012" {
		t.Error("env override not applied")
	}
}

func TestLoad_Security_EnvVarWithNullBytes(t *testing.T) {
	path := writeYAML(t, `
security:
  hmac_key: "12345678901234567890123456789012"
  enable_hash_chain: true
pipeline:
  service_id: test
`)
	// Env var with null bytes — Go os.Setenv silently truncates at null byte
	os.Setenv("SENTINEL_ADDR", "0.0.0.0:50051\x00injected")
	defer os.Unsetenv("SENTINEL_ADDR")

	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	// Go handles this safely — the string is truncated or contains the null byte
	// Either way, it should not crash
	_ = cfg
}

func TestLoad_Security_EmptyFile(t *testing.T) {
	path := writeYAML(t, "")
	_, err := Load(path)
	// Empty YAML produces zero-value config, should fail on required fields
	if err == nil {
		t.Fatal("expected error for empty config file")
	}
}

func TestLoad_Security_NullValues(t *testing.T) {
	path := writeYAML(t, `
security:
  hmac_key: "12345678901234567890123456789012"
  enable_hash_chain: true
pipeline:
  service_id: ~
`)
	_, err := Load(path)
	// service_id: ~ (null) should fail validation
	if err == nil {
		t.Fatal("expected error for null service_id")
	}
}

func TestLoad_Security_BoolAsString(t *testing.T) {
	path := writeYAML(t, `
security:
  hmac_key: "12345678901234567890123456789012"
  enable_hash_chain: "yes"
pipeline:
  service_id: test
`)
	// YAML "yes" is parsed as true for bool fields
	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !cfg.Security.EnableHashChain {
		t.Error("expected enable_hash_chain=true from YAML 'yes'")
	}
}
