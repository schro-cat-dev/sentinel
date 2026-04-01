package config

import (
	"os"
	"path/filepath"
	"testing"
)

func writeYAML(t *testing.T, content string) string {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "sentinel.yaml")
	if err := os.WriteFile(path, []byte(content), 0644); err != nil {
		t.Fatal(err)
	}
	return path
}

// --- detection_rules validation ---

func TestLoad_DetectionRules_Valid(t *testing.T) {
	path := writeYAML(t, `
security:
  hmac_key: "12345678901234567890123456789012"
  enable_hash_chain: true
pipeline:
  service_id: test-svc
detection_rules:
  - rule_id: brute-force
    event_name: SECURITY_INTRUSION_DETECTED
    priority: HIGH
    conditions:
      log_types: [SECURITY]
      min_level: 4
      message_pattern: "brute.*force"
`)
	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	if len(cfg.DetectionRules) != 1 {
		t.Fatalf("expected 1 detection rule, got %d", len(cfg.DetectionRules))
	}
	if cfg.DetectionRules[0].EventName != "SECURITY_INTRUSION_DETECTED" {
		t.Errorf("expected SECURITY_INTRUSION_DETECTED, got %s", cfg.DetectionRules[0].EventName)
	}
}

func TestLoad_DetectionRules_InvalidEventName(t *testing.T) {
	path := writeYAML(t, `
security:
  hmac_key: "12345678901234567890123456789012"
  enable_hash_chain: true
pipeline:
  service_id: test-svc
detection_rules:
  - rule_id: bad
    event_name: INVALID_EVENT
    priority: HIGH
`)
	_, err := Load(path)
	if err == nil {
		t.Fatal("expected validation error for invalid event_name")
	}
}

func TestLoad_DetectionRules_InvalidPriority(t *testing.T) {
	path := writeYAML(t, `
security:
  hmac_key: "12345678901234567890123456789012"
  enable_hash_chain: true
pipeline:
  service_id: test-svc
detection_rules:
  - rule_id: bad
    event_name: SECURITY_INTRUSION_DETECTED
    priority: CRITICAL
`)
	_, err := Load(path)
	if err == nil {
		t.Fatal("expected validation error for invalid priority (CRITICAL not in HIGH/MEDIUM/LOW)")
	}
}

func TestLoad_DetectionRules_Empty(t *testing.T) {
	path := writeYAML(t, `
security:
  hmac_key: "12345678901234567890123456789012"
  enable_hash_chain: true
pipeline:
  service_id: test-svc
detection_rules: []
`)
	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("expected no error for empty rules, got %v", err)
	}
	if len(cfg.DetectionRules) != 0 {
		t.Errorf("expected 0 rules, got %d", len(cfg.DetectionRules))
	}
}

// --- error_routing validation ---

func TestLoad_ErrorRouting_ValidRules(t *testing.T) {
	path := writeYAML(t, `
security:
  hmac_key: "12345678901234567890123456789012"
  enable_hash_chain: true
pipeline:
  service_id: test-svc
error_routing:
  enabled: true
  rules:
    - match:
        severity: CRITICAL
      decisions:
        - destination: audit_sink
          action: record
          priority: 1
`)
	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	if !cfg.ErrorRouting.Enabled {
		t.Error("expected error_routing.enabled=true")
	}
}

func TestLoad_ErrorRouting_InvalidSeverity(t *testing.T) {
	path := writeYAML(t, `
security:
  hmac_key: "12345678901234567890123456789012"
  enable_hash_chain: true
pipeline:
  service_id: test-svc
error_routing:
  enabled: true
  rules:
    - match:
        severity: MEGA
      decisions: []
`)
	_, err := Load(path)
	if err == nil {
		t.Fatal("expected validation error for invalid severity")
	}
}

func TestLoad_ErrorRouting_InvalidDestination(t *testing.T) {
	path := writeYAML(t, `
security:
  hmac_key: "12345678901234567890123456789012"
  enable_hash_chain: true
pipeline:
  service_id: test-svc
error_routing:
  enabled: true
  rules:
    - match:
        severity: CRITICAL
      decisions:
        - destination: void
          action: record
          priority: 1
`)
	_, err := Load(path)
	if err == nil {
		t.Fatal("expected validation error for invalid destination")
	}
}

func TestLoad_ErrorRouting_InvalidAction(t *testing.T) {
	path := writeYAML(t, `
security:
  hmac_key: "12345678901234567890123456789012"
  enable_hash_chain: true
pipeline:
  service_id: test-svc
error_routing:
  enabled: true
  rules:
    - match:
        severity: CRITICAL
      decisions:
        - destination: log
          action: destroy
          priority: 1
`)
	_, err := Load(path)
	if err == nil {
		t.Fatal("expected validation error for invalid action")
	}
}

func TestLoad_ErrorRouting_Disabled(t *testing.T) {
	path := writeYAML(t, `
security:
  hmac_key: "12345678901234567890123456789012"
  enable_hash_chain: true
pipeline:
  service_id: test-svc
error_routing:
  enabled: false
`)
	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	if cfg.ErrorRouting.Enabled {
		t.Error("expected error_routing.enabled=false")
	}
}
