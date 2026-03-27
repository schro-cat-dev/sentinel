package response

import (
	"testing"

	"github.com/schro-cat-dev/sentinel-server/internal/domain"
	"github.com/schro-cat-dev/sentinel-server/testutil"
)

func TestExtractThreatTarget_SecurityIntrusion(t *testing.T) {
	det := &domain.DetectionResult{
		EventName: domain.EventSecurityIntrusion,
		Priority:  domain.PriorityHigh,
		Payload: domain.SecurityIntrusionPayload{
			IP: "192.168.1.100", Severity: 5,
		},
	}
	log := testutil.NewSecurityLog(func(l *domain.Log) {
		l.ActorID = "user-123"
	})

	target := ExtractThreatTarget(det, log)

	if target.IP != "192.168.1.100" {
		t.Errorf("expected IP 192.168.1.100, got %s", target.IP)
	}
	if target.Boundary != "auth-service:login" {
		t.Errorf("expected boundary, got %s", target.Boundary)
	}
	if target.UserID != "user-123" {
		t.Errorf("expected user-123, got %s", target.UserID)
	}
}

func TestExtractThreatTarget_Anomaly(t *testing.T) {
	det := &domain.DetectionResult{
		EventName: domain.EventAnomaly,
		Priority:  domain.PriorityMedium,
		Payload: domain.AnomalyPayload{
			MetricKey: "SECURITY|auth-svc", Baseline: 5, Observed: 25,
		},
	}
	log := testutil.NewTestLog(func(l *domain.Log) {
		l.Boundary = "auth-svc"
	})

	target := ExtractThreatTarget(det, log)
	if target.MetricKey != "SECURITY|auth-svc" {
		t.Errorf("expected metric key, got %s", target.MetricKey)
	}
}

func TestExtractThreatTarget_Compliance(t *testing.T) {
	det := &domain.DetectionResult{
		EventName: domain.EventComplianceViolation,
		Payload: domain.ComplianceViolationPayload{
			UserID: "usr-1", DocumentID: "doc-1", RuleID: "r-1",
		},
	}
	log := testutil.NewComplianceLog()

	target := ExtractThreatTarget(det, log)
	if target.UserID != "usr-1" {
		t.Errorf("expected usr-1, got %s", target.UserID)
	}
	if target.ResourceID != "doc-1" {
		t.Errorf("expected doc-1, got %s", target.ResourceID)
	}
}

func TestExtractThreatTarget_IPFromTags(t *testing.T) {
	det := &domain.DetectionResult{
		EventName: domain.EventSystemCriticalFailure,
		Payload: domain.SystemCriticalPayload{
			Component: "db", ErrorDetails: "error",
		},
	}
	log := testutil.NewTestLog(func(l *domain.Log) {
		l.Tags = []domain.LogTag{{Key: "ip", Category: "10.0.0.1"}}
	})

	target := ExtractThreatTarget(det, log)
	if target.IP != "10.0.0.1" {
		t.Errorf("expected IP from tags, got %s", target.IP)
	}
}

func TestFindResponseRule_ExactMatch(t *testing.T) {
	cfg := ThreatResponseConfig{
		Enabled: true,
		Rules: []ResponseRuleConfig{
			{EventName: "SECURITY_INTRUSION_DETECTED", Strategy: StrategyBlockAndNotify, BlockAction: "block_ip"},
			{EventName: "COMPLIANCE_VIOLATION", Strategy: StrategyNotifyOnly},
		},
	}

	rule := FindResponseRule(cfg, domain.EventSecurityIntrusion, domain.PriorityHigh)
	if rule == nil {
		t.Fatal("expected rule")
	}
	if rule.Strategy != StrategyBlockAndNotify {
		t.Errorf("expected BLOCK_AND_NOTIFY, got %s", rule.Strategy)
	}
	if rule.BlockAction != "block_ip" {
		t.Errorf("expected block_ip, got %s", rule.BlockAction)
	}
}

func TestFindResponseRule_Wildcard(t *testing.T) {
	cfg := ThreatResponseConfig{
		Enabled: true,
		Rules: []ResponseRuleConfig{
			{EventName: "", Strategy: StrategyMonitor}, // wildcard
		},
	}

	rule := FindResponseRule(cfg, domain.EventAnomaly, domain.PriorityMedium)
	if rule == nil {
		t.Fatal("expected wildcard rule")
	}
	if rule.Strategy != StrategyMonitor {
		t.Errorf("expected MONITOR, got %s", rule.Strategy)
	}
}

func TestFindResponseRule_NoMatch(t *testing.T) {
	cfg := ThreatResponseConfig{
		Enabled: true,
		Rules: []ResponseRuleConfig{
			{EventName: "SECURITY_INTRUSION_DETECTED", Strategy: StrategyBlockAndNotify},
		},
	}

	rule := FindResponseRule(cfg, domain.EventAnomaly, domain.PriorityMedium)
	if rule != nil {
		t.Error("expected no match")
	}
}

func TestFindResponseRule_MinPriority(t *testing.T) {
	cfg := ThreatResponseConfig{
		Enabled: true,
		Rules: []ResponseRuleConfig{
			{EventName: "SECURITY_INTRUSION_DETECTED", Strategy: StrategyBlockAndNotify, MinPriority: "HIGH"},
		},
	}

	t.Run("HIGH priority matches", func(t *testing.T) {
		rule := FindResponseRule(cfg, domain.EventSecurityIntrusion, domain.PriorityHigh)
		if rule == nil {
			t.Error("HIGH should match")
		}
	})

	t.Run("MEDIUM priority does not match", func(t *testing.T) {
		rule := FindResponseRule(cfg, domain.EventSecurityIntrusion, domain.PriorityMedium)
		if rule != nil {
			t.Error("MEDIUM should not match when min is HIGH")
		}
	})
}

func TestDefaultThreatResponseConfig(t *testing.T) {
	cfg := DefaultThreatResponseConfig()
	if cfg.Enabled {
		t.Error("should be disabled by default")
	}
	if cfg.DefaultStrategy != StrategyNotifyOnly {
		t.Errorf("expected NOTIFY_ONLY default, got %s", cfg.DefaultStrategy)
	}
}
