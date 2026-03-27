package detection

import (
	"testing"

	"github.com/schro-cat-dev/sentinel-server/internal/domain"
	"github.com/schro-cat-dev/sentinel-server/testutil"
)

func TestDetector_Critical(t *testing.T) {
	d := NewEventDetector()

	t.Run("detects critical log", func(t *testing.T) {
		log := testutil.NewCriticalLog()
		result := d.Detect(log)
		if result == nil {
			t.Fatal("expected detection")
		}
		if result.EventName != domain.EventSystemCriticalFailure {
			t.Errorf("expected SYSTEM_CRITICAL_FAILURE, got %s", result.EventName)
		}
		if result.Priority != domain.PriorityHigh {
			t.Errorf("expected HIGH priority, got %s", result.Priority)
		}
		payload, ok := result.Payload.(domain.SystemCriticalPayload)
		if !ok {
			t.Fatal("expected SystemCriticalPayload type")
		}
		if payload.Component != "db-service:connection-pool" {
			t.Errorf("expected component db-service:connection-pool, got %s", payload.Component)
		}
	})

	t.Run("detects critical AI_AGENT logs", func(t *testing.T) {
		log := testutil.NewCriticalLog(func(l *domain.Log) { l.Origin = domain.OriginAIAgent })
		result := d.Detect(log)
		if result == nil {
			t.Fatal("critical AI_AGENT should be detected")
		}
	})
}

func TestDetector_Security(t *testing.T) {
	d := NewEventDetector()

	t.Run("detects security level >= 5", func(t *testing.T) {
		log := testutil.NewSecurityLog()
		result := d.Detect(log)
		if result == nil {
			t.Fatal("expected detection")
		}
		if result.EventName != domain.EventSecurityIntrusion {
			t.Errorf("expected SECURITY_INTRUSION_DETECTED, got %s", result.EventName)
		}
	})

	t.Run("extracts IP from tags via typed payload", func(t *testing.T) {
		log := testutil.NewSecurityLog(func(l *domain.Log) {
			l.Tags = []domain.LogTag{{Key: "ip", Category: "10.0.0.1"}}
		})
		result := d.Detect(log)
		payload, ok := result.Payload.(domain.SecurityIntrusionPayload)
		if !ok {
			t.Fatal("expected SecurityIntrusionPayload type")
		}
		if payload.IP != "10.0.0.1" {
			t.Errorf("expected IP 10.0.0.1, got %s", payload.IP)
		}
		if payload.Severity != 5 {
			t.Errorf("expected severity 5, got %d", payload.Severity)
		}
	})

	t.Run("does not detect level < 5", func(t *testing.T) {
		log := testutil.NewSecurityLog(func(l *domain.Log) { l.Level = domain.LogLevelWarn })
		result := d.Detect(log)
		if result != nil {
			t.Error("should not detect level 4 security log")
		}
	})

	t.Run("defaults IP to 0.0.0.0 when no ip tag", func(t *testing.T) {
		log := testutil.NewSecurityLog(func(l *domain.Log) { l.Tags = nil })
		result := d.Detect(log)
		payload := result.Payload.(domain.SecurityIntrusionPayload)
		if payload.IP != "0.0.0.0" {
			t.Errorf("expected 0.0.0.0, got %s", payload.IP)
		}
	})
}

func TestDetector_Compliance(t *testing.T) {
	d := NewEventDetector()

	t.Run("detects compliance violation", func(t *testing.T) {
		log := testutil.NewComplianceLog()
		result := d.Detect(log)
		if result == nil {
			t.Fatal("expected detection")
		}
		if result.EventName != domain.EventComplianceViolation {
			t.Errorf("expected COMPLIANCE_VIOLATION, got %s", result.EventName)
		}
		payload, ok := result.Payload.(domain.ComplianceViolationPayload)
		if !ok {
			t.Fatal("expected ComplianceViolationPayload type")
		}
		if payload.DocumentID != "doc-456" {
			t.Errorf("expected doc-456, got %s", payload.DocumentID)
		}
		if payload.UserID != "user-123" {
			t.Errorf("expected user-123, got %s", payload.UserID)
		}
	})

	t.Run("case-insensitive violation", func(t *testing.T) {
		log := testutil.NewComplianceLog(func(l *domain.Log) { l.Message = "VIOLATION detected" })
		if d.Detect(log) == nil {
			t.Error("should detect uppercase VIOLATION")
		}
	})

	t.Run("no detection without violation keyword", func(t *testing.T) {
		log := testutil.NewComplianceLog(func(l *domain.Log) { l.Message = "Audit complete" })
		if d.Detect(log) != nil {
			t.Error("should not detect without violation keyword")
		}
	})
}

func TestDetector_SLA(t *testing.T) {
	d := NewEventDetector()

	t.Run("detects SLA violation level >= 4", func(t *testing.T) {
		log := testutil.NewTestLog(func(l *domain.Log) {
			l.Type = domain.LogTypeSLA
			l.Level = domain.LogLevelWarn
			l.Message = "Response time exceeded"
		})
		result := d.Detect(log)
		if result == nil {
			t.Fatal("expected detection")
		}
		if result.Priority != domain.PriorityMedium {
			t.Errorf("expected MEDIUM, got %s", result.Priority)
		}
		payload := result.Payload.(domain.SystemCriticalPayload)
		if payload.ErrorDetails != "SLA violation: Response time exceeded" {
			t.Errorf("unexpected error details: %s", payload.ErrorDetails)
		}
	})
}

func TestDetector_AILoopPrevention(t *testing.T) {
	d := NewEventDetector()

	t.Run("skips non-critical AI_AGENT logs", func(t *testing.T) {
		log := testutil.NewSecurityLog(func(l *domain.Log) { l.Origin = domain.OriginAIAgent })
		if d.Detect(log) != nil {
			t.Error("non-critical AI_AGENT should be skipped")
		}
	})
}

func TestDetector_Normal(t *testing.T) {
	d := NewEventDetector()

	t.Run("returns nil for normal log", func(t *testing.T) {
		if d.Detect(testutil.NewTestLog()) != nil {
			t.Error("normal log should not be detected")
		}
	})
}

func TestDetector_CustomRules(t *testing.T) {
	t.Run("works with custom rule set", func(t *testing.T) {
		// セキュリティルールだけで初期化
		d := NewEventDetectorWithRules([]DetectionRule{&SecurityIntrusionRule{}})
		// criticalログはルールにないので検知されない（CriticalRule未登録）
		critLog := testutil.NewCriticalLog()
		if d.Detect(critLog) != nil {
			t.Error("CriticalRule not registered, should not detect")
		}
		// セキュリティログは検知される
		secLog := testutil.NewSecurityLog()
		if d.Detect(secLog) == nil {
			t.Error("SecurityIntrusionRule should detect")
		}
	})
}
