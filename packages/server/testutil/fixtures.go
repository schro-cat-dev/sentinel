package testutil

import (
	"time"

	"github.com/schro-cat-dev/sentinel-server/internal/domain"
)

var FixedTime = time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)

func NewTestLog(overrides ...func(*domain.Log)) domain.Log {
	log := domain.Log{
		TraceID:      "test-trace-001",
		Type:         domain.LogTypeSystem,
		Level:        domain.LogLevelInfo,
		Timestamp:    FixedTime,
		LogicalClock: 1000,
		Boundary:     "test-service:handler",
		ServiceID:    "test-service",
		IsCritical:   false,
		Message:      "Test log message",
		Origin:       domain.OriginSystem,
		Tags:         nil,
	}
	for _, fn := range overrides {
		fn(&log)
	}
	return log
}

func NewSecurityLog(overrides ...func(*domain.Log)) domain.Log {
	return NewTestLog(append([]func(*domain.Log){func(l *domain.Log) {
		l.Type = domain.LogTypeSecurity
		l.Level = domain.LogLevelError
		l.Message = "Suspicious activity detected from IP 192.168.1.100"
		l.Boundary = "auth-service:login"
		l.Tags = []domain.LogTag{{Key: "ip", Category: "192.168.1.100"}}
	}}, overrides...)...)
}

func NewCriticalLog(overrides ...func(*domain.Log)) domain.Log {
	return NewTestLog(append([]func(*domain.Log){func(l *domain.Log) {
		l.IsCritical = true
		l.Level = domain.LogLevelCritical
		l.Message = "Database connection pool exhausted"
		l.Boundary = "db-service:connection-pool"
	}}, overrides...)...)
}

func NewComplianceLog(overrides ...func(*domain.Log)) domain.Log {
	return NewTestLog(append([]func(*domain.Log){func(l *domain.Log) {
		l.Type = domain.LogTypeCompliance
		l.Level = domain.LogLevelWarn
		l.Message = "Data retention policy violation detected"
		l.Boundary = "audit-service:retention"
		l.ActorID = "user-123"
		l.ResourceIDs = []string{"doc-456"}
	}}, overrides...)...)
}

func NewTestTaskRule(overrides ...func(*domain.TaskRule)) domain.TaskRule {
	rule := domain.TaskRule{
		RuleID:         "rule-001",
		EventName:      "SYSTEM_CRITICAL_FAILURE",
		Severity:       domain.SeverityCritical,
		ActionType:     domain.ActionSystemNotification,
		ExecutionLevel: domain.ExecLevelAuto,
		Priority:       1,
		Description:    "Notify on critical system failure",
		ExecParams: domain.ExecParams{
			NotificationChannel: "#incidents",
		},
		Guardrails: domain.Guardrails{
			RequireHumanApproval: false,
			TimeoutMs:            30000,
			MaxRetries:           3,
		},
	}
	for _, fn := range overrides {
		fn(&rule)
	}
	return rule
}
