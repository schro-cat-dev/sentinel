package task

import (
	"testing"
	"time"

	"github.com/schro-cat-dev/sentinel-server/internal/domain"
)

func makeDetection(eventName domain.SystemEventName, priority domain.DetectionPriority) *domain.DetectionResult {
	return &domain.DetectionResult{
		EventName: eventName,
		Priority:  priority,
	}
}

func makeLog(opts ...func(*domain.Log)) domain.Log {
	l := domain.Log{
		TraceID:    "trace-1",
		Type:       domain.LogTypeSystem,
		Level:      3,
		Timestamp:  time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC),
		Boundary:   "test-service:handler",
		ServiceID:  "test-svc",
		IsCritical: false,
		Message:    "test log",
		Origin:     domain.OriginSystem,
	}
	for _, o := range opts {
		o(&l)
	}
	return l
}

func makeRule(eventName string, severity domain.TaskSeverity, actionType domain.TaskActionType) domain.TaskRule {
	return domain.TaskRule{
		RuleID:         "rule-1",
		EventName:      eventName,
		Severity:       severity,
		ActionType:     actionType,
		ExecutionLevel: domain.ExecLevelAuto,
		Priority:       1,
		Description:    "test rule",
		Guardrails: domain.Guardrails{
			RequireHumanApproval: false,
			TimeoutMs:            30000,
			MaxRetries:           3,
		},
	}
}

func TestGenerator_BasicMatch(t *testing.T) {
	gen := NewTaskGenerator([]domain.TaskRule{
		makeRule("SYSTEM_CRITICAL_FAILURE", domain.SeverityHigh, domain.ActionSystemNotification),
	})

	det := makeDetection(domain.EventSystemCriticalFailure, domain.PriorityHigh)
	tasks := gen.Generate(det, makeLog(func(l *domain.Log) { l.IsCritical = true }))

	if len(tasks) == 0 {
		t.Fatal("expected at least 1 task")
	}
	if tasks[0].EventName != "SYSTEM_CRITICAL_FAILURE" {
		t.Errorf("expected SYSTEM_CRITICAL_FAILURE, got %s", tasks[0].EventName)
	}
}

func TestGenerator_NoMatchingRules(t *testing.T) {
	gen := NewTaskGenerator([]domain.TaskRule{
		makeRule("COMPLIANCE_VIOLATION", domain.SeverityHigh, domain.ActionEscalate),
	})

	det := makeDetection(domain.EventSystemCriticalFailure, domain.PriorityHigh)
	tasks := gen.Generate(det, makeLog())

	if len(tasks) != 0 {
		t.Errorf("expected 0 tasks, got %d", len(tasks))
	}
}

func TestGenerator_NilDetection(t *testing.T) {
	gen := NewTaskGenerator([]domain.TaskRule{
		makeRule("SYSTEM_CRITICAL_FAILURE", domain.SeverityHigh, domain.ActionSystemNotification),
	})

	tasks := gen.Generate(nil, makeLog())
	if tasks != nil {
		t.Errorf("expected nil, got %v", tasks)
	}
}

func TestGenerator_SeverityThreshold(t *testing.T) {
	gen := NewTaskGenerator([]domain.TaskRule{
		makeRule("SYSTEM_CRITICAL_FAILURE", domain.SeverityCritical, domain.ActionKillSwitch),
	})

	// CRITICAL severity rule requires CRITICAL actual severity
	// Non-critical log → severity is HIGH (not CRITICAL) → no match
	det := makeDetection(domain.EventSystemCriticalFailure, domain.PriorityMedium)
	tasks := gen.Generate(det, makeLog())

	if len(tasks) != 0 {
		t.Errorf("expected 0 tasks (below threshold), got %d", len(tasks))
	}

	// Critical log → severity is CRITICAL → matches
	tasks = gen.Generate(det, makeLog(func(l *domain.Log) { l.IsCritical = true }))
	if len(tasks) == 0 {
		t.Fatal("expected task for critical log")
	}
}

func TestGenerator_PriorityOrdering(t *testing.T) {
	gen := NewTaskGenerator([]domain.TaskRule{
		{
			RuleID: "low-pri", EventName: "SYSTEM_CRITICAL_FAILURE",
			Severity: domain.SeverityHigh, ActionType: domain.ActionSystemNotification,
			ExecutionLevel: domain.ExecLevelAuto, Priority: 5,
			Guardrails: domain.Guardrails{TimeoutMs: 30000},
		},
		{
			RuleID: "high-pri", EventName: "SYSTEM_CRITICAL_FAILURE",
			Severity: domain.SeverityHigh, ActionType: domain.ActionEscalate,
			ExecutionLevel: domain.ExecLevelAuto, Priority: 1,
			Guardrails: domain.Guardrails{TimeoutMs: 30000},
		},
	})

	det := makeDetection(domain.EventSystemCriticalFailure, domain.PriorityHigh)
	tasks := gen.Generate(det, makeLog(func(l *domain.Log) { l.IsCritical = true }))

	if len(tasks) < 2 {
		t.Fatalf("expected 2 tasks, got %d", len(tasks))
	}
	if tasks[0].RuleID != "high-pri" {
		t.Errorf("expected high-pri first, got %s", tasks[0].RuleID)
	}
}

func TestGenerator_RuleCount(t *testing.T) {
	gen := NewTaskGenerator([]domain.TaskRule{
		makeRule("SYSTEM_CRITICAL_FAILURE", domain.SeverityHigh, domain.ActionSystemNotification),
		makeRule("SECURITY_INTRUSION_DETECTED", domain.SeverityHigh, domain.ActionEscalate),
	})
	if gen.RuleCount() != 2 {
		t.Errorf("expected 2 rules, got %d", gen.RuleCount())
	}
}

func TestGenerator_EmptyRules(t *testing.T) {
	gen := NewTaskGenerator(nil)
	if gen.RuleCount() != 0 {
		t.Errorf("expected 0 rules, got %d", gen.RuleCount())
	}

	det := makeDetection(domain.EventSystemCriticalFailure, domain.PriorityHigh)
	tasks := gen.Generate(det, makeLog())
	if len(tasks) != 0 {
		t.Errorf("expected 0 tasks, got %d", len(tasks))
	}
}

func TestGenerator_SecurityIntrusion_SeverityClassification(t *testing.T) {
	gen := NewTaskGenerator([]domain.TaskRule{
		makeRule("SECURITY_INTRUSION_DETECTED", domain.SeverityHigh, domain.ActionAIAnalyze),
	})

	det := makeDetection(domain.EventSecurityIntrusion, domain.PriorityHigh)
	tasks := gen.Generate(det, makeLog(func(l *domain.Log) {
		l.Type = domain.LogTypeSecurity
		l.Level = 5
	}))

	if len(tasks) == 0 {
		t.Fatal("expected task for security intrusion")
	}
	if tasks[0].Severity != domain.SeverityHigh {
		t.Errorf("expected HIGH severity, got %s", tasks[0].Severity)
	}
}

func TestGenerator_SourceLogInfo(t *testing.T) {
	gen := NewTaskGenerator([]domain.TaskRule{
		makeRule("SYSTEM_CRITICAL_FAILURE", domain.SeverityHigh, domain.ActionSystemNotification),
	})

	det := makeDetection(domain.EventSystemCriticalFailure, domain.PriorityHigh)
	log := makeLog(func(l *domain.Log) {
		l.IsCritical = true
		l.TraceID = "trace-xyz"
		l.Message = "db connection lost"
		l.Boundary = "DBService:pool"
	})

	tasks := gen.Generate(det, log)
	if len(tasks) == 0 {
		t.Fatal("expected task")
	}
	if tasks[0].SourceLog.TraceID != "trace-xyz" {
		t.Errorf("expected trace-xyz, got %s", tasks[0].SourceLog.TraceID)
	}
	if tasks[0].SourceLog.Message != "db connection lost" {
		t.Errorf("expected 'db connection lost', got %s", tasks[0].SourceLog.Message)
	}
}
