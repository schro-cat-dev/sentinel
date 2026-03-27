package task

import (
	"testing"

	"github.com/schro-cat-dev/sentinel-server/internal/domain"
	"github.com/schro-cat-dev/sentinel-server/testutil"
)

func defaultRules() []domain.TaskRule {
	return []domain.TaskRule{
		testutil.NewTestTaskRule(func(r *domain.TaskRule) {
			r.RuleID = "crit-notify"
			r.EventName = "SYSTEM_CRITICAL_FAILURE"
			r.Severity = domain.SeverityHigh
			r.ActionType = domain.ActionSystemNotification
		}),
		testutil.NewTestTaskRule(func(r *domain.TaskRule) {
			r.RuleID = "sec-analyze"
			r.EventName = "SECURITY_INTRUSION_DETECTED"
			r.Severity = domain.SeverityHigh
			r.ActionType = domain.ActionAIAnalyze
		}),
		testutil.NewTestTaskRule(func(r *domain.TaskRule) {
			r.RuleID = "comp-escalate"
			r.EventName = "COMPLIANCE_VIOLATION"
			r.Severity = domain.SeverityMedium
			r.ActionType = domain.ActionEscalate
			r.ExecutionLevel = domain.ExecLevelManual
		}),
	}
}

func TestGenerator_Generate(t *testing.T) {
	g := NewTaskGenerator(defaultRules())

	t.Run("rule count", func(t *testing.T) {
		if g.RuleCount() != 3 {
			t.Errorf("expected 3 rules, got %d", g.RuleCount())
		}
	})

	t.Run("generates tasks for critical log", func(t *testing.T) {
		det := &domain.DetectionResult{
			EventName: domain.EventSystemCriticalFailure,
			Priority:  domain.PriorityHigh,
			Payload:   domain.SystemCriticalPayload{Component: "db", ErrorDetails: "pool exhausted"},
		}
		log := testutil.NewCriticalLog()
		tasks := g.Generate(det, log)
		if len(tasks) == 0 {
			t.Fatal("expected tasks")
		}
		if tasks[0].RuleID != "crit-notify" {
			t.Errorf("expected crit-notify, got %s", tasks[0].RuleID)
		}
		if tasks[0].SourceLog.TraceID != log.TraceID {
			t.Error("source log traceID mismatch")
		}
	})

	t.Run("generates unique taskIDs", func(t *testing.T) {
		det := &domain.DetectionResult{
			EventName: domain.EventSystemCriticalFailure,
			Priority:  domain.PriorityHigh,
			Payload:   domain.SystemCriticalPayload{},
		}
		tasks := g.Generate(det, testutil.NewCriticalLog())
		seen := map[string]bool{}
		for _, task := range tasks {
			if seen[task.TaskID] {
				t.Error("duplicate taskID")
			}
			seen[task.TaskID] = true
		}
	})

	t.Run("no tasks for unregistered event", func(t *testing.T) {
		det := &domain.DetectionResult{EventName: domain.EventAIActionRequired, Priority: domain.PriorityLow}
		tasks := g.Generate(det, testutil.NewTestLog())
		if len(tasks) != 0 {
			t.Errorf("expected 0 tasks, got %d", len(tasks))
		}
	})

	t.Run("nil detection returns nil", func(t *testing.T) {
		tasks := g.Generate(nil, testutil.NewTestLog())
		if tasks != nil {
			t.Error("expected nil for nil detection")
		}
	})

	t.Run("empty rules generates nothing", func(t *testing.T) {
		g2 := NewTaskGenerator(nil)
		det := &domain.DetectionResult{
			EventName: domain.EventSystemCriticalFailure,
			Priority:  domain.PriorityHigh,
			Payload:   domain.SystemCriticalPayload{},
		}
		if tasks := g2.Generate(det, testutil.NewCriticalLog()); len(tasks) != 0 {
			t.Error("expected 0 tasks with empty rules")
		}
	})
}
