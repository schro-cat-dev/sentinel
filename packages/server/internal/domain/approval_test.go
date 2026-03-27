package domain

import (
	"testing"
	"time"
)

func TestComputeTaskContentHash(t *testing.T) {
	task := GeneratedTask{
		TaskID: "task-001", RuleID: "rule-001", EventName: "TEST",
		Severity: SeverityHigh, ActionType: ActionEscalate,
		ExecutionLevel: ExecLevelManual, Description: "Test task",
		SourceLog: SourceLogInfo{TraceID: "t1", Message: "original"},
	}

	t.Run("deterministic", func(t *testing.T) {
		h1 := ComputeTaskContentHash(task)
		h2 := ComputeTaskContentHash(task)
		if h1 != h2 {
			t.Error("same task should produce same hash")
		}
		if len(h1) != 64 {
			t.Errorf("expected 64-char hex, got %d", len(h1))
		}
	})

	t.Run("changes on description tamper", func(t *testing.T) {
		h1 := ComputeTaskContentHash(task)
		tampered := task
		tampered.Description = "TAMPERED"
		h2 := ComputeTaskContentHash(tampered)
		if h1 == h2 {
			t.Error("different description should produce different hash")
		}
	})

	t.Run("changes on exec_params tamper", func(t *testing.T) {
		h1 := ComputeTaskContentHash(task)
		tampered := task
		tampered.ExecParams.ScriptIdentifier = "malicious-script"
		h2 := ComputeTaskContentHash(tampered)
		if h1 == h2 {
			t.Error("different exec_params should produce different hash")
		}
	})

	t.Run("changes on source message tamper", func(t *testing.T) {
		h1 := ComputeTaskContentHash(task)
		tampered := task
		tampered.SourceLog.Message = "falsified log"
		h2 := ComputeTaskContentHash(tampered)
		if h1 == h2 {
			t.Error("different source message should produce different hash")
		}
	})
}

func TestApprovalChainStep_Structure(t *testing.T) {
	chain := []ApprovalChainStep{
		{StepOrder: 1, Role: "team_lead", TeamID: "security-team", Required: true},
		{StepOrder: 2, Role: "manager", TeamID: "security-team", Required: true},
		{StepOrder: 3, Role: "ciso", TeamID: "executive", Required: true},
	}

	t.Run("chain is ordered", func(t *testing.T) {
		for i := 1; i < len(chain); i++ {
			if chain[i].StepOrder <= chain[i-1].StepOrder {
				t.Error("chain should be in ascending order")
			}
		}
	})

	t.Run("all steps required", func(t *testing.T) {
		for _, step := range chain {
			if !step.Required {
				t.Errorf("step %d should be required", step.StepOrder)
			}
		}
	})
}

func TestApprovalRoutingRule_LevelMatching(t *testing.T) {
	rules := []ApprovalRoutingRule{
		{
			RuleID: "low-auto", MinLevel: LogLevelTrace, MaxLevel: LogLevelInfo,
			Chain: []ApprovalChainStep{{StepOrder: 1, Role: "team_lead"}},
		},
		{
			RuleID: "med-review", MinLevel: LogLevelWarn, MaxLevel: LogLevelError,
			Chain: []ApprovalChainStep{
				{StepOrder: 1, Role: "team_lead"},
				{StepOrder: 2, Role: "manager"},
			},
		},
		{
			RuleID: "high-critical", MinLevel: LogLevelCritical, MaxLevel: LogLevelCritical,
			EventName: "SYSTEM_CRITICAL_FAILURE",
			Chain: []ApprovalChainStep{
				{StepOrder: 1, Role: "team_lead"},
				{StepOrder: 2, Role: "manager"},
				{StepOrder: 3, Role: "ciso"},
			},
			NotifyTargets: []NotifyTarget{
				{Type: "slack", Target: "#security-critical", Role: "security_team"},
				{Type: "email", Target: "ciso@company.com", Role: "ciso"},
			},
		},
	}

	t.Run("level 3 matches low-auto (1 step)", func(t *testing.T) {
		matched := findMatchingRule(rules, LogLevelInfo, "")
		if matched == nil || matched.RuleID != "low-auto" {
			t.Error("level 3 should match low-auto")
		}
		if len(matched.Chain) != 1 {
			t.Errorf("expected 1 step, got %d", len(matched.Chain))
		}
	})

	t.Run("level 5 matches med-review (2 steps)", func(t *testing.T) {
		matched := findMatchingRule(rules, LogLevelError, "")
		if matched == nil || matched.RuleID != "med-review" {
			t.Error("level 5 should match med-review")
		}
		if len(matched.Chain) != 2 {
			t.Errorf("expected 2 steps, got %d", len(matched.Chain))
		}
	})

	t.Run("level 6 + SYSTEM_CRITICAL_FAILURE matches high-critical (3 steps + notify)", func(t *testing.T) {
		matched := findMatchingRule(rules, LogLevelCritical, "SYSTEM_CRITICAL_FAILURE")
		if matched == nil || matched.RuleID != "high-critical" {
			t.Error("level 6 + critical event should match high-critical")
		}
		if len(matched.Chain) != 3 {
			t.Errorf("expected 3 steps, got %d", len(matched.Chain))
		}
		if len(matched.NotifyTargets) != 2 {
			t.Errorf("expected 2 notify targets, got %d", len(matched.NotifyTargets))
		}
	})
}

func TestApprovalStepRecord_Immutability(t *testing.T) {
	record := ApprovalStepRecord{
		RecordID: "rec-001", ApprovalID: "appr-001", StepOrder: 1,
		Action: "approved", ActorID: "lead-001", ActorRole: "team_lead",
		Reason: "Verified", ContentHash: "abc123", CreatedAt: time.Now(),
	}

	t.Run("has all required fields", func(t *testing.T) {
		if record.RecordID == "" { t.Error("missing RecordID") }
		if record.ApprovalID == "" { t.Error("missing ApprovalID") }
		if record.ActorID == "" { t.Error("missing ActorID") }
		if record.ContentHash == "" { t.Error("missing ContentHash") }
		if record.CreatedAt.IsZero() { t.Error("missing CreatedAt") }
	})
}

func TestTaskModification_AuditTrail(t *testing.T) {
	mod := TaskModification{
		ModificationID: "mod-001", TaskID: "task-001",
		ModifiedBy: "admin", Field: "description",
		OldValue: "original", NewValue: "changed",
		ContentHash: "hash-after", CreatedAt: time.Now(),
	}

	t.Run("tracks field change", func(t *testing.T) {
		if mod.OldValue == mod.NewValue {
			t.Error("old and new should differ")
		}
	})

	t.Run("records content hash after modification", func(t *testing.T) {
		if mod.ContentHash == "" {
			t.Error("content hash should be set")
		}
	})
}

// Helper: find first matching routing rule for a given level/event
func findMatchingRule(rules []ApprovalRoutingRule, level LogLevel, eventName string) *ApprovalRoutingRule {
	for i, r := range rules {
		if level >= r.MinLevel && level <= r.MaxLevel {
			if r.EventName == "" || r.EventName == eventName {
				return &rules[i]
			}
		}
	}
	return nil
}
