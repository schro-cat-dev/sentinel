package detection

import (
	"testing"

	"github.com/schro-cat-dev/sentinel-server/internal/domain"
	"github.com/schro-cat-dev/sentinel-server/testutil"
)

func TestDynamicRule_BasicMatch(t *testing.T) {
	cfg := DynamicRuleConfig{
		RuleID:    "dyn-001",
		EventName: "CUSTOM_EVENT",
		Priority:  "HIGH",
		Score:     0.9,
		Conditions: DynamicRuleConditions{
			LogTypes: []string{"SECURITY"},
			MinLevel: 5,
		},
		PayloadBuilder: "security_intrusion",
	}
	rule, err := NewDynamicRule(cfg)
	if err != nil {
		t.Fatalf("NewDynamicRule: %v", err)
	}

	t.Run("matches security level 5+", func(t *testing.T) {
		log := testutil.NewSecurityLog()
		result := rule.Match(log)
		if result == nil {
			t.Fatal("expected match")
		}
		if result.EventName != "CUSTOM_EVENT" {
			t.Errorf("expected CUSTOM_EVENT, got %s", result.EventName)
		}
		if result.Priority != domain.PriorityHigh {
			t.Errorf("expected HIGH, got %s", result.Priority)
		}
		if result.RuleID != "dyn-001" {
			t.Errorf("expected dyn-001, got %s", result.RuleID)
		}
	})

	t.Run("does not match wrong type", func(t *testing.T) {
		log := testutil.NewTestLog() // SYSTEM type
		if rule.Match(log) != nil {
			t.Error("should not match SYSTEM type")
		}
	})

	t.Run("does not match level < 5", func(t *testing.T) {
		log := testutil.NewSecurityLog(func(l *domain.Log) { l.Level = domain.LogLevelWarn })
		if rule.Match(log) != nil {
			t.Error("should not match level 4")
		}
	})
}

func TestDynamicRule_MessagePattern(t *testing.T) {
	cfg := DynamicRuleConfig{
		RuleID:    "dyn-002",
		EventName: "PATTERN_MATCH",
		Priority:  "MEDIUM",
		Score:     0.8,
		Conditions: DynamicRuleConditions{
			MessagePattern: `(?i)unauthorized\s+access`,
		},
		PayloadBuilder: "system_critical",
	}
	rule, err := NewDynamicRule(cfg)
	if err != nil {
		t.Fatalf("NewDynamicRule: %v", err)
	}

	t.Run("matches message pattern", func(t *testing.T) {
		log := testutil.NewTestLog(func(l *domain.Log) {
			l.Message = "Unauthorized Access attempt from 10.0.0.1"
		})
		if rule.Match(log) == nil {
			t.Error("should match message pattern")
		}
	})

	t.Run("does not match unrelated message", func(t *testing.T) {
		log := testutil.NewTestLog(func(l *domain.Log) { l.Message = "Normal operation" })
		if rule.Match(log) != nil {
			t.Error("should not match")
		}
	})
}

func TestDynamicRule_RequireCritical(t *testing.T) {
	trueVal := true
	cfg := DynamicRuleConfig{
		RuleID:    "dyn-003",
		EventName: "CRITICAL_ONLY",
		Priority:  "HIGH",
		Score:     1.0,
		Conditions: DynamicRuleConditions{
			RequireCritical: &trueVal,
		},
	}
	rule, err := NewDynamicRule(cfg)
	if err != nil {
		t.Fatalf("NewDynamicRule: %v", err)
	}

	t.Run("matches critical log", func(t *testing.T) {
		log := testutil.NewCriticalLog()
		if rule.Match(log) == nil {
			t.Error("should match critical")
		}
	})

	t.Run("does not match non-critical", func(t *testing.T) {
		log := testutil.NewTestLog()
		if rule.Match(log) != nil {
			t.Error("should not match non-critical")
		}
	})
}

func TestDynamicRule_TagKeys(t *testing.T) {
	cfg := DynamicRuleConfig{
		RuleID:    "dyn-004",
		EventName: "TAG_MATCH",
		Priority:  "LOW",
		Score:     0.7,
		Conditions: DynamicRuleConditions{
			TagKeys: []string{"ip", "user_agent"},
		},
	}
	rule, err := NewDynamicRule(cfg)
	if err != nil {
		t.Fatalf("NewDynamicRule: %v", err)
	}

	t.Run("matches when all tags present", func(t *testing.T) {
		log := testutil.NewTestLog(func(l *domain.Log) {
			l.Tags = []domain.LogTag{
				{Key: "ip", Category: "10.0.0.1"},
				{Key: "user_agent", Category: "curl/7.0"},
			}
		})
		if rule.Match(log) == nil {
			t.Error("should match with all tags")
		}
	})

	t.Run("does not match when tag missing", func(t *testing.T) {
		log := testutil.NewTestLog(func(l *domain.Log) {
			l.Tags = []domain.LogTag{{Key: "ip", Category: "10.0.0.1"}}
		})
		if rule.Match(log) != nil {
			t.Error("should not match with missing tag")
		}
	})
}

func TestDynamicRule_LevelRange(t *testing.T) {
	cfg := DynamicRuleConfig{
		RuleID:    "dyn-005",
		EventName: "LEVEL_RANGE",
		Priority:  "MEDIUM",
		Score:     0.6,
		Conditions: DynamicRuleConditions{
			MinLevel: 3,
			MaxLevel: 4,
		},
	}
	rule, err := NewDynamicRule(cfg)
	if err != nil {
		t.Fatalf("NewDynamicRule: %v", err)
	}

	t.Run("matches level 3 (INFO)", func(t *testing.T) {
		log := testutil.NewTestLog(func(l *domain.Log) { l.Level = domain.LogLevelInfo })
		if rule.Match(log) == nil {
			t.Error("should match level 3")
		}
	})

	t.Run("matches level 4 (WARN)", func(t *testing.T) {
		log := testutil.NewTestLog(func(l *domain.Log) { l.Level = domain.LogLevelWarn })
		if rule.Match(log) == nil {
			t.Error("should match level 4")
		}
	})

	t.Run("does not match level 5", func(t *testing.T) {
		log := testutil.NewTestLog(func(l *domain.Log) { l.Level = domain.LogLevelError })
		if rule.Match(log) != nil {
			t.Error("should not match level 5")
		}
	})

	t.Run("does not match level 2", func(t *testing.T) {
		log := testutil.NewTestLog(func(l *domain.Log) { l.Level = domain.LogLevelDebug })
		if rule.Match(log) != nil {
			t.Error("should not match level 2")
		}
	})
}

func TestDynamicRule_InvalidRegex(t *testing.T) {
	cfg := DynamicRuleConfig{
		RuleID:    "dyn-bad",
		EventName: "BAD",
		Conditions: DynamicRuleConditions{
			MessagePattern: `[unclosed`,
		},
	}
	_, err := NewDynamicRule(cfg)
	if err == nil {
		t.Error("expected error for invalid regex")
	}
}

func TestDynamicRule_PayloadBuilders(t *testing.T) {
	tests := []struct {
		builder  string
		logSetup func(l *domain.Log)
	}{
		{"system_critical", func(l *domain.Log) { l.Boundary = "test-svc" }},
		{"security_intrusion", func(l *domain.Log) {
			l.Tags = []domain.LogTag{{Key: "ip", Category: "1.2.3.4"}}
		}},
		{"compliance_violation", func(l *domain.Log) {
			l.ActorID = "usr-1"
			l.ResourceIDs = []string{"doc-1"}
		}},
		{"unknown_builder", func(l *domain.Log) {}},
	}
	for _, tt := range tests {
		t.Run(tt.builder, func(t *testing.T) {
			cfg := DynamicRuleConfig{
				RuleID:         "dyn-pb",
				EventName:      "PB_TEST",
				Priority:       "MEDIUM",
				Score:          1.0,
				PayloadBuilder: tt.builder,
			}
			rule, err := NewDynamicRule(cfg)
			if err != nil {
				t.Fatal(err)
			}
			log := testutil.NewTestLog(tt.logSetup)
			result := rule.Match(log)
			if result == nil {
				t.Fatal("expected match")
			}
			if result.Payload == nil {
				t.Error("expected payload")
			}
		})
	}
}

func TestDynamicRule_Score(t *testing.T) {
	cfg := DynamicRuleConfig{
		RuleID:    "dyn-score",
		EventName: "SCORE_TEST",
		Score:     0.85,
		Conditions: DynamicRuleConditions{
			LogTypes: []string{"SECURITY"},
		},
	}
	rule, err := NewDynamicRule(cfg)
	if err != nil {
		t.Fatal(err)
	}

	t.Run("returns configured score on match", func(t *testing.T) {
		log := testutil.NewSecurityLog()
		if s := rule.Score(log); s != 0.85 {
			t.Errorf("expected 0.85, got %f", s)
		}
	})

	t.Run("returns 0 on no match", func(t *testing.T) {
		log := testutil.NewTestLog()
		if s := rule.Score(log); s != 0 {
			t.Errorf("expected 0, got %f", s)
		}
	})
}

func TestDynamicRule_OriginFilter(t *testing.T) {
	cfg := DynamicRuleConfig{
		RuleID:    "dyn-origin",
		EventName: "ORIGIN_TEST",
		Score:     1.0,
		Conditions: DynamicRuleConditions{
			Origins: []string{"AI_AGENT"},
		},
	}
	rule, err := NewDynamicRule(cfg)
	if err != nil {
		t.Fatal(err)
	}

	t.Run("matches AI_AGENT origin", func(t *testing.T) {
		log := testutil.NewTestLog(func(l *domain.Log) { l.Origin = domain.OriginAIAgent })
		if rule.Match(log) == nil {
			t.Error("should match AI_AGENT")
		}
	})

	t.Run("does not match SYSTEM origin", func(t *testing.T) {
		log := testutil.NewTestLog()
		if rule.Match(log) != nil {
			t.Error("should not match SYSTEM")
		}
	})
}

func TestLoadDynamicRules(t *testing.T) {
	configs := []DynamicRuleConfig{
		{RuleID: "r1", EventName: "E1", Score: 0.8, Conditions: DynamicRuleConditions{LogTypes: []string{"SECURITY"}}},
		{RuleID: "r2", EventName: "E2", Score: 0.6},
	}
	rules, err := LoadDynamicRules(configs)
	if err != nil {
		t.Fatalf("LoadDynamicRules: %v", err)
	}
	if len(rules) != 2 {
		t.Errorf("expected 2 rules, got %d", len(rules))
	}
}

func TestLoadDynamicRules_InvalidRegex(t *testing.T) {
	configs := []DynamicRuleConfig{
		{RuleID: "r-bad", EventName: "E", Conditions: DynamicRuleConditions{MessagePattern: `[bad`}},
	}
	_, err := LoadDynamicRules(configs)
	if err == nil {
		t.Error("expected error for invalid regex")
	}
}
