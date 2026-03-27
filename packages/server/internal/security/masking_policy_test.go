package security

import (
	"regexp"
	"strings"
	"testing"

	"github.com/schro-cat-dev/sentinel-server/internal/domain"
	"github.com/schro-cat-dev/sentinel-server/testutil"
)

func TestMaskingPolicyEngine_MatchesByLogType(t *testing.T) {
	policies := []MaskingPolicyRule{
		{
			PolicyID: "security-strict",
			Condition: MaskingPolicyCondition{
				LogTypes: []domain.LogType{domain.LogTypeSecurity},
			},
			MaskingRules: []MaskingRule{
				{Type: "PII_TYPE", Category: "EMAIL"},
				{Type: "PII_TYPE", Category: "PHONE"},
				{Type: "PII_TYPE", Category: "CREDIT_CARD"},
			},
		},
		{
			PolicyID: "compliance-audit",
			Condition: MaskingPolicyCondition{
				LogTypes: []domain.LogType{domain.LogTypeCompliance},
			},
			MaskingRules: []MaskingRule{
				{Type: "PII_TYPE", Category: "EMAIL"},
			},
			PreserveExtra: []string{"actorId"},
		},
	}

	defaultRules := []MaskingRule{
		{Type: "PII_TYPE", Category: "EMAIL"},
	}

	engine := NewMaskingPolicyEngine(policies, defaultRules, []string{"traceId"})

	t.Run("security log gets strict rules", func(t *testing.T) {
		log := testutil.NewSecurityLog()
		rules, preserve := engine.ResolveRules(log)
		if len(rules) != 3 {
			t.Errorf("expected 3 rules for security, got %d", len(rules))
		}
		// traceId should be in preserve
		found := false
		for _, f := range preserve {
			if f == "traceId" {
				found = true
			}
		}
		if !found {
			t.Error("expected traceId in preserve fields")
		}
	})

	t.Run("compliance log gets compliance rules + preserve actorId", func(t *testing.T) {
		log := testutil.NewComplianceLog()
		rules, preserve := engine.ResolveRules(log)
		if len(rules) != 1 {
			t.Errorf("expected 1 rule for compliance, got %d", len(rules))
		}
		hasActor := false
		for _, f := range preserve {
			if f == "actorId" {
				hasActor = true
			}
		}
		if !hasActor {
			t.Error("expected actorId in preserve for compliance")
		}
	})

	t.Run("unmatched log gets default rules", func(t *testing.T) {
		log := testutil.NewTestLog() // SYSTEM type
		rules, _ := engine.ResolveRules(log)
		if len(rules) != 1 {
			t.Errorf("expected 1 default rule, got %d", len(rules))
		}
	})
}

func TestMaskingPolicyEngine_MatchesByOrigin(t *testing.T) {
	policies := []MaskingPolicyRule{
		{
			PolicyID: "ai-agent-strict",
			Condition: MaskingPolicyCondition{
				Origins: []domain.Origin{domain.OriginAIAgent},
			},
			MaskingRules: []MaskingRule{
				{Type: "PII_TYPE", Category: "EMAIL"},
				{Type: "PII_TYPE", Category: "GOVERNMENT_ID"},
			},
		},
	}
	engine := NewMaskingPolicyEngine(policies, nil, nil)

	t.Run("AI_AGENT origin matches", func(t *testing.T) {
		log := testutil.NewTestLog(func(l *domain.Log) { l.Origin = domain.OriginAIAgent })
		rules, _ := engine.ResolveRules(log)
		if len(rules) != 2 {
			t.Errorf("expected 2 rules, got %d", len(rules))
		}
	})

	t.Run("SYSTEM origin does not match", func(t *testing.T) {
		log := testutil.NewTestLog()
		rules, _ := engine.ResolveRules(log)
		if len(rules) != 0 {
			t.Errorf("expected 0 rules (no default), got %d", len(rules))
		}
	})
}

func TestMaskingPolicyEngine_MatchesByLevel(t *testing.T) {
	policies := []MaskingPolicyRule{
		{
			PolicyID: "high-level",
			Condition: MaskingPolicyCondition{
				MinLevel: domain.LogLevelError,
			},
			MaskingRules: []MaskingRule{
				{Type: "PII_TYPE", Category: "EMAIL"},
				{Type: "PII_TYPE", Category: "PHONE"},
			},
		},
	}
	engine := NewMaskingPolicyEngine(policies, nil, nil)

	t.Run("error level matches", func(t *testing.T) {
		log := testutil.NewTestLog(func(l *domain.Log) { l.Level = domain.LogLevelError })
		rules, _ := engine.ResolveRules(log)
		if len(rules) != 2 {
			t.Errorf("expected 2, got %d", len(rules))
		}
	})

	t.Run("info level does not match", func(t *testing.T) {
		log := testutil.NewTestLog(func(l *domain.Log) { l.Level = domain.LogLevelInfo })
		rules, _ := engine.ResolveRules(log)
		if len(rules) != 0 {
			t.Errorf("expected 0, got %d", len(rules))
		}
	})
}

func TestMaskingPolicyEngine_CreateMaskingService(t *testing.T) {
	policies := []MaskingPolicyRule{
		{
			PolicyID: "email-only",
			Condition: MaskingPolicyCondition{
				LogTypes: []domain.LogType{domain.LogTypeSecurity},
			},
			MaskingRules: []MaskingRule{
				{Type: "PII_TYPE", Category: "EMAIL"},
			},
		},
	}
	engine := NewMaskingPolicyEngine(policies, nil, nil)

	log := testutil.NewSecurityLog()
	svc := engine.CreateMaskingService(log)

	testLog := domain.Log{Message: "Contact admin@example.com for help"}
	svc.MaskLog(&testLog)
	if strings.Contains(testLog.Message, "admin@example.com") {
		t.Error("email should be masked")
	}
}

func TestMaskingPolicyEngine_CombinedConditions(t *testing.T) {
	policies := []MaskingPolicyRule{
		{
			PolicyID: "strict-security-error",
			Condition: MaskingPolicyCondition{
				LogTypes: []domain.LogType{domain.LogTypeSecurity},
				MinLevel: domain.LogLevelError,
			},
			MaskingRules: []MaskingRule{
				{Type: "REGEX", Pattern: regexp.MustCompile(`\d{3}\.\d{3}\.\d{3}\.\d{3}`), Replacement: "[MASKED_IP]"},
			},
		},
	}
	engine := NewMaskingPolicyEngine(policies, nil, nil)

	t.Run("matches both conditions", func(t *testing.T) {
		log := testutil.NewSecurityLog() // SECURITY + Error level
		rules, _ := engine.ResolveRules(log)
		if len(rules) != 1 {
			t.Errorf("expected 1, got %d", len(rules))
		}
	})

	t.Run("wrong type fails", func(t *testing.T) {
		log := testutil.NewTestLog(func(l *domain.Log) { l.Level = domain.LogLevelError })
		rules, _ := engine.ResolveRules(log)
		if len(rules) != 0 {
			t.Errorf("expected 0, got %d", len(rules))
		}
	})

	t.Run("wrong level fails", func(t *testing.T) {
		log := testutil.NewTestLog(func(l *domain.Log) {
			l.Type = domain.LogTypeSecurity
			l.Level = domain.LogLevelInfo
		})
		rules, _ := engine.ResolveRules(log)
		if len(rules) != 0 {
			t.Errorf("expected 0, got %d", len(rules))
		}
	})
}

func TestMaskingPolicyEngine_MultiplePoliciesMatch(t *testing.T) {
	policies := []MaskingPolicyRule{
		{
			PolicyID: "policy-1",
			Condition: MaskingPolicyCondition{
				LogTypes: []domain.LogType{domain.LogTypeSecurity},
			},
			MaskingRules: []MaskingRule{
				{Type: "PII_TYPE", Category: "EMAIL"},
			},
		},
		{
			PolicyID: "policy-2",
			Condition: MaskingPolicyCondition{
				MinLevel: domain.LogLevelError,
			},
			MaskingRules: []MaskingRule{
				{Type: "PII_TYPE", Category: "PHONE"},
			},
		},
	}
	engine := NewMaskingPolicyEngine(policies, nil, nil)

	// Security + Error matches both policies
	log := testutil.NewSecurityLog()
	rules, _ := engine.ResolveRules(log)
	if len(rules) != 2 {
		t.Errorf("expected 2 rules (from both policies), got %d", len(rules))
	}
}
