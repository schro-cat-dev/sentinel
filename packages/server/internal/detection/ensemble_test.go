package detection

import (
	"testing"
	"time"

	"github.com/schro-cat-dev/sentinel-server/internal/domain"
	"github.com/schro-cat-dev/sentinel-server/testutil"
)

func TestEnsembleDetector_AllRulesFire(t *testing.T) {
	// CriticalかつSECURITYタイプのログ → 複数ルールが発火
	rules := []ScoredDetectionRule{
		WrapRule(&CriticalRule{}, "critical-001", 1.0),
		WrapRule(&SecurityIntrusionRule{}, "security-001", 0.9),
	}
	e := NewEnsembleDetector(rules, WithThreshold(&ThresholdPolicy{MinScore: 0.5}))

	log := testutil.NewCriticalLog(func(l *domain.Log) {
		l.Type = domain.LogTypeSecurity
		l.Level = domain.LogLevelCritical
	})
	result := e.DetectAll(log)
	if result == nil {
		t.Fatal("expected ensemble result")
	}
	if len(result.Results) != 2 {
		t.Errorf("expected 2 fired rules, got %d", len(result.Results))
	}
	if result.TopResult == nil {
		t.Fatal("expected top result")
	}
	if result.TopResult.Priority != domain.PriorityHigh {
		t.Errorf("expected HIGH priority, got %s", result.TopResult.Priority)
	}
}

func TestEnsembleDetector_AggregateMax(t *testing.T) {
	rules := []ScoredDetectionRule{
		WrapRule(&CriticalRule{}, "critical-001", 0.8),
		WrapRule(&SecurityIntrusionRule{}, "security-001", 0.6),
	}
	e := NewEnsembleDetector(rules, WithAggregator(AggregateMax), WithThreshold(&ThresholdPolicy{MinScore: 0.5}))

	log := testutil.NewCriticalLog(func(l *domain.Log) {
		l.Type = domain.LogTypeSecurity
		l.Level = domain.LogLevelCritical
	})
	result := e.DetectAll(log)
	if result == nil {
		t.Fatal("expected result")
	}
	if result.AggregateScore != 0.8 {
		t.Errorf("expected aggregate 0.8, got %f", result.AggregateScore)
	}
}

func TestEnsembleDetector_AggregateAvg(t *testing.T) {
	rules := []ScoredDetectionRule{
		WrapRule(&CriticalRule{}, "critical-001", 0.8),
		WrapRule(&SecurityIntrusionRule{}, "security-001", 0.6),
	}
	e := NewEnsembleDetector(rules, WithAggregator(AggregateAvg), WithThreshold(&ThresholdPolicy{MinScore: 0.5}))

	log := testutil.NewCriticalLog(func(l *domain.Log) {
		l.Type = domain.LogTypeSecurity
		l.Level = domain.LogLevelCritical
	})
	result := e.DetectAll(log)
	if result == nil {
		t.Fatal("expected result")
	}
	expected := 0.7
	if result.AggregateScore < expected-0.01 || result.AggregateScore > expected+0.01 {
		t.Errorf("expected aggregate ~0.7, got %f", result.AggregateScore)
	}
}

func TestEnsembleDetector_AggregateWeightedSum(t *testing.T) {
	rules := []ScoredDetectionRule{
		WrapRule(&CriticalRule{}, "critical-001", 0.6),
		WrapRule(&SecurityIntrusionRule{}, "security-001", 0.7),
	}
	e := NewEnsembleDetector(rules, WithAggregator(AggregateWeightedSum), WithThreshold(&ThresholdPolicy{MinScore: 0.5}))

	log := testutil.NewCriticalLog(func(l *domain.Log) {
		l.Type = domain.LogTypeSecurity
		l.Level = domain.LogLevelCritical
	})
	result := e.DetectAll(log)
	if result == nil {
		t.Fatal("expected result")
	}
	// 0.6 + 0.7 = 1.3, clamped to 1.0
	if result.AggregateScore != 1.0 {
		t.Errorf("expected aggregate 1.0 (clamped), got %f", result.AggregateScore)
	}
}

func TestEnsembleDetector_ThresholdFilter(t *testing.T) {
	rules := []ScoredDetectionRule{
		WrapRule(&CriticalRule{}, "critical-001", 0.3),
	}
	e := NewEnsembleDetector(rules, WithThreshold(&ThresholdPolicy{MinScore: 0.5}))

	log := testutil.NewCriticalLog()
	result := e.DetectAll(log)
	if result != nil {
		t.Error("expected nil because score 0.3 < threshold 0.5")
	}
}

func TestEnsembleDetector_PriorityResolution(t *testing.T) {
	rules := []ScoredDetectionRule{
		WrapRule(&SLAViolationRule{}, "sla-001", 0.9),       // MEDIUM
		WrapRule(&SecurityIntrusionRule{}, "sec-001", 0.7),   // HIGH
	}
	e := NewEnsembleDetector(rules, WithThreshold(&ThresholdPolicy{MinScore: 0.5}))

	log := testutil.NewSecurityLog(func(l *domain.Log) {
		l.Type = domain.LogTypeSecurity
		l.Level = domain.LogLevelError
	})
	// SLA won't match (wrong type), only security fires
	result := e.DetectAll(log)
	if result == nil {
		t.Fatal("expected result")
	}
	if result.TopResult.EventName != domain.EventSecurityIntrusion {
		t.Errorf("expected SECURITY_INTRUSION, got %s", result.TopResult.EventName)
	}
}

func TestEnsembleDetector_BackwardCompatDetect(t *testing.T) {
	rules := []ScoredDetectionRule{
		WrapRule(&CriticalRule{}, "critical-001", 1.0),
	}
	e := NewEnsembleDetector(rules)

	log := testutil.NewCriticalLog()
	result := e.Detect(log)
	if result == nil {
		t.Fatal("expected backward-compat Detect to return result")
	}
	if result.EventName != domain.EventSystemCriticalFailure {
		t.Errorf("expected SYSTEM_CRITICAL_FAILURE, got %s", result.EventName)
	}
}

func TestEnsembleDetector_AIAgentPrevention(t *testing.T) {
	rules := []ScoredDetectionRule{
		WrapRule(&SecurityIntrusionRule{}, "sec-001", 1.0),
	}
	e := NewEnsembleDetector(rules)

	log := testutil.NewSecurityLog(func(l *domain.Log) { l.Origin = domain.OriginAIAgent })
	if e.Detect(log) != nil {
		t.Error("non-critical AI_AGENT should be skipped")
	}
}

func TestEnsembleDetector_WithDeduplication(t *testing.T) {
	dedup := NewDeduplicator(1 * time.Second)
	rules := []ScoredDetectionRule{
		WrapRule(&CriticalRule{}, "critical-001", 1.0),
	}
	e := NewEnsembleDetector(rules, WithDeduplicator(dedup))

	log := testutil.NewCriticalLog()

	// First detection should succeed
	r1 := e.Detect(log)
	if r1 == nil {
		t.Fatal("first detection should fire")
	}

	// Second detection within window should be suppressed
	r2 := e.DetectAll(log)
	if r2 != nil {
		t.Error("second detection should be suppressed by dedup")
	}
}

func TestEnsembleDetector_NoRulesFire(t *testing.T) {
	rules := []ScoredDetectionRule{
		WrapRule(&SecurityIntrusionRule{}, "sec-001", 1.0),
	}
	e := NewEnsembleDetector(rules)

	log := testutil.NewTestLog() // normal log, won't match security rule
	if e.Detect(log) != nil {
		t.Error("normal log should not fire")
	}
}

func TestRuleAdapter(t *testing.T) {
	adapter := WrapRule(&CriticalRule{}, "crit-001", 0.95)

	t.Run("returns ruleID", func(t *testing.T) {
		if adapter.RuleID() != "crit-001" {
			t.Errorf("expected crit-001, got %s", adapter.RuleID())
		}
	})

	t.Run("returns score on match", func(t *testing.T) {
		log := testutil.NewCriticalLog()
		if s := adapter.Score(log); s != 0.95 {
			t.Errorf("expected 0.95, got %f", s)
		}
	})

	t.Run("returns 0 on no match", func(t *testing.T) {
		log := testutil.NewTestLog()
		if s := adapter.Score(log); s != 0 {
			t.Errorf("expected 0, got %f", s)
		}
	})
}

func TestEnsembleDetector_EmptyRules(t *testing.T) {
	e := NewEnsembleDetector(nil)

	log := testutil.NewCriticalLog()
	result := e.DetectAll(log)
	if result != nil {
		t.Error("empty rules should produce nil result")
	}

	e2 := NewEnsembleDetector([]ScoredDetectionRule{})
	if e2.Detect(testutil.NewSecurityLog()) != nil {
		t.Error("zero rules should produce nil")
	}
}

func TestPriorityResolution_SameLevel(t *testing.T) {
	// When same priority, higher score wins
	rules := []ScoredDetectionRule{
		WrapRule(&CriticalRule{}, "crit-001", 0.7),
		WrapRule(&SecurityIntrusionRule{}, "sec-001", 0.9),
	}
	e := NewEnsembleDetector(rules, WithThreshold(&ThresholdPolicy{MinScore: 0.5}))

	log := testutil.NewCriticalLog(func(l *domain.Log) {
		l.Type = domain.LogTypeSecurity
		l.Level = domain.LogLevelCritical
	})
	result := e.DetectAll(log)
	if result == nil {
		t.Fatal("expected result")
	}
	// Both are HIGH priority, security has higher score (0.9 vs 0.7)
	if result.TopResult.RuleID != "sec-001" {
		t.Errorf("expected sec-001 (higher score at same priority), got %s", result.TopResult.RuleID)
	}
}
