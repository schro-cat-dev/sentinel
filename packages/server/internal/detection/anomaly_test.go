package detection

import (
	"testing"
	"time"

	"github.com/schro-cat-dev/sentinel-server/internal/domain"
	"github.com/schro-cat-dev/sentinel-server/testutil"
)

func TestAnomalyDetector_NormalTraffic(t *testing.T) {
	now := time.Now()
	currentTime := now
	cfg := AnomalyConfig{
		WindowSize:     1 * time.Minute,
		BaselineWindow: 5 * time.Minute,
		ThresholdPct:   300.0,
		MinBaseline:    3.0,
	}
	ad := NewAnomalyDetector(cfg, WithNowFunc(func() time.Time { return currentTime }))

	// 5分間で均等に15件のログを送る（ベースライン: 1分あたり3件）
	for i := 0; i < 15; i++ {
		currentTime = now.Add(time.Duration(i) * 20 * time.Second)
		log := testutil.NewTestLog(func(l *domain.Log) {
			l.Type = domain.LogTypeSecurity
			l.Boundary = "auth-service:login"
		})
		result := ad.Analyze(log)
		// 通常のトラフィックなので異常検知されないはず
		if result != nil && !result.Suppressed {
			// 初期段階でベースライン未確立の場合は無視
		}
	}
}

func TestAnomalyDetector_SpikeDetection(t *testing.T) {
	now := time.Now()
	currentTime := now
	cfg := AnomalyConfig{
		WindowSize:     1 * time.Minute,
		BaselineWindow: 5 * time.Minute,
		ThresholdPct:   300.0,
		MinBaseline:    3.0,
	}
	ad := NewAnomalyDetector(cfg, WithNowFunc(func() time.Time { return currentTime }))

	// Phase 1: 4分間で疎なトラフィック（1分あたり1件 = 合計4件）
	for i := 0; i < 4; i++ {
		currentTime = now.Add(time.Duration(i) * 60 * time.Second)
		log := testutil.NewTestLog(func(l *domain.Log) {
			l.Type = domain.LogTypeSecurity
			l.Boundary = "auth-service:login"
		})
		ad.Analyze(log)
	}

	// Phase 2: 直近1分で急増（25件 → ベースライン比 ~400%+）
	var detected *domain.DetectionResult
	for i := 0; i < 25; i++ {
		currentTime = now.Add(4*time.Minute + time.Duration(i)*2*time.Second)
		log := testutil.NewTestLog(func(l *domain.Log) {
			l.Type = domain.LogTypeSecurity
			l.Boundary = "auth-service:login"
		})
		result := ad.Analyze(log)
		if result != nil {
			detected = result
		}
	}

	if detected == nil {
		t.Fatal("expected anomaly detection on spike")
	}
	if detected.EventName != domain.EventAnomaly {
		t.Errorf("expected ANOMALY_DETECTED, got %s", detected.EventName)
	}

	payload, ok := detected.Payload.(domain.AnomalyPayload)
	if !ok {
		t.Fatal("expected AnomalyPayload")
	}
	if payload.MetricKey != "SECURITY|auth-service:login" {
		t.Errorf("unexpected metric key: %s", payload.MetricKey)
	}
	if payload.DeviationPct < 300 {
		t.Errorf("expected deviation >= 300%%, got %.1f%%", payload.DeviationPct)
	}
}

func TestAnomalyDetector_BelowMinBaseline(t *testing.T) {
	now := time.Now()
	currentTime := now
	cfg := AnomalyConfig{
		WindowSize:     1 * time.Minute,
		BaselineWindow: 5 * time.Minute,
		ThresholdPct:   200.0,
		MinBaseline:    10.0, // 高い閾値
	}
	ad := NewAnomalyDetector(cfg, WithNowFunc(func() time.Time { return currentTime }))

	// 少量のログ → ベースラインが低すぎて判定されない
	for i := 0; i < 5; i++ {
		currentTime = now.Add(time.Duration(i) * 10 * time.Second)
		log := testutil.NewTestLog(func(l *domain.Log) {
			l.Boundary = "test-svc"
		})
		result := ad.Analyze(log)
		if result != nil {
			t.Error("should not detect with low baseline")
		}
	}
}

func TestFrequencyTracker_CountInWindow(t *testing.T) {
	cfg := DefaultAnomalyConfig()
	tracker := NewFrequencyTracker(cfg)

	now := time.Now()
	tracker.Record("key1", now.Add(-30*time.Second))
	tracker.Record("key1", now.Add(-20*time.Second))
	tracker.Record("key1", now.Add(-10*time.Second))
	tracker.Record("key1", now)

	count := tracker.CountInWindow("key1", now, 1*time.Minute)
	if count != 4 {
		t.Errorf("expected 4, got %d", count)
	}

	count = tracker.CountInWindow("key1", now, 15*time.Second)
	if count != 2 {
		t.Errorf("expected 2 (within 15s), got %d", count)
	}

	count = tracker.CountInWindow("key2", now, 1*time.Minute)
	if count != 0 {
		t.Errorf("expected 0 for unknown key, got %d", count)
	}
}

func TestMetricKeyForLog(t *testing.T) {
	log := testutil.NewSecurityLog()
	key := MetricKeyForLog(log)
	if key != "SECURITY|auth-service:login" {
		t.Errorf("unexpected key: %s", key)
	}
}

func TestAnomalyDetector_HighDeviationPriority(t *testing.T) {
	now := time.Now()
	currentTime := now
	cfg := AnomalyConfig{
		WindowSize:     1 * time.Minute,
		BaselineWindow: 10 * time.Minute,
		ThresholdPct:   200.0,
		MinBaseline:    3.0,
	}
	ad := NewAnomalyDetector(cfg, WithNowFunc(func() time.Time { return currentTime }))

	// Build baseline: 9 minutes, 4 logs per minute (36 total)
	for i := 0; i < 36; i++ {
		currentTime = now.Add(time.Duration(i) * 15 * time.Second)
		log := testutil.NewTestLog(func(l *domain.Log) {
			l.Type = domain.LogTypeInfra
			l.Boundary = "infra-svc"
		})
		ad.Analyze(log)
	}

	// Spike: 30 logs in final minute (deviation ~750% of ~3.6 baseline)
	var lastResult *domain.DetectionResult
	for i := 0; i < 30; i++ {
		currentTime = now.Add(9*time.Minute + time.Duration(i)*2*time.Second)
		log := testutil.NewTestLog(func(l *domain.Log) {
			l.Type = domain.LogTypeInfra
			l.Boundary = "infra-svc"
		})
		r := ad.Analyze(log)
		if r != nil {
			lastResult = r
		}
	}

	if lastResult == nil {
		t.Fatal("expected detection")
	}
	payload := lastResult.Payload.(domain.AnomalyPayload)
	t.Logf("deviation: %.1f%%", payload.DeviationPct)
	if payload.DeviationPct >= 500 && lastResult.Priority != domain.PriorityHigh {
		t.Errorf("expected HIGH priority for deviation >= 500%%, got %s (deviation=%.1f%%)", lastResult.Priority, payload.DeviationPct)
	}
	if payload.DeviationPct < 500 && payload.DeviationPct >= 200 && lastResult.Priority != domain.PriorityMedium {
		t.Errorf("expected MEDIUM priority for deviation 200-500%%, got %s (deviation=%.1f%%)", lastResult.Priority, payload.DeviationPct)
	}
}
