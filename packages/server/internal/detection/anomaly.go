package detection

import (
	"sync"
	"time"

	"github.com/schro-cat-dev/sentinel-server/internal/domain"
)

// AnomalyConfig は異常検知の設定
type AnomalyConfig struct {
	WindowSize     time.Duration // 分析対象のスライディングウィンドウ幅
	BaselineWindow time.Duration // ベースライン計算に使うウィンドウ幅
	ThresholdPct   float64       // 乖離率の閾値（%）: 例 200.0 = ベースラインの2倍
	MinBaseline    float64       // ベースラインがこの値以下の場合は判定しない（ノイズ回避）
}

// DefaultAnomalyConfig はデフォルトの異常検知設定を返す
func DefaultAnomalyConfig() AnomalyConfig {
	return AnomalyConfig{
		WindowSize:     1 * time.Minute,
		BaselineWindow: 10 * time.Minute,
		ThresholdPct:   300.0,
		MinBaseline:    3.0,
	}
}

// FrequencyTracker はメトリクスキーごとの出現頻度を追跡する
type FrequencyTracker struct {
	mu         sync.Mutex
	timestamps map[string][]time.Time // metricKey → sorted timestamps
	config     AnomalyConfig
}

// NewFrequencyTracker はFrequencyTrackerを生成する
func NewFrequencyTracker(cfg AnomalyConfig) *FrequencyTracker {
	return &FrequencyTracker{
		timestamps: make(map[string][]time.Time),
		config:     cfg,
	}
}

// Record はイベント発生を記録する
func (f *FrequencyTracker) Record(key string, ts time.Time) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.timestamps[key] = append(f.timestamps[key], ts)
	f.evict(key, ts)
}

// CountInWindow は指定ウィンドウ内のイベント数を返す
func (f *FrequencyTracker) CountInWindow(key string, now time.Time, window time.Duration) int {
	f.mu.Lock()
	defer f.mu.Unlock()
	cutoff := now.Add(-window)
	count := 0
	for _, ts := range f.timestamps[key] {
		if !ts.Before(cutoff) {
			count++
		}
	}
	return count
}

func (f *FrequencyTracker) evict(key string, now time.Time) {
	maxWindow := f.config.BaselineWindow
	if f.config.WindowSize > maxWindow {
		maxWindow = f.config.WindowSize
	}
	cutoff := now.Add(-maxWindow * 2)

	ts := f.timestamps[key]
	start := 0
	for start < len(ts) && ts[start].Before(cutoff) {
		start++
	}
	if start > 0 {
		f.timestamps[key] = ts[start:]
	}
}

// AnomalyDetector は統計的異常検知を行うサブモジュール
type AnomalyDetector struct {
	tracker *FrequencyTracker
	config  AnomalyConfig
	nowFunc func() time.Time // テスト用の時刻注入
}

// AnomalyDetectorOption はAnomalyDetectorの設定オプション
type AnomalyDetectorOption func(*AnomalyDetector)

// WithNowFunc はテスト用の時刻関数を設定する
func WithNowFunc(fn func() time.Time) AnomalyDetectorOption {
	return func(a *AnomalyDetector) { a.nowFunc = fn }
}

// NewAnomalyDetector はAnomalyDetectorを生成する
func NewAnomalyDetector(cfg AnomalyConfig, opts ...AnomalyDetectorOption) *AnomalyDetector {
	a := &AnomalyDetector{
		tracker: NewFrequencyTracker(cfg),
		config:  cfg,
		nowFunc: time.Now,
	}
	for _, opt := range opts {
		opt(a)
	}
	return a
}

// MetricKeyForLog はログからメトリクスキーを生成する
func MetricKeyForLog(log domain.Log) string {
	return string(log.Type) + "|" + log.Boundary
}

// Analyze はログを記録し、異常を検知した場合に結果を返す
func (a *AnomalyDetector) Analyze(log domain.Log) *domain.DetectionResult {
	now := a.nowFunc()
	key := MetricKeyForLog(log)

	a.tracker.Record(key, now)

	// 現在のウィンドウ内カウント
	currentCount := float64(a.tracker.CountInWindow(key, now, a.config.WindowSize))

	// ベースライン算出: BaselineWindow内のカウントをWindowSize単位に正規化
	baselineCount := float64(a.tracker.CountInWindow(key, now, a.config.BaselineWindow))
	windowsInBaseline := float64(a.config.BaselineWindow) / float64(a.config.WindowSize)
	if windowsInBaseline <= 0 {
		windowsInBaseline = 1
	}
	baseline := baselineCount / windowsInBaseline

	// ベースラインが低すぎる場合はスキップ（ノイズ回避）
	if baseline < a.config.MinBaseline {
		return nil
	}

	// 乖離率の計算
	deviationPct := (currentCount / baseline) * 100

	if deviationPct < a.config.ThresholdPct {
		return nil
	}

	priority := domain.PriorityMedium
	if deviationPct >= 500 {
		priority = domain.PriorityHigh
	}

	return &domain.DetectionResult{
		EventName: domain.EventAnomaly,
		Priority:  priority,
		Payload: domain.AnomalyPayload{
			MetricKey:    key,
			Baseline:     baseline,
			Observed:     currentCount,
			DeviationPct: deviationPct,
		},
		Score:  clampScore(deviationPct / 1000),
		RuleID: "anomaly-frequency",
	}
}

func clampScore(v float64) float64 {
	if v > 1.0 {
		return 1.0
	}
	if v < 0.0 {
		return 0.0
	}
	return v
}
