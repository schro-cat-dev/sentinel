package detection

import (
	"github.com/schro-cat-dev/sentinel-server/internal/domain"
)

// ScoredDetectionRule は信頼度スコア付きの検知ルール
type ScoredDetectionRule interface {
	DetectionRule
	// RuleID はルールの一意識別子を返す
	RuleID() string
	// Score はログに対する信頼度スコア (0.0〜1.0) を返す。0はマッチしない。
	Score(log domain.Log) float64
}

// ThresholdPolicy は集約スコアに基づく発火判定ポリシー
type ThresholdPolicy struct {
	MinScore float64 // この値以上で発火（デフォルト0.5）
}

// DefaultThresholdPolicy はデフォルトの閾値ポリシーを返す
func DefaultThresholdPolicy() *ThresholdPolicy {
	return &ThresholdPolicy{MinScore: 0.5}
}

// ShouldFire は集約スコアが閾値を超えているか判定する
func (p *ThresholdPolicy) ShouldFire(score float64) bool {
	return score >= p.MinScore
}

// ScoreAggregator はスコア集約方式
type ScoreAggregator int

const (
	// AggregateMax は最大スコアを採用する
	AggregateMax ScoreAggregator = iota
	// AggregateAvg は平均スコアを採用する（発火したルールのみ）
	AggregateAvg
	// AggregateWeightedSum は重み付き合計を採用する（1.0で上限クランプ）
	AggregateWeightedSum
)

// PriorityOrder は検知優先度の序列
var PriorityOrder = map[domain.DetectionPriority]int{
	domain.PriorityLow:    0,
	domain.PriorityMedium: 1,
	domain.PriorityHigh:   2,
}

// EnsembleDetector は全ルールを評価しスコアを集約するアンサンブル検知器
type EnsembleDetector struct {
	rules      []ScoredDetectionRule
	aggregator ScoreAggregator
	policy     *ThresholdPolicy
	dedup      *Deduplicator
}

// EnsembleOption はEnsembleDetectorの設定オプション
type EnsembleOption func(*EnsembleDetector)

// WithAggregator はスコア集約方式を設定する
func WithAggregator(agg ScoreAggregator) EnsembleOption {
	return func(e *EnsembleDetector) { e.aggregator = agg }
}

// WithThreshold は閾値ポリシーを設定する
func WithThreshold(policy *ThresholdPolicy) EnsembleOption {
	return func(e *EnsembleDetector) { e.policy = policy }
}

// WithDeduplicator は重複抑制フィルターを設定する
func WithDeduplicator(d *Deduplicator) EnsembleOption {
	return func(e *EnsembleDetector) { e.dedup = d }
}

// NewEnsembleDetector はアンサンブル検知器を生成する
func NewEnsembleDetector(rules []ScoredDetectionRule, opts ...EnsembleOption) *EnsembleDetector {
	e := &EnsembleDetector{
		rules:      rules,
		aggregator: AggregateMax,
		policy:     DefaultThresholdPolicy(),
	}
	for _, opt := range opts {
		opt(e)
	}
	return e
}

// DetectAll は全ルールを評価し、アンサンブル結果を返す
func (e *EnsembleDetector) DetectAll(log domain.Log) *domain.EnsembleResult {
	// AI_AGENT再帰防止（criticalを除く）
	if log.Origin == domain.OriginAIAgent && !log.IsCritical {
		return nil
	}

	var fired []*domain.DetectionResult
	for _, rule := range e.rules {
		score := rule.Score(log)
		if score <= 0 {
			continue
		}
		result := rule.Match(log)
		if result == nil {
			continue
		}
		result.Score = score
		result.RuleID = rule.RuleID()

		// 重複抑制チェック
		if e.dedup != nil {
			key := deduplicationKey(log, result)
			if e.dedup.IsDuplicate(key) {
				result.Suppressed = true
			}
		}

		if !result.Suppressed {
			fired = append(fired, result)
		}
	}

	if len(fired) == 0 {
		return nil
	}

	aggScore := e.aggregate(fired)

	if !e.policy.ShouldFire(aggScore) {
		return nil
	}

	top := e.resolveTopPriority(fired)

	return &domain.EnsembleResult{
		Results:        fired,
		AggregateScore: aggScore,
		TopResult:      top,
	}
}

// Detect は後方互換性のため、アンサンブル結果の最高優先度結果を返す
func (e *EnsembleDetector) Detect(log domain.Log) *domain.DetectionResult {
	result := e.DetectAll(log)
	if result == nil {
		return nil
	}
	return result.TopResult
}

func (e *EnsembleDetector) aggregate(results []*domain.DetectionResult) float64 {
	if len(results) == 0 {
		return 0
	}

	switch e.aggregator {
	case AggregateMax:
		max := 0.0
		for _, r := range results {
			if r.Score > max {
				max = r.Score
			}
		}
		return max

	case AggregateAvg:
		sum := 0.0
		for _, r := range results {
			sum += r.Score
		}
		return sum / float64(len(results))

	case AggregateWeightedSum:
		sum := 0.0
		for _, r := range results {
			sum += r.Score
		}
		if sum > 1.0 {
			sum = 1.0
		}
		return sum

	default:
		return results[0].Score
	}
}

func (e *EnsembleDetector) resolveTopPriority(results []*domain.DetectionResult) *domain.DetectionResult {
	if len(results) == 0 {
		return nil
	}
	top := results[0]
	for _, r := range results[1:] {
		if PriorityOrder[r.Priority] > PriorityOrder[top.Priority] {
			top = r
		} else if PriorityOrder[r.Priority] == PriorityOrder[top.Priority] && r.Score > top.Score {
			top = r
		}
	}
	return top
}

func deduplicationKey(log domain.Log, result *domain.DetectionResult) string {
	return string(result.EventName) + "|" + log.Boundary + "|" + log.ServiceID
}

// --- Adapter: 既存DetectionRuleをScoredDetectionRuleに変換 ---

// RuleAdapter は既存DetectionRuleをScoredDetectionRuleに変換するアダプター
type RuleAdapter struct {
	rule       DetectionRule
	ruleID     string
	fixedScore float64
}

// WrapRule は既存ルールを固定スコア付きのScoredDetectionRuleに変換する
func WrapRule(rule DetectionRule, ruleID string, score float64) ScoredDetectionRule {
	return &RuleAdapter{rule: rule, ruleID: ruleID, fixedScore: score}
}

func (a *RuleAdapter) Match(log domain.Log) *domain.DetectionResult {
	return a.rule.Match(log)
}

func (a *RuleAdapter) RuleID() string { return a.ruleID }

func (a *RuleAdapter) Score(log domain.Log) float64 {
	if a.rule.Match(log) != nil {
		return a.fixedScore
	}
	return 0
}
