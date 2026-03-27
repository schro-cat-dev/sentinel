package detection

import (
	"github.com/schro-cat-dev/sentinel-server/internal/domain"
)

// DetectionRule はログからイベントを検知するルールの抽象
type DetectionRule interface {
	Match(log domain.Log) *domain.DetectionResult
}

// EventDetector はルール集合を走査してイベントを検知する
type EventDetector struct {
	rules []DetectionRule
}

// NewEventDetector はデフォルトルールセットでDetectorを生成する
func NewEventDetector() *EventDetector {
	return &EventDetector{
		rules: []DetectionRule{
			&CriticalRule{},
			&SecurityIntrusionRule{},
			&ComplianceViolationRule{},
			&SLAViolationRule{},
		},
	}
}

// NewEventDetectorWithRules はカスタムルールセットでDetectorを生成する
func NewEventDetectorWithRules(rules []DetectionRule) *EventDetector {
	return &EventDetector{rules: rules}
}

// Detect はログを全ルールに対して評価し、最初にマッチしたイベントを返す。
// AI_AGENTからのログは再帰検知防止のためスキップ（criticalを除く）。
func (d *EventDetector) Detect(log domain.Log) *domain.DetectionResult {
	if log.Origin == domain.OriginAIAgent && !log.IsCritical {
		return nil
	}
	for _, rule := range d.rules {
		if result := rule.Match(log); result != nil {
			return result
		}
	}
	return nil
}
