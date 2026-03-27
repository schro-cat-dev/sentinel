package detection

import (
	"regexp"
	"strings"

	"github.com/schro-cat-dev/sentinel-server/internal/domain"
)

// DynamicRuleConfig は設定ファイルから読み込むルール定義
type DynamicRuleConfig struct {
	RuleID         string                `json:"rule_id"`
	EventName      string                `json:"event_name"`
	Priority       string                `json:"priority"`         // "HIGH", "MEDIUM", "LOW"
	Score          float64               `json:"score"`            // 0.0〜1.0
	Conditions     DynamicRuleConditions `json:"conditions"`
	PayloadBuilder string                `json:"payload_builder"`  // "system_critical", "security_intrusion", "compliance_violation"
}

// DynamicRuleConditions はルールの発火条件
type DynamicRuleConditions struct {
	LogTypes       []string `json:"log_types"`       // OR条件
	MinLevel       int      `json:"min_level"`       // 最低レベル（inclusive）
	MaxLevel       int      `json:"max_level"`       // 最高レベル（inclusive, 0=無制限）
	MessagePattern string   `json:"message_pattern"` // 正規表現（空=条件なし）
	RequireCritical *bool   `json:"require_critical"` // nil=条件なし, true/false=一致要求
	TagKeys        []string `json:"tag_keys"`        // AND条件: これらのタグキーが全て存在
	Origins        []string `json:"origins"`         // OR条件
}

// DynamicRule は設定ベースの検知ルール
type DynamicRule struct {
	config         DynamicRuleConfig
	messageRegex   *regexp.Regexp
	logTypeSet     map[domain.LogType]bool
	originSet      map[domain.Origin]bool
	priority       domain.DetectionPriority
}

// NewDynamicRule は設定からDynamicRuleを生成する
func NewDynamicRule(cfg DynamicRuleConfig) (*DynamicRule, error) {
	r := &DynamicRule{
		config:   cfg,
		priority: parsePriority(cfg.Priority),
	}

	// メッセージパターンのコンパイル
	if cfg.Conditions.MessagePattern != "" {
		re, err := regexp.Compile(cfg.Conditions.MessagePattern)
		if err != nil {
			return nil, err
		}
		r.messageRegex = re
	}

	// LogTypeセットの構築
	if len(cfg.Conditions.LogTypes) > 0 {
		r.logTypeSet = make(map[domain.LogType]bool, len(cfg.Conditions.LogTypes))
		for _, lt := range cfg.Conditions.LogTypes {
			r.logTypeSet[domain.LogType(lt)] = true
		}
	}

	// Originセットの構築
	if len(cfg.Conditions.Origins) > 0 {
		r.originSet = make(map[domain.Origin]bool, len(cfg.Conditions.Origins))
		for _, o := range cfg.Conditions.Origins {
			r.originSet[domain.Origin(o)] = true
		}
	}

	return r, nil
}

func (r *DynamicRule) RuleID() string { return r.config.RuleID }

func (r *DynamicRule) Score(log domain.Log) float64 {
	if r.match(log) {
		if r.config.Score > 0 {
			return r.config.Score
		}
		return 1.0
	}
	return 0
}

func (r *DynamicRule) Match(log domain.Log) *domain.DetectionResult {
	if !r.match(log) {
		return nil
	}
	return &domain.DetectionResult{
		EventName: domain.SystemEventName(r.config.EventName),
		Priority:  r.priority,
		Payload:   r.buildPayload(log),
		Score:     r.config.Score,
		RuleID:    r.config.RuleID,
	}
}

func (r *DynamicRule) match(log domain.Log) bool {
	c := r.config.Conditions

	// LogType チェック（OR）
	if r.logTypeSet != nil && !r.logTypeSet[log.Type] {
		return false
	}

	// Level範囲チェック
	if c.MinLevel > 0 && int(log.Level) < c.MinLevel {
		return false
	}
	if c.MaxLevel > 0 && int(log.Level) > c.MaxLevel {
		return false
	}

	// Origin チェック（OR）
	if r.originSet != nil && !r.originSet[log.Origin] {
		return false
	}

	// IsCritical チェック
	if c.RequireCritical != nil && log.IsCritical != *c.RequireCritical {
		return false
	}

	// メッセージパターンチェック
	if r.messageRegex != nil && !r.messageRegex.MatchString(log.Message) {
		return false
	}

	// タグキーチェック（AND: 全キーが存在すること）
	if len(c.TagKeys) > 0 {
		tagSet := make(map[string]bool, len(log.Tags))
		for _, tag := range log.Tags {
			tagSet[tag.Key] = true
		}
		for _, key := range c.TagKeys {
			if !tagSet[key] {
				return false
			}
		}
	}

	return true
}

func (r *DynamicRule) buildPayload(log domain.Log) domain.EventPayload {
	switch strings.ToLower(r.config.PayloadBuilder) {
	case "system_critical":
		return domain.SystemCriticalPayload{
			Component:    log.Boundary,
			ErrorDetails: log.Message,
		}
	case "security_intrusion":
		return domain.SecurityIntrusionPayload{
			IP:       log.IP("0.0.0.0"),
			Severity: int(log.Level),
		}
	case "compliance_violation":
		return domain.ComplianceViolationPayload{
			RuleID:     r.config.RuleID,
			DocumentID: log.FirstResourceID("unknown"),
			UserID:     log.ActorOrDefault("system"),
		}
	default:
		return domain.SystemCriticalPayload{
			Component:    log.Boundary,
			ErrorDetails: log.Message,
		}
	}
}

func parsePriority(s string) domain.DetectionPriority {
	switch strings.ToUpper(s) {
	case "HIGH":
		return domain.PriorityHigh
	case "MEDIUM":
		return domain.PriorityMedium
	case "LOW":
		return domain.PriorityLow
	default:
		return domain.PriorityMedium
	}
}

// LoadDynamicRules は設定スライスからDynamicRuleスライスを生成する
func LoadDynamicRules(configs []DynamicRuleConfig) ([]ScoredDetectionRule, error) {
	rules := make([]ScoredDetectionRule, 0, len(configs))
	for _, cfg := range configs {
		r, err := NewDynamicRule(cfg)
		if err != nil {
			return nil, err
		}
		rules = append(rules, r)
	}
	return rules, nil
}
