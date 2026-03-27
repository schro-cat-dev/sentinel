package security

import (
	"github.com/schro-cat-dev/sentinel-server/internal/domain"
)

// MaskingPolicyCondition はマスクポリシーの適用条件
type MaskingPolicyCondition struct {
	LogTypes []domain.LogType // OR条件（空=全タイプ対象）
	Origins  []domain.Origin  // OR条件（空=全オリジン対象）
	MinLevel domain.LogLevel  // 最低レベル（0=条件なし）
	MaxLevel domain.LogLevel  // 最高レベル（0=条件なし）
}

// MaskingPolicyRule はコンテキスト依存マスクルール
type MaskingPolicyRule struct {
	PolicyID      string
	Condition     MaskingPolicyCondition
	MaskingRules  []MaskingRule  // この条件で適用するマスクルール
	PreserveExtra []string       // この条件で追加で保護するフィールド
}

// MaskingPolicyEngine はログのコンテキストに応じてマスクルールを動的に選択する
type MaskingPolicyEngine struct {
	policies       []MaskingPolicyRule
	defaultRules   []MaskingRule   // どのポリシーにもマッチしない場合のデフォルト
	preserveFields []string
}

// NewMaskingPolicyEngine はMaskingPolicyEngineを生成する
func NewMaskingPolicyEngine(policies []MaskingPolicyRule, defaultRules []MaskingRule, preserveFields []string) *MaskingPolicyEngine {
	return &MaskingPolicyEngine{
		policies:       policies,
		defaultRules:   defaultRules,
		preserveFields: preserveFields,
	}
}

// ResolveRules はログのコンテキストに基づいてマスクルールとpreserveFieldsを選択する
func (e *MaskingPolicyEngine) ResolveRules(log domain.Log) ([]MaskingRule, []string) {
	var matchedRules []MaskingRule
	preserveSet := make(map[string]bool)
	for _, f := range e.preserveFields {
		preserveSet[f] = true
	}

	matched := false
	for _, policy := range e.policies {
		if e.matchCondition(log, policy.Condition) {
			matched = true
			matchedRules = append(matchedRules, policy.MaskingRules...)
			for _, f := range policy.PreserveExtra {
				preserveSet[f] = true
			}
		}
	}

	if !matched {
		matchedRules = e.defaultRules
	}

	preserveFields := make([]string, 0, len(preserveSet))
	for f := range preserveSet {
		preserveFields = append(preserveFields, f)
	}

	return matchedRules, preserveFields
}

// CreateMaskingService はログに応じたMaskingServiceを生成する
func (e *MaskingPolicyEngine) CreateMaskingService(log domain.Log) *MaskingService {
	rules, preserveFields := e.ResolveRules(log)
	return NewMaskingService(rules, preserveFields)
}

func (e *MaskingPolicyEngine) matchCondition(log domain.Log, cond MaskingPolicyCondition) bool {
	// LogType チェック
	if len(cond.LogTypes) > 0 {
		found := false
		for _, lt := range cond.LogTypes {
			if log.Type == lt {
				found = true
				break
			}
		}
		if !found {
			return false
		}
	}

	// Origin チェック
	if len(cond.Origins) > 0 {
		found := false
		for _, o := range cond.Origins {
			if log.Origin == o {
				found = true
				break
			}
		}
		if !found {
			return false
		}
	}

	// Level範囲チェック
	if cond.MinLevel > 0 && log.Level < cond.MinLevel {
		return false
	}
	if cond.MaxLevel > 0 && log.Level > cond.MaxLevel {
		return false
	}

	return true
}
