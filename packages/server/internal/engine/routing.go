package engine

import "github.com/schro-cat-dev/sentinel-server/internal/domain"

// FindRoutingRule はログレベルとイベント名に基づいて最適なルーティングルールを返す
// マッチしなければnil（デフォルト1ステップ承認にフォールバック）
func FindRoutingRule(rules []domain.ApprovalRoutingRule, level domain.LogLevel, eventName string) *domain.ApprovalRoutingRule {
	// 1. イベント名+レベルの完全マッチを優先
	for i, r := range rules {
		if r.EventName != "" && r.EventName == eventName && level >= r.MinLevel && level <= r.MaxLevel {
			return &rules[i]
		}
	}
	// 2. レベルのみでマッチ（イベント名なし=ワイルドカード）
	for i, r := range rules {
		if r.EventName == "" && level >= r.MinLevel && level <= r.MaxLevel {
			return &rules[i]
		}
	}
	return nil
}

// DefaultApprovalChain はルーティングルールがない場合のデフォルト（1ステップ）
func DefaultApprovalChain() []domain.ApprovalChainStep {
	return []domain.ApprovalChainStep{
		{StepOrder: 1, Role: "approver", Required: true},
	}
}
