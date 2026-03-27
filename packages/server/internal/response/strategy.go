package response

import (
	"time"

	"github.com/schro-cat-dev/sentinel-server/internal/domain"
)

// ResponseStrategy はレスポンス戦略
type ResponseStrategy string

const (
	StrategyBlockAndNotify   ResponseStrategy = "BLOCK_AND_NOTIFY"
	StrategyAnalyzeAndNotify ResponseStrategy = "ANALYZE_AND_NOTIFY"
	StrategyNotifyOnly       ResponseStrategy = "NOTIFY_ONLY"
	StrategyBlockOnly        ResponseStrategy = "BLOCK_ONLY"
	StrategyMonitor          ResponseStrategy = "MONITOR"
)

// ThreatTarget は脅威対象の情報
type ThreatTarget struct {
	IP         string // 攻撃元IP
	UserID     string // 対象ユーザー
	Boundary   string // 影響を受けたサービス境界
	MetricKey  string // 異常検知のメトリクスキー
	ResourceID string // 対象リソースID
}

// BlockResult はブロック実行結果
type BlockResult struct {
	ActionType string    // "block_ip", "lock_account", "revoke_token"
	Target     string    // ブロック対象
	Success    bool      // 成功したか
	Error      string    // エラー（失敗時）
	ExecutedAt time.Time // 実行日時
}

// AnalysisResult はAI分析結果
type AnalysisResult struct {
	Summary     string  // 分析サマリー
	RiskLevel   string  // "critical", "high", "medium", "low"
	Confidence  float64 // 信頼度 (0.0-1.0)
	Indicators  []string // 検出された脅威インジケータ
	Recommended string  // 推奨アクション
	Model       string  // 使用モデル
	TokensUsed  int     // 消費トークン数
	AnalyzedAt  time.Time
	Error       string // エラー（失敗時）
}

// ThreatResponseRecord は脅威レスポンスの完全記録（永続化用）
type ThreatResponseRecord struct {
	ResponseID   string
	TraceID      string
	EventName    domain.SystemEventName
	Strategy     ResponseStrategy
	Target       ThreatTarget
	Analysis     *AnalysisResult // nullable
	Block        *BlockResult    // nullable
	Notified     bool
	NotifyTarget string
	CreatedAt    time.Time
}

// ResponseRuleConfig はイベント種別ごとのレスポンスルール設定
type ResponseRuleConfig struct {
	EventName      string           `json:"event_name"`       // マッチするイベント名（空=デフォルト）
	Strategy       ResponseStrategy `json:"strategy"`
	BlockAction    string           `json:"block_action"`     // "block_ip", "lock_account"
	AnalysisPrompt string           `json:"analysis_prompt"`  // AI分析のプロンプトテンプレート
	NotifyTargets  []string         `json:"notify_targets"`   // 通知先
	MinPriority    string           `json:"min_priority"`     // 最低優先度 ("HIGH", "MEDIUM", "LOW")
}

// ThreatResponseConfig は脅威レスポンスの全体設定
type ThreatResponseConfig struct {
	Enabled         bool                 `json:"enabled"`
	DefaultStrategy ResponseStrategy     `json:"default_strategy"`
	Rules           []ResponseRuleConfig `json:"rules"`
}

// DefaultThreatResponseConfig はデフォルト設定を返す
func DefaultThreatResponseConfig() ThreatResponseConfig {
	return ThreatResponseConfig{
		Enabled:         false,
		DefaultStrategy: StrategyNotifyOnly,
	}
}

// FindResponseRule はイベント名に対応するルールを探す
func FindResponseRule(cfg ThreatResponseConfig, eventName domain.SystemEventName, priority domain.DetectionPriority) *ResponseRuleConfig {
	for i, rule := range cfg.Rules {
		if rule.EventName == string(eventName) {
			if rule.MinPriority != "" && !priorityGTE(priority, domain.DetectionPriority(rule.MinPriority)) {
				continue
			}
			return &cfg.Rules[i]
		}
	}
	// ワイルドカード（EventName空）
	for i, rule := range cfg.Rules {
		if rule.EventName == "" {
			return &cfg.Rules[i]
		}
	}
	return nil
}

func priorityGTE(actual, threshold domain.DetectionPriority) bool {
	order := map[domain.DetectionPriority]int{
		domain.PriorityLow:    0,
		domain.PriorityMedium: 1,
		domain.PriorityHigh:   2,
	}
	return order[actual] >= order[threshold]
}

// ExtractThreatTarget は検知結果とログから脅威対象を抽出する
func ExtractThreatTarget(det *domain.DetectionResult, log domain.Log) ThreatTarget {
	target := ThreatTarget{
		Boundary: log.Boundary,
		UserID:   log.ActorOrDefault(""),
	}

	switch p := det.Payload.(type) {
	case domain.SecurityIntrusionPayload:
		target.IP = p.IP
	case domain.AnomalyPayload:
		target.MetricKey = p.MetricKey
	case domain.ComplianceViolationPayload:
		target.UserID = p.UserID
		target.ResourceID = p.DocumentID
	}

	// タグからIPを補完
	if target.IP == "" || target.IP == "0.0.0.0" {
		target.IP = log.IP("")
	}

	return target
}
