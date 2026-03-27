package domain

// SystemEventName 検知可能なイベント名
type SystemEventName string

const (
	EventSecurityIntrusion     SystemEventName = "SECURITY_INTRUSION_DETECTED"
	EventComplianceViolation   SystemEventName = "COMPLIANCE_VIOLATION"
	EventSystemCriticalFailure SystemEventName = "SYSTEM_CRITICAL_FAILURE"
	EventAIActionRequired      SystemEventName = "AI_ACTION_REQUIRED"
)

// DetectionPriority 検知優先度
type DetectionPriority string

const (
	PriorityHigh   DetectionPriority = "HIGH"
	PriorityMedium DetectionPriority = "MEDIUM"
	PriorityLow    DetectionPriority = "LOW"
)

// EventPayload イベントごとの型付きペイロード（interface）
type EventPayload interface {
	eventPayloadMarker()
}

// SystemCriticalPayload SYSTEM_CRITICAL_FAILURE 用
type SystemCriticalPayload struct {
	Component    string
	ErrorDetails string
}

func (SystemCriticalPayload) eventPayloadMarker() {}

// SecurityIntrusionPayload SECURITY_INTRUSION_DETECTED 用
type SecurityIntrusionPayload struct {
	IP       string
	Severity int
}

func (SecurityIntrusionPayload) eventPayloadMarker() {}

// ComplianceViolationPayload COMPLIANCE_VIOLATION 用
type ComplianceViolationPayload struct {
	RuleID     string
	DocumentID string
	UserID     string
}

func (ComplianceViolationPayload) eventPayloadMarker() {}

// DetectionResult イベント検知結果
type DetectionResult struct {
	EventName  SystemEventName
	Priority   DetectionPriority
	Payload    EventPayload
	Score      float64 // 0.0〜1.0 の信頼度スコア（アンサンブル用）
	RuleID     string  // 発火したルールの識別子
	Suppressed bool    // 重複抑制でスキップされた場合true
}

// AnomalyPayload 統計的異常検知用ペイロード
type AnomalyPayload struct {
	MetricKey    string  // 異常を検知したメトリクスキー
	Baseline     float64 // ベースライン値
	Observed     float64 // 観測値
	DeviationPct float64 // 乖離率（%）
}

func (AnomalyPayload) eventPayloadMarker() {}

// EventAnomaly 統計的異常検知イベント名
const EventAnomaly SystemEventName = "ANOMALY_DETECTED"

// --- Ensemble types ---

// EnsembleResult はアンサンブル検知の集約結果
type EnsembleResult struct {
	Results        []*DetectionResult // 全発火ルールの結果
	AggregateScore float64            // 集約スコア
	TopResult      *DetectionResult   // 最高優先度の結果
}
