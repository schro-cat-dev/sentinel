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
	EventName SystemEventName
	Priority  DetectionPriority
	Payload   EventPayload
}
