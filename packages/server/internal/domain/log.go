package domain

import "time"

// LogType ログ種別
type LogType string

const (
	LogTypeBusinessAudit LogType = "BUSINESS-AUDIT"
	LogTypeSecurity      LogType = "SECURITY"
	LogTypeCompliance    LogType = "COMPLIANCE"
	LogTypeInfra         LogType = "INFRA"
	LogTypeSystem        LogType = "SYSTEM"
	LogTypeSLA           LogType = "SLA"
	LogTypeDebug         LogType = "DEBUG"
)

// LogLevel ログレベル (1=最低, 6=最高)
type LogLevel int

const (
	LogLevelTrace    LogLevel = 1
	LogLevelDebug    LogLevel = 2
	LogLevelInfo     LogLevel = 3
	LogLevelWarn     LogLevel = 4
	LogLevelError    LogLevel = 5
	LogLevelCritical LogLevel = 6
)

// Origin ログの発生源
type Origin string

const (
	OriginSystem  Origin = "SYSTEM"
	OriginAIAgent Origin = "AI_AGENT"
)

// LogTag キーカテゴリペア
type LogTag struct {
	Key      string
	Category string
}

// AIContext はAIエージェント実行コンテキスト
type AIContext struct {
	AgentID        string
	TaskID         string
	LoopDepth      int
	Model          string
	Confidence     float64
	ReasoningTrace string
}

// AgentBackLogEntry はAIエージェント実行履歴
type AgentBackLogEntry struct {
	AgentID   string
	Action    string
	Timestamp time.Time
	Result    string
	Status    string // "pending", "success", "failed"
}

// Log ドメインモデル
type Log struct {
	TraceID      string
	SpanID       string
	ParentSpanID string
	ActorID      string
	Type         LogType
	Level        LogLevel
	Timestamp    time.Time
	LogicalClock int64
	Boundary     string
	ServiceID    string
	Origin       Origin
	IsCritical   bool
	Message      string
	Tags         []LogTag
	ResourceIDs  []string
	PreviousHash string
	Hash         string
	Signature    string
	// v2: AI agent integration
	AIContext    *AIContext
	AgentBackLog []AgentBackLogEntry
	Input        string
	TriggerAgent bool
	Details      map[string]string
}

// ValidLogTypes 有効なログ種別一覧
var ValidLogTypes = map[LogType]bool{
	LogTypeBusinessAudit: true,
	LogTypeSecurity:      true,
	LogTypeCompliance:    true,
	LogTypeInfra:         true,
	LogTypeSystem:        true,
	LogTypeSLA:           true,
	LogTypeDebug:         true,
}

// IsValidLogType ログ種別の検証
func IsValidLogType(t LogType) bool {
	return ValidLogTypes[t]
}

// IsValidLogLevel ログレベルの検証
func IsValidLogLevel(l LogLevel) bool {
	return l >= 1 && l <= 6
}

// IsValidOrigin オリジンの検証
func IsValidOrigin(o Origin) bool {
	return o == OriginSystem || o == OriginAIAgent
}

// --- Log ドメインメソッド ---

// IP はタグからIPアドレスを取得する。見つからなければデフォルト値を返す。
func (l Log) IP(defaultVal string) string {
	for _, tag := range l.Tags {
		if tag.Key == "ip" {
			return tag.Category
		}
	}
	return defaultVal
}

// FirstResourceID は最初のリソースIDを返す。なければデフォルト値を返す。
func (l Log) FirstResourceID(defaultVal string) string {
	if len(l.ResourceIDs) > 0 {
		return l.ResourceIDs[0]
	}
	return defaultVal
}

// ActorOrDefault はActorIDを返す。空ならデフォルト値を返す。
func (l Log) ActorOrDefault(defaultVal string) string {
	if l.ActorID != "" {
		return l.ActorID
	}
	return defaultVal
}
