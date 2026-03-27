package domain

import "time"

// TaskActionType タスクアクション種別
type TaskActionType string

const (
	ActionAIAnalyze          TaskActionType = "AI_ANALYZE"
	ActionAutomatedRemediate TaskActionType = "AUTOMATED_REMEDIATE"
	ActionSystemNotification TaskActionType = "SYSTEM_NOTIFICATION"
	ActionExternalWebhook    TaskActionType = "EXTERNAL_WEBHOOK"
	ActionKillSwitch         TaskActionType = "KILL_SWITCH"
	ActionEscalate           TaskActionType = "ESCALATE"
)

// TaskSeverity 重大度
type TaskSeverity string

const (
	SeverityCritical TaskSeverity = "CRITICAL"
	SeverityHigh     TaskSeverity = "HIGH"
	SeverityMedium   TaskSeverity = "MEDIUM"
	SeverityLow      TaskSeverity = "LOW"
	SeverityInfo     TaskSeverity = "INFO"
)

// TaskExecutionLevel 実行レベル
type TaskExecutionLevel string

const (
	ExecLevelAuto     TaskExecutionLevel = "AUTO"
	ExecLevelSemiAuto TaskExecutionLevel = "SEMI_AUTO"
	ExecLevelManual   TaskExecutionLevel = "MANUAL"
	ExecLevelMonitor  TaskExecutionLevel = "MONITOR"
)

// TaskPriority 優先度 (1=最高, 5=最低)
type TaskPriority int

// TaskDispatchStatus ディスパッチ結果
type TaskDispatchStatus string

const (
	StatusPending         TaskDispatchStatus = "pending"
	StatusDispatched      TaskDispatchStatus = "dispatched"
	StatusBlockedApproval TaskDispatchStatus = "blocked_approval"
	StatusApproved        TaskDispatchStatus = "approved"
	StatusRejected        TaskDispatchStatus = "rejected"
	StatusCompleted       TaskDispatchStatus = "completed"
	StatusSkipped         TaskDispatchStatus = "skipped"
	StatusFailed          TaskDispatchStatus = "failed"
)

// TaskRule タスク生成ルール
type TaskRule struct {
	RuleID         string
	EventName      string
	Severity       TaskSeverity
	ActionType     TaskActionType
	ExecutionLevel TaskExecutionLevel
	Priority       TaskPriority
	Description    string
	ExecParams     ExecParams
	Guardrails     Guardrails
}

// ExecParams 実行パラメータ
type ExecParams struct {
	TargetEndpoint      string
	ScriptIdentifier    string
	NotificationChannel string
	PromptTemplate      string
}

// Guardrails ガードレール
type Guardrails struct {
	RequireHumanApproval bool
	TimeoutMs            int
	MaxRetries           int
}

// GeneratedTask 生成されたタスク
type GeneratedTask struct {
	TaskID         string
	RuleID         string
	EventName      string
	Severity       TaskSeverity
	ActionType     TaskActionType
	ExecutionLevel TaskExecutionLevel
	Priority       TaskPriority
	Description    string
	ExecParams     ExecParams
	Guardrails     Guardrails
	SourceLog      SourceLogInfo
	CreatedAt      time.Time
}

// SourceLogInfo タスクの元になったログ情報
type SourceLogInfo struct {
	TraceID   string
	Message   string
	Boundary  string
	Level     LogLevel
	Timestamp time.Time
}

// TaskResult タスク実行結果
type TaskResult struct {
	TaskID       string
	RuleID       string
	Status       TaskDispatchStatus
	DispatchedAt time.Time
	Error        string
}

// StoredTask はDB永続化されたタスク（ステータス管理付き）
type StoredTask struct {
	GeneratedTask
	Status       TaskDispatchStatus
	ErrorMessage string
	UpdatedAt    time.Time
}

// SeverityOrder 重大度の比較用序列
var SeverityOrder = map[TaskSeverity]int{
	SeverityInfo:     0,
	SeverityLow:      1,
	SeverityMedium:   2,
	SeverityHigh:     3,
	SeverityCritical: 4,
}

// SeverityGTE severity a >= b か判定
func SeverityGTE(actual, threshold TaskSeverity) bool {
	return SeverityOrder[actual] >= SeverityOrder[threshold]
}
