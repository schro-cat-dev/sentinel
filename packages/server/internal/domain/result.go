package domain

// ThreatResponseSummary は脅威レスポンスの要約（IngestionResult用）
type ThreatResponseSummary struct {
	ResponseID string
	EventName  SystemEventName
	Strategy   string
	Blocked    bool
	BlockTarget string
	Analyzed   bool
	RiskLevel  string
	Notified   bool
}

// IngestionResult パイプライン処理結果
type IngestionResult struct {
	TraceID          string
	HashChainValid   bool
	Masked           bool
	TasksGenerated   []TaskResult
	ThreatResponses  []ThreatResponseSummary
}

// PendingBlockRecord は永続化用の承認待ちブロック記録
type PendingBlockRecord struct {
	BlockID      string
	ActionType   string
	TargetIP     string
	TargetUserID string
	Boundary     string
	Reason       string
	Status       string // "pending", "approved", "rejected"
	ResolvedBy   string
	ResolvedAt   string // RFC3339 or empty
	CreatedAt    string // RFC3339
}

// ThreatResponseStoreRecord は永続化用の脅威レスポンス記録
type ThreatResponseStoreRecord struct {
	ResponseID   string
	TraceID      string
	EventName    string
	Strategy     string
	TargetIP     string
	TargetUserID string
	Boundary     string
	BlockAction  string
	BlockSuccess bool
	BlockTarget  string
	Analyzed     bool
	RiskLevel    string
	Confidence   float64
	AnalysisSummary string
	Notified     bool
	NotifyTarget string
	CreatedAt    string // RFC3339
}
