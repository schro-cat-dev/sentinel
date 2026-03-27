package domain

import (
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"time"
)

// --- 承認チェーン ---

// ApprovalChainStep は承認チェーンの1ステップ
type ApprovalChainStep struct {
	StepOrder  int    // 1, 2, 3... (昇順で承認)
	Role       string // 承認者のロール (e.g., "team_lead", "manager", "security_officer")
	TeamID     string // 承認チーム (e.g., "security-team", "legal-team")
	Required   bool   // このステップが必須か
}

// ApprovalRoutingRule はセキュリティレベル/イベント種別に応じた承認ルーティングルール
type ApprovalRoutingRule struct {
	RuleID        string
	MinLevel      LogLevel        // このルールが適用される最低ログレベル
	MaxLevel      LogLevel        // このルールが適用される最高ログレベル
	EventName     string          // 特定イベントに限定 (空なら全イベント)
	Severity      TaskSeverity    // 特定severity (空なら全severity)
	Chain         []ApprovalChainStep // 承認チェーン（順序付き）
	NotifyTargets []NotifyTarget  // 通知先
}

// NotifyTarget は通知先
type NotifyTarget struct {
	Type    string // "webhook", "email", "slack"
	Target  string // URL, メールアドレス, Slackチャンネル
	Role    string // 対象ロール
}

// --- 承認リクエスト（多段階対応） ---

// ApprovalRequest は承認リクエスト（改ざん検証 + 多段階対応）
type ApprovalRequest struct {
	ApprovalID    string
	TaskID        string
	RequestedAt   time.Time
	Status        string // "pending", "in_review", "approved", "rejected", "revision_requested"
	ContentHash   string // タスク内容のハッシュ（改ざん検証用）
	CurrentStep   int    // 現在の承認ステップ (1-based)
	TotalSteps    int    // 総承認ステップ数
	ResolvedAt    *time.Time
}

// ApprovalStepRecord は各承認ステップの記録（不変、append-only）
type ApprovalStepRecord struct {
	RecordID    string
	ApprovalID  string
	StepOrder   int
	Action      string    // "approved", "rejected", "revision_requested", "comment"
	ActorID     string    // 承認/却下した人のID
	ActorRole   string    // 承認者のロール
	Reason      string    // 理由/コメント
	ContentHash string    // この時点でのタスク内容ハッシュ
	CreatedAt   time.Time
}

// TaskModification はタスク内容の修正履歴（不変、append-only）
type TaskModification struct {
	ModificationID string
	TaskID         string
	ModifiedBy     string // 修正者ID
	Field          string // 修正されたフィールド
	OldValue       string // 修正前の値
	NewValue       string // 修正後の値
	ContentHash    string // 修正後のコンテンツハッシュ
	CreatedAt      time.Time
}

// --- コンテンツハッシュ計算 ---

// ComputeTaskContentHash はタスク内容のSHA-256ハッシュを計算する
// 承認時と実行時でこのハッシュを比較し、改ざんを検知する
func ComputeTaskContentHash(task GeneratedTask) string {
	data := map[string]interface{}{
		"task_id":         task.TaskID,
		"rule_id":         task.RuleID,
		"event_name":      task.EventName,
		"severity":        task.Severity,
		"action_type":     task.ActionType,
		"execution_level": task.ExecutionLevel,
		"description":     task.Description,
		"exec_params":     task.ExecParams,
		"source_trace_id": task.SourceLog.TraceID,
		"source_message":  task.SourceLog.Message,
	}
	b, _ := json.Marshal(data)
	h := sha256.Sum256(b)
	return fmt.Sprintf("%x", h)
}
