package store

import (
	"context"
	"time"

	"github.com/schro-cat-dev/sentinel-server/internal/domain"
)

// TaskFilter はタスク検索条件
type TaskFilter struct {
	EventName string
	Status    string
	FromTime  *time.Time
	ToTime    *time.Time
	Limit     int
	Offset    int
}

// Store は永続化層の抽象インターフェース
type Store interface {
	// --- Logs (immutable) ---
	InsertLog(ctx context.Context, log domain.Log) (int64, error)
	GetLogByTraceID(ctx context.Context, traceID string) (*domain.Log, error)

	// --- Tasks ---
	InsertTask(ctx context.Context, task domain.GeneratedTask, status domain.TaskDispatchStatus) error
	GetTask(ctx context.Context, taskID string) (*domain.StoredTask, error)
	ListTasks(ctx context.Context, filter TaskFilter) ([]domain.StoredTask, int, error)
	UpdateTaskStatus(ctx context.Context, taskID string, status domain.TaskDispatchStatus, errMsg string) error

	// --- Approvals (multi-step) ---
	InsertApproval(ctx context.Context, approval domain.ApprovalRequest) error
	GetApprovalByTaskID(ctx context.Context, taskID string) (*domain.ApprovalRequest, error)
	UpdateApprovalStep(ctx context.Context, approvalID string, currentStep int, status string) error
	ResolveApproval(ctx context.Context, approvalID string, status string, resolverID string, reason string) error

	// --- Approval Step Records (append-only audit trail) ---
	InsertApprovalStepRecord(ctx context.Context, record domain.ApprovalStepRecord) error
	GetApprovalStepRecords(ctx context.Context, approvalID string) ([]domain.ApprovalStepRecord, error)

	// --- Task Modifications (append-only audit trail) ---
	InsertTaskModification(ctx context.Context, mod domain.TaskModification) error
	GetTaskModifications(ctx context.Context, taskID string) ([]domain.TaskModification, error)

	// --- Task Results (append-only) ---
	InsertTaskResult(ctx context.Context, result domain.TaskResult) error

	// --- Threat Responses (append-only audit trail) ---
	InsertThreatResponse(ctx context.Context, record domain.ThreatResponseStoreRecord) error
	GetThreatResponsesByTraceID(ctx context.Context, traceID string) ([]domain.ThreatResponseStoreRecord, error)

	// --- Pending Blocks (approval workflow) ---
	SavePendingBlock(ctx context.Context, block domain.PendingBlockRecord) error
	GetPendingBlock(ctx context.Context, blockID string) (*domain.PendingBlockRecord, error)
	UpdatePendingBlock(ctx context.Context, blockID, status, resolvedBy string) error
	ListPendingBlocks(ctx context.Context) ([]domain.PendingBlockRecord, error)

	// --- Transactions ---
	// WithTx はトランザクション内で複数操作を原子的に実行する（Store実装がサポートしない場合はfnを直接実行）
	WithTx(ctx context.Context, fn func(tx interface{}) error) error

	Close() error
}
