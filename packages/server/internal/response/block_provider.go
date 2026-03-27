package response

import (
	"context"
	"fmt"
	"sync"
	"time"
)

// BlockExecutionMode はブロック実行モード
type BlockExecutionMode string

const (
	// ExecModeImmediate は即座に実行する
	ExecModeImmediate BlockExecutionMode = "IMMEDIATE"
	// ExecModeRequireApproval はユーザー承認を待ってから実行する
	ExecModeRequireApproval BlockExecutionMode = "REQUIRE_APPROVAL"
)

// PendingBlock は承認待ちのブロックリクエスト
type PendingBlock struct {
	BlockID    string
	ActionType string
	Target     ThreatTarget
	Reason     string
	CreatedAt  time.Time
	Status     string // "pending", "approved", "rejected", "expired"
	ResolvedBy string
	ResolvedAt *time.Time
}

// BlockApprovalStore は承認待ちブロックの永続化インターフェース
type BlockApprovalStore interface {
	SavePendingBlock(ctx context.Context, block PendingBlock) error
	GetPendingBlock(ctx context.Context, blockID string) (*PendingBlock, error)
	UpdatePendingBlock(ctx context.Context, blockID, status, resolvedBy string) error
	ListPendingBlocks(ctx context.Context) ([]PendingBlock, error)
}

// EnhancedBlockDispatcher はBlockDispatcherの拡張版（承認待ち対応）
type EnhancedBlockDispatcher struct {
	*BlockDispatcher
	mode          BlockExecutionMode
	approvalStore BlockApprovalStore
	mu            sync.RWMutex
	pendingBlocks map[string]PendingBlock // in-memory fallback
}

// NewEnhancedBlockDispatcher はEnhancedBlockDispatcherを生成する
func NewEnhancedBlockDispatcher(mode BlockExecutionMode, store BlockApprovalStore) *EnhancedBlockDispatcher {
	return &EnhancedBlockDispatcher{
		BlockDispatcher: NewBlockDispatcher(),
		mode:            mode,
		approvalStore:   store,
		pendingBlocks:   make(map[string]PendingBlock),
	}
}

// ExecuteWithMode はモードに応じてブロックを実行する
func (d *EnhancedBlockDispatcher) ExecuteWithMode(ctx context.Context, blockID, actionType string, target ThreatTarget, reason string) (*BlockResult, *PendingBlock, error) {
	switch d.mode {
	case ExecModeImmediate:
		result, err := d.BlockDispatcher.Execute(ctx, actionType, target)
		return result, nil, err

	case ExecModeRequireApproval:
		pending := PendingBlock{
			BlockID:    blockID,
			ActionType: actionType,
			Target:     target,
			Reason:     reason,
			CreatedAt:  time.Now().UTC(),
			Status:     "pending",
		}

		if d.approvalStore != nil {
			if err := d.approvalStore.SavePendingBlock(ctx, pending); err != nil {
				return nil, nil, fmt.Errorf("save pending block: %w", err)
			}
		}

		d.mu.Lock()
		d.pendingBlocks[blockID] = pending
		d.mu.Unlock()

		return &BlockResult{
			ActionType: actionType,
			Target:     target.IP,
			Success:    false,
			Error:      "awaiting approval",
			ExecutedAt: time.Now().UTC(),
		}, &pending, nil

	default:
		return nil, nil, fmt.Errorf("unknown block mode: %s", d.mode)
	}
}

// ApproveBlock は承認待ちブロックを承認し実行する
func (d *EnhancedBlockDispatcher) ApproveBlock(ctx context.Context, blockID, approverID string) (*BlockResult, error) {
	d.mu.Lock()
	pending, ok := d.pendingBlocks[blockID]
	if !ok {
		d.mu.Unlock()
		return nil, fmt.Errorf("pending block not found: %s", blockID)
	}
	if pending.Status != "pending" {
		d.mu.Unlock()
		return nil, fmt.Errorf("block %s already resolved: %s", blockID, pending.Status)
	}
	now := time.Now().UTC()
	pending.Status = "approved"
	pending.ResolvedBy = approverID
	pending.ResolvedAt = &now
	d.pendingBlocks[blockID] = pending
	d.mu.Unlock()

	if d.approvalStore != nil {
		d.approvalStore.UpdatePendingBlock(ctx, blockID, "approved", approverID)
	}

	return d.BlockDispatcher.Execute(ctx, pending.ActionType, pending.Target)
}

// RejectBlock は承認待ちブロックを却下する
func (d *EnhancedBlockDispatcher) RejectBlock(ctx context.Context, blockID, rejecterID string) error {
	d.mu.Lock()
	pending, ok := d.pendingBlocks[blockID]
	if !ok {
		d.mu.Unlock()
		return fmt.Errorf("pending block not found: %s", blockID)
	}
	now := time.Now().UTC()
	pending.Status = "rejected"
	pending.ResolvedBy = rejecterID
	pending.ResolvedAt = &now
	d.pendingBlocks[blockID] = pending
	d.mu.Unlock()

	if d.approvalStore != nil {
		d.approvalStore.UpdatePendingBlock(ctx, blockID, "rejected", rejecterID)
	}
	return nil
}

// GetPendingBlock は承認待ちブロックを取得する
func (d *EnhancedBlockDispatcher) GetPendingBlock(blockID string) (PendingBlock, bool) {
	d.mu.RLock()
	defer d.mu.RUnlock()
	p, ok := d.pendingBlocks[blockID]
	return p, ok
}

// PendingCount は承認待ち数を返す
func (d *EnhancedBlockDispatcher) PendingCount() int {
	d.mu.RLock()
	defer d.mu.RUnlock()
	count := 0
	for _, p := range d.pendingBlocks {
		if p.Status == "pending" {
			count++
		}
	}
	return count
}

// Mode は現在の実行モードを返す
func (d *EnhancedBlockDispatcher) Mode() BlockExecutionMode {
	return d.mode
}

// ListPending は全承認待ちブロックを返す
func (d *EnhancedBlockDispatcher) ListPending() []PendingBlock {
	d.mu.RLock()
	defer d.mu.RUnlock()
	var result []PendingBlock
	for _, p := range d.pendingBlocks {
		if p.Status == "pending" {
			result = append(result, p)
		}
	}
	return result
}

// --- Cloud Provider Block Actions (Adapter Pattern) ---

// CloudBlockConfig はクラウドプロバイダブロックアクションの設定
type CloudBlockConfig struct {
	Provider    string // "aws", "gcp", "azure"
	Region      string
	Credentials string // 環境変数名 or パス
}

// AWSBlockAction はAWS Security Group / WAF / GuardDutyへのブロック委任
type AWSBlockAction struct {
	config  CloudBlockConfig
	execFn  func(ctx context.Context, target ThreatTarget) (*BlockResult, error)
}

func NewAWSBlockAction(cfg CloudBlockConfig, fn func(ctx context.Context, target ThreatTarget) (*BlockResult, error)) *AWSBlockAction {
	return &AWSBlockAction{config: cfg, execFn: fn}
}

func (a *AWSBlockAction) ActionType() string { return "aws_block" }

func (a *AWSBlockAction) Execute(ctx context.Context, target ThreatTarget) (*BlockResult, error) {
	if a.execFn != nil {
		return a.execFn(ctx, target)
	}
	return &BlockResult{
		ActionType: "aws_block",
		Target:     target.IP,
		Success:    false,
		Error:      "AWS block function not configured",
		ExecutedAt: time.Now().UTC(),
	}, fmt.Errorf("AWS block function not configured")
}

// GCPBlockAction はGCP Cloud Armor / VPC Firewall Rulesへのブロック委任
type GCPBlockAction struct {
	config CloudBlockConfig
	execFn func(ctx context.Context, target ThreatTarget) (*BlockResult, error)
}

func NewGCPBlockAction(cfg CloudBlockConfig, fn func(ctx context.Context, target ThreatTarget) (*BlockResult, error)) *GCPBlockAction {
	return &GCPBlockAction{config: cfg, execFn: fn}
}

func (g *GCPBlockAction) ActionType() string { return "gcp_block" }

func (g *GCPBlockAction) Execute(ctx context.Context, target ThreatTarget) (*BlockResult, error) {
	if g.execFn != nil {
		return g.execFn(ctx, target)
	}
	return &BlockResult{
		ActionType: "gcp_block",
		Target:     target.IP,
		Success:    false,
		Error:      "GCP block function not configured",
		ExecutedAt: time.Now().UTC(),
	}, fmt.Errorf("GCP block function not configured")
}

// AzureBlockAction はAzure NSG / WAFへのブロック委任
type AzureBlockAction struct {
	config CloudBlockConfig
	execFn func(ctx context.Context, target ThreatTarget) (*BlockResult, error)
}

func NewAzureBlockAction(cfg CloudBlockConfig, fn func(ctx context.Context, target ThreatTarget) (*BlockResult, error)) *AzureBlockAction {
	return &AzureBlockAction{config: cfg, execFn: fn}
}

func (a *AzureBlockAction) ActionType() string { return "azure_block" }

func (a *AzureBlockAction) Execute(ctx context.Context, target ThreatTarget) (*BlockResult, error) {
	if a.execFn != nil {
		return a.execFn(ctx, target)
	}
	return &BlockResult{
		ActionType: "azure_block",
		Target:     target.IP,
		Success:    false,
		Error:      "Azure block function not configured",
		ExecutedAt: time.Now().UTC(),
	}, fmt.Errorf("Azure block function not configured")
}
