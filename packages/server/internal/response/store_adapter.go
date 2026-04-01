package response

import (
	"context"
	"database/sql"
	"errors"
	"time"

	"github.com/schro-cat-dev/sentinel-server/internal/domain"
)

// DomainStoreAdapter はdomain.PendingBlockRecord ベースのストアを
// response.BlockApprovalStore インターフェースに適合させるアダプタ。
type DomainStoreAdapter struct {
	store DomainBlockStore
}

// DomainBlockStore はSQLiteStoreのpending block操作インターフェース
type DomainBlockStore interface {
	SavePendingBlock(ctx context.Context, block domain.PendingBlockRecord) error
	GetPendingBlock(ctx context.Context, blockID string) (*domain.PendingBlockRecord, error)
	UpdatePendingBlock(ctx context.Context, blockID, status, resolvedBy string) error
	ListPendingBlocks(ctx context.Context) ([]domain.PendingBlockRecord, error)
}

// NewDomainStoreAdapter はアダプタを生成する
func NewDomainStoreAdapter(store DomainBlockStore) *DomainStoreAdapter {
	return &DomainStoreAdapter{store: store}
}

func (a *DomainStoreAdapter) SavePendingBlock(ctx context.Context, block PendingBlock) error {
	record := domain.PendingBlockRecord{
		BlockID:      block.BlockID,
		ActionType:   block.ActionType,
		TargetIP:     block.Target.IP,
		TargetUserID: block.Target.UserID,
		Boundary:     block.Target.Boundary,
		Reason:       block.Reason,
		Status:       block.Status,
		CreatedAt:    block.CreatedAt.Format(time.RFC3339),
	}
	return a.store.SavePendingBlock(ctx, record)
}

func (a *DomainStoreAdapter) GetPendingBlock(ctx context.Context, blockID string) (*PendingBlock, error) {
	record, err := a.store.GetPendingBlock(ctx, blockID)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, nil // not found
		}
		return nil, err
	}
	if record == nil {
		return nil, nil
	}
	createdAt, _ := time.Parse(time.RFC3339, record.CreatedAt)
	var resolvedAt *time.Time
	if record.ResolvedAt != "" {
		t, _ := time.Parse(time.RFC3339, record.ResolvedAt)
		resolvedAt = &t
	}
	return &PendingBlock{
		BlockID:    record.BlockID,
		ActionType: record.ActionType,
		Target: ThreatTarget{
			IP:       record.TargetIP,
			UserID:   record.TargetUserID,
			Boundary: record.Boundary,
		},
		Reason:     record.Reason,
		Status:     record.Status,
		ResolvedBy: record.ResolvedBy,
		ResolvedAt: resolvedAt,
		CreatedAt:  createdAt,
	}, nil
}

func (a *DomainStoreAdapter) UpdatePendingBlock(ctx context.Context, blockID, status, resolvedBy string) error {
	return a.store.UpdatePendingBlock(ctx, blockID, status, resolvedBy)
}

func (a *DomainStoreAdapter) ListPendingBlocks(ctx context.Context) ([]PendingBlock, error) {
	records, err := a.store.ListPendingBlocks(ctx)
	if err != nil {
		return nil, err
	}
	var blocks []PendingBlock
	for _, r := range records {
		createdAt, _ := time.Parse(time.RFC3339, r.CreatedAt)
		blocks = append(blocks, PendingBlock{
			BlockID:    r.BlockID,
			ActionType: r.ActionType,
			Target: ThreatTarget{
				IP:       r.TargetIP,
				UserID:   r.TargetUserID,
				Boundary: r.Boundary,
			},
			Reason:    r.Reason,
			Status:    r.Status,
			CreatedAt: createdAt,
		})
	}
	return blocks, nil
}
