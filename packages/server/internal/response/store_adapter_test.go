package response

import (
	"context"
	"testing"
	"time"

	"fmt"

	"github.com/schro-cat-dev/sentinel-server/internal/store"
)

func newTestAdapter(t *testing.T) (*DomainStoreAdapter, *store.SQLiteStore) {
	t.Helper()
	st, err := store.NewSQLiteStore("file::memory:?_busy_timeout=5000")
	if err != nil {
		t.Fatal(err)
	}
	return NewDomainStoreAdapter(st), st
}

func TestStoreAdapter_SaveAndGet(t *testing.T) {
	adapter, _ := newTestAdapter(t)
	ctx := context.Background()

	block := PendingBlock{
		BlockID:    "block-1",
		ActionType: "block_ip",
		Target: ThreatTarget{
			IP:       "10.0.0.99",
			UserID:   "",
			Boundary: "auth-service",
		},
		Reason:    "brute force detected",
		Status:    "pending",
		CreatedAt: time.Now().UTC(),
	}

	if err := adapter.SavePendingBlock(ctx, block); err != nil {
		t.Fatalf("save failed: %v", err)
	}

	got, err := adapter.GetPendingBlock(ctx, "block-1")
	if err != nil {
		t.Fatalf("get failed: %v", err)
	}
	if got == nil {
		t.Fatal("expected non-nil block")
	}
	if got.BlockID != "block-1" {
		t.Errorf("expected block-1, got %s", got.BlockID)
	}
	if got.Target.IP != "10.0.0.99" {
		t.Errorf("expected IP 10.0.0.99, got %s", got.Target.IP)
	}
	if got.Reason != "brute force detected" {
		t.Errorf("expected reason preserved, got %s", got.Reason)
	}
	if got.Status != "pending" {
		t.Errorf("expected pending, got %s", got.Status)
	}
}

func TestStoreAdapter_Update(t *testing.T) {
	adapter, _ := newTestAdapter(t)
	ctx := context.Background()

	block := PendingBlock{
		BlockID:    "block-2",
		ActionType: "block_ip",
		Target:     ThreatTarget{IP: "10.0.0.1"},
		Reason:     "suspicious",
		Status:     "pending",
		CreatedAt:  time.Now().UTC(),
	}
	adapter.SavePendingBlock(ctx, block)

	if err := adapter.UpdatePendingBlock(ctx, "block-2", "approved", "admin-1"); err != nil {
		t.Fatalf("update failed: %v", err)
	}

	got, _ := adapter.GetPendingBlock(ctx, "block-2")
	if got.Status != "approved" {
		t.Errorf("expected approved, got %s", got.Status)
	}
	if got.ResolvedBy != "admin-1" {
		t.Errorf("expected admin-1, got %s", got.ResolvedBy)
	}
}

func TestStoreAdapter_List(t *testing.T) {
	adapter, _ := newTestAdapter(t)
	ctx := context.Background()

	for i := 0; i < 3; i++ {
		adapter.SavePendingBlock(ctx, PendingBlock{
			BlockID:    fmt.Sprintf("block-%d", i),
			ActionType: "block_ip",
			Target:     ThreatTarget{IP: "10.0.0.1"},
			Status:     "pending",
			CreatedAt:  time.Now().UTC(),
		})
	}

	blocks, err := adapter.ListPendingBlocks(ctx)
	if err != nil {
		t.Fatalf("list failed: %v", err)
	}
	if len(blocks) != 3 {
		t.Errorf("expected 3 blocks, got %d", len(blocks))
	}
}

func TestStoreAdapter_GetNonExistent(t *testing.T) {
	adapter, _ := newTestAdapter(t)
	ctx := context.Background()

	got, err := adapter.GetPendingBlock(ctx, "nonexistent")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got != nil {
		t.Error("expected nil for nonexistent block")
	}
}
