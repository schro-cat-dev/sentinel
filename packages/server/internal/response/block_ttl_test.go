package response

import (
	"context"
	"testing"
	"time"
)

func TestIPBlockAction_TTL(t *testing.T) {
	action := NewIPBlockActionWithTTL(100 * time.Millisecond)
	action.Execute(context.Background(), ThreatTarget{IP: "10.0.0.1"})

	if !action.IsBlocked("10.0.0.1") {
		t.Error("should be blocked immediately")
	}

	time.Sleep(150 * time.Millisecond)

	if action.IsBlocked("10.0.0.1") {
		t.Error("should expire after TTL")
	}
}

func TestIPBlockAction_TTL_CountExcludesExpired(t *testing.T) {
	action := NewIPBlockActionWithTTL(100 * time.Millisecond)
	action.Execute(context.Background(), ThreatTarget{IP: "10.0.0.1"})
	action.Execute(context.Background(), ThreatTarget{IP: "10.0.0.2"})

	if action.BlockedCount() != 2 {
		t.Errorf("expected 2, got %d", action.BlockedCount())
	}

	time.Sleep(150 * time.Millisecond)

	if action.BlockedCount() != 0 {
		t.Errorf("expected 0 after TTL, got %d", action.BlockedCount())
	}
}

func TestIPBlockAction_NoTTL(t *testing.T) {
	action := NewIPBlockAction() // TTL=0 → permanent
	action.Execute(context.Background(), ThreatTarget{IP: "10.0.0.1"})

	time.Sleep(50 * time.Millisecond)

	if !action.IsBlocked("10.0.0.1") {
		t.Error("permanent block should not expire")
	}
}

func TestIPBlockAction_Unblock(t *testing.T) {
	action := NewIPBlockAction()
	action.Execute(context.Background(), ThreatTarget{IP: "10.0.0.1"})

	if !action.IsBlocked("10.0.0.1") {
		t.Error("should be blocked")
	}

	action.Unblock("10.0.0.1")

	if action.IsBlocked("10.0.0.1") {
		t.Error("should be unblocked")
	}
}

func TestEnhancedBlockDispatcher_ListPending(t *testing.T) {
	d := NewEnhancedBlockDispatcher(ExecModeRequireApproval, nil)
	d.Register(NewIPBlockAction())

	d.ExecuteWithMode(context.Background(), "b-1", "block_ip", ThreatTarget{IP: "1.1.1.1"}, "test1")
	d.ExecuteWithMode(context.Background(), "b-2", "block_ip", ThreatTarget{IP: "2.2.2.2"}, "test2")
	d.ExecuteWithMode(context.Background(), "b-3", "block_ip", ThreatTarget{IP: "3.3.3.3"}, "test3")

	pending := d.ListPending()
	if len(pending) != 3 {
		t.Errorf("expected 3 pending, got %d", len(pending))
	}

	// Approve one
	d.ApproveBlock(context.Background(), "b-1", "admin")
	pending = d.ListPending()
	if len(pending) != 2 {
		t.Errorf("expected 2 pending after approve, got %d", len(pending))
	}

	// Reject one
	d.RejectBlock(context.Background(), "b-2", "admin")
	pending = d.ListPending()
	if len(pending) != 1 {
		t.Errorf("expected 1 pending after reject, got %d", len(pending))
	}
}
