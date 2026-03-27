package response

import (
	"context"
	"testing"
	"time"
)

func TestEnhancedBlockDispatcher_ImmediateMode(t *testing.T) {
	d := NewEnhancedBlockDispatcher(ExecModeImmediate, nil)
	d.Register(NewIPBlockAction())

	result, pending, err := d.ExecuteWithMode(
		context.Background(), "block-001", "block_ip",
		ThreatTarget{IP: "10.0.0.1"}, "brute force",
	)
	if err != nil {
		t.Fatalf("error: %v", err)
	}
	if pending != nil {
		t.Error("immediate mode should not create pending block")
	}
	if !result.Success {
		t.Error("expected success")
	}
	if result.Target != "10.0.0.1" {
		t.Errorf("expected 10.0.0.1, got %s", result.Target)
	}
}

func TestEnhancedBlockDispatcher_ApprovalMode(t *testing.T) {
	d := NewEnhancedBlockDispatcher(ExecModeRequireApproval, nil)
	d.Register(NewIPBlockAction())

	result, pending, err := d.ExecuteWithMode(
		context.Background(), "block-002", "block_ip",
		ThreatTarget{IP: "10.0.0.2"}, "suspicious activity",
	)
	if err != nil {
		t.Fatalf("error: %v", err)
	}
	if pending == nil {
		t.Fatal("approval mode should create pending block")
	}
	if pending.Status != "pending" {
		t.Errorf("expected pending, got %s", pending.Status)
	}
	if pending.BlockID != "block-002" {
		t.Errorf("expected block-002, got %s", pending.BlockID)
	}
	if !result.Success {
		// In approval mode, block is NOT executed yet
	}
	if d.PendingCount() != 1 {
		t.Errorf("expected 1 pending, got %d", d.PendingCount())
	}
}

func TestEnhancedBlockDispatcher_ApproveBlock(t *testing.T) {
	d := NewEnhancedBlockDispatcher(ExecModeRequireApproval, nil)
	ipBlock := NewIPBlockAction()
	d.Register(ipBlock)

	// Create pending block
	d.ExecuteWithMode(
		context.Background(), "block-003", "block_ip",
		ThreatTarget{IP: "10.0.0.3"}, "attack",
	)

	// IP should NOT be blocked yet
	if ipBlock.IsBlocked("10.0.0.3") {
		t.Error("IP should not be blocked before approval")
	}

	// Approve
	result, err := d.ApproveBlock(context.Background(), "block-003", "admin-1")
	if err != nil {
		t.Fatalf("approve error: %v", err)
	}
	if !result.Success {
		t.Error("block should succeed after approval")
	}

	// Now IP should be blocked
	if !ipBlock.IsBlocked("10.0.0.3") {
		t.Error("IP should be blocked after approval")
	}

	// Pending block should be resolved
	pending, ok := d.GetPendingBlock("block-003")
	if !ok {
		t.Fatal("pending block should still exist")
	}
	if pending.Status != "approved" {
		t.Errorf("expected approved, got %s", pending.Status)
	}
	if pending.ResolvedBy != "admin-1" {
		t.Errorf("expected admin-1, got %s", pending.ResolvedBy)
	}
}

func TestEnhancedBlockDispatcher_RejectBlock(t *testing.T) {
	d := NewEnhancedBlockDispatcher(ExecModeRequireApproval, nil)
	d.Register(NewIPBlockAction())

	d.ExecuteWithMode(
		context.Background(), "block-004", "block_ip",
		ThreatTarget{IP: "10.0.0.4"}, "suspicious",
	)

	err := d.RejectBlock(context.Background(), "block-004", "reviewer-1")
	if err != nil {
		t.Fatalf("reject error: %v", err)
	}

	pending, _ := d.GetPendingBlock("block-004")
	if pending.Status != "rejected" {
		t.Errorf("expected rejected, got %s", pending.Status)
	}
	if pending.ResolvedBy != "reviewer-1" {
		t.Error("wrong resolver")
	}
}

func TestEnhancedBlockDispatcher_ApproveNonexistent(t *testing.T) {
	d := NewEnhancedBlockDispatcher(ExecModeRequireApproval, nil)
	_, err := d.ApproveBlock(context.Background(), "nonexistent", "admin")
	if err == nil {
		t.Error("expected error for nonexistent block")
	}
}

func TestEnhancedBlockDispatcher_DoubleApprove(t *testing.T) {
	d := NewEnhancedBlockDispatcher(ExecModeRequireApproval, nil)
	d.Register(NewIPBlockAction())

	d.ExecuteWithMode(context.Background(), "block-005", "block_ip",
		ThreatTarget{IP: "10.0.0.5"}, "attack")

	d.ApproveBlock(context.Background(), "block-005", "admin")

	// Second approve should fail
	_, err := d.ApproveBlock(context.Background(), "block-005", "admin")
	if err == nil {
		t.Error("double approve should fail")
	}
}

func TestEnhancedBlockDispatcher_RejectNonexistent(t *testing.T) {
	d := NewEnhancedBlockDispatcher(ExecModeRequireApproval, nil)
	err := d.RejectBlock(context.Background(), "nonexistent", "admin")
	if err == nil {
		t.Error("expected error")
	}
}

func TestEnhancedBlockDispatcher_Mode(t *testing.T) {
	d1 := NewEnhancedBlockDispatcher(ExecModeImmediate, nil)
	if d1.Mode() != ExecModeImmediate {
		t.Error("wrong mode")
	}

	d2 := NewEnhancedBlockDispatcher(ExecModeRequireApproval, nil)
	if d2.Mode() != ExecModeRequireApproval {
		t.Error("wrong mode")
	}
}

func TestEnhancedBlockDispatcher_PendingCount(t *testing.T) {
	d := NewEnhancedBlockDispatcher(ExecModeRequireApproval, nil)
	d.Register(NewIPBlockAction())

	for i := 0; i < 5; i++ {
		d.ExecuteWithMode(context.Background(),
			"block-"+string(rune('A'+i)), "block_ip",
			ThreatTarget{IP: "10.0.0." + string(rune('1'+i))}, "test")
	}

	if d.PendingCount() != 5 {
		t.Errorf("expected 5 pending, got %d", d.PendingCount())
	}

	// Approve one
	d.ApproveBlock(context.Background(), "block-A", "admin")
	if d.PendingCount() != 4 {
		t.Errorf("expected 4 pending after 1 approval, got %d", d.PendingCount())
	}

	// Reject one
	d.RejectBlock(context.Background(), "block-B", "admin")
	if d.PendingCount() != 3 {
		t.Errorf("expected 3 pending, got %d", d.PendingCount())
	}
}

// --- Cloud Provider Tests ---

func TestAWSBlockAction_WithFunc(t *testing.T) {
	action := NewAWSBlockAction(CloudBlockConfig{Provider: "aws", Region: "us-east-1"}, func(ctx context.Context, target ThreatTarget) (*BlockResult, error) {
		return &BlockResult{
			ActionType: "aws_block",
			Target:     target.IP,
			Success:    true,
			ExecutedAt: time.Now().UTC(),
		}, nil
	})

	if action.ActionType() != "aws_block" {
		t.Error("wrong action type")
	}

	result, err := action.Execute(context.Background(), ThreatTarget{IP: "1.2.3.4"})
	if err != nil {
		t.Fatalf("error: %v", err)
	}
	if !result.Success {
		t.Error("expected success")
	}
}

func TestAWSBlockAction_NoFunc(t *testing.T) {
	action := NewAWSBlockAction(CloudBlockConfig{Provider: "aws"}, nil)
	_, err := action.Execute(context.Background(), ThreatTarget{IP: "1.2.3.4"})
	if err == nil {
		t.Error("expected error without function")
	}
}

func TestGCPBlockAction_WithFunc(t *testing.T) {
	action := NewGCPBlockAction(CloudBlockConfig{Provider: "gcp", Region: "asia-northeast1"}, func(ctx context.Context, target ThreatTarget) (*BlockResult, error) {
		return &BlockResult{
			ActionType: "gcp_block",
			Target:     target.IP,
			Success:    true,
			ExecutedAt: time.Now().UTC(),
		}, nil
	})

	if action.ActionType() != "gcp_block" {
		t.Error("wrong action type")
	}

	result, _ := action.Execute(context.Background(), ThreatTarget{IP: "5.6.7.8"})
	if !result.Success {
		t.Error("expected success")
	}
}

func TestGCPBlockAction_NoFunc(t *testing.T) {
	action := NewGCPBlockAction(CloudBlockConfig{Provider: "gcp"}, nil)
	_, err := action.Execute(context.Background(), ThreatTarget{IP: "1.2.3.4"})
	if err == nil {
		t.Error("expected error")
	}
}

func TestAzureBlockAction_WithFunc(t *testing.T) {
	action := NewAzureBlockAction(CloudBlockConfig{Provider: "azure"}, func(ctx context.Context, target ThreatTarget) (*BlockResult, error) {
		return &BlockResult{
			ActionType: "azure_block",
			Target:     target.IP,
			Success:    true,
			ExecutedAt: time.Now().UTC(),
		}, nil
	})

	if action.ActionType() != "azure_block" {
		t.Error("wrong action type")
	}

	result, _ := action.Execute(context.Background(), ThreatTarget{IP: "9.10.11.12"})
	if !result.Success {
		t.Error("expected success")
	}
}

func TestAzureBlockAction_NoFunc(t *testing.T) {
	action := NewAzureBlockAction(CloudBlockConfig{Provider: "azure"}, nil)
	_, err := action.Execute(context.Background(), ThreatTarget{IP: "1.2.3.4"})
	if err == nil {
		t.Error("expected error")
	}
}

func TestCloudProviders_RegisterInDispatcher(t *testing.T) {
	d := NewEnhancedBlockDispatcher(ExecModeImmediate, nil)

	awsAction := NewAWSBlockAction(CloudBlockConfig{}, func(ctx context.Context, target ThreatTarget) (*BlockResult, error) {
		return &BlockResult{ActionType: "aws_block", Target: target.IP, Success: true, ExecutedAt: time.Now().UTC()}, nil
	})
	gcpAction := NewGCPBlockAction(CloudBlockConfig{}, func(ctx context.Context, target ThreatTarget) (*BlockResult, error) {
		return &BlockResult{ActionType: "gcp_block", Target: target.IP, Success: true, ExecutedAt: time.Now().UTC()}, nil
	})

	d.Register(awsAction)
	d.Register(gcpAction)
	d.Register(NewIPBlockAction())

	// AWS block
	result, _, err := d.ExecuteWithMode(context.Background(), "b1", "aws_block", ThreatTarget{IP: "1.1.1.1"}, "test")
	if err != nil {
		t.Fatalf("AWS: %v", err)
	}
	if !result.Success {
		t.Error("AWS should succeed")
	}

	// GCP block
	result, _, err = d.ExecuteWithMode(context.Background(), "b2", "gcp_block", ThreatTarget{IP: "2.2.2.2"}, "test")
	if err != nil {
		t.Fatalf("GCP: %v", err)
	}
	if !result.Success {
		t.Error("GCP should succeed")
	}

	// IP block (standard)
	result, _, err = d.ExecuteWithMode(context.Background(), "b3", "block_ip", ThreatTarget{IP: "3.3.3.3"}, "test")
	if err != nil {
		t.Fatalf("IP: %v", err)
	}
	if !result.Success {
		t.Error("IP block should succeed")
	}
}
