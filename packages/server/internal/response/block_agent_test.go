package response

import (
	"context"
	"sync"
	"testing"
)

func TestIPBlockAction_Success(t *testing.T) {
	action := NewIPBlockAction()
	target := ThreatTarget{IP: "192.168.1.100"}

	result, err := action.Execute(context.Background(), target)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !result.Success {
		t.Error("expected success")
	}
	if result.Target != "192.168.1.100" {
		t.Errorf("expected 192.168.1.100, got %s", result.Target)
	}
	if result.ActionType != "block_ip" {
		t.Errorf("expected block_ip, got %s", result.ActionType)
	}
	if !action.IsBlocked("192.168.1.100") {
		t.Error("IP should be blocked")
	}
	if action.BlockedCount() != 1 {
		t.Errorf("expected 1 blocked, got %d", action.BlockedCount())
	}
}

func TestIPBlockAction_EmptyIP(t *testing.T) {
	action := NewIPBlockAction()
	_, err := action.Execute(context.Background(), ThreatTarget{IP: ""})
	if err == nil {
		t.Error("expected error for empty IP")
	}
}

func TestIPBlockAction_ZeroIP(t *testing.T) {
	action := NewIPBlockAction()
	_, err := action.Execute(context.Background(), ThreatTarget{IP: "0.0.0.0"})
	if err == nil {
		t.Error("expected error for 0.0.0.0")
	}
}

func TestIPBlockAction_CancelledContext(t *testing.T) {
	action := NewIPBlockAction()
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, err := action.Execute(ctx, ThreatTarget{IP: "10.0.0.1"})
	if err == nil {
		t.Error("expected error for cancelled context")
	}
}

func TestIPBlockAction_MultipleIPs(t *testing.T) {
	action := NewIPBlockAction()
	ips := []string{"10.0.0.1", "10.0.0.2", "10.0.0.3"}
	for _, ip := range ips {
		action.Execute(context.Background(), ThreatTarget{IP: ip})
	}
	if action.BlockedCount() != 3 {
		t.Errorf("expected 3, got %d", action.BlockedCount())
	}
	for _, ip := range ips {
		if !action.IsBlocked(ip) {
			t.Errorf("%s should be blocked", ip)
		}
	}
}

func TestIPBlockAction_ConcurrentSafety(t *testing.T) {
	action := NewIPBlockAction()
	var wg sync.WaitGroup
	for i := 0; i < 100; i++ {
		wg.Add(1)
		go func(n int) {
			defer wg.Done()
			ip := "10.0.0." + string(rune('1'+n%9))
			action.Execute(context.Background(), ThreatTarget{IP: ip})
		}(i)
	}
	wg.Wait()
	if action.BlockedCount() == 0 {
		t.Error("should have blocked IPs")
	}
}

func TestAccountLockAction_Success(t *testing.T) {
	action := NewAccountLockAction()
	target := ThreatTarget{UserID: "user-malicious"}

	result, err := action.Execute(context.Background(), target)
	if err != nil {
		t.Fatalf("error: %v", err)
	}
	if !result.Success {
		t.Error("expected success")
	}
	if result.ActionType != "lock_account" {
		t.Errorf("expected lock_account, got %s", result.ActionType)
	}
	if !action.IsLocked("user-malicious") {
		t.Error("user should be locked")
	}
}

func TestAccountLockAction_EmptyUserID(t *testing.T) {
	action := NewAccountLockAction()
	_, err := action.Execute(context.Background(), ThreatTarget{UserID: ""})
	if err == nil {
		t.Error("expected error for empty user ID")
	}
}

func TestBlockDispatcher_RegisterAndExecute(t *testing.T) {
	d := NewBlockDispatcher()
	ipBlock := NewIPBlockAction()
	acctLock := NewAccountLockAction()

	d.Register(ipBlock)
	d.Register(acctLock)

	t.Run("executes block_ip", func(t *testing.T) {
		result, err := d.Execute(context.Background(), "block_ip", ThreatTarget{IP: "1.2.3.4"})
		if err != nil {
			t.Fatalf("error: %v", err)
		}
		if !result.Success {
			t.Error("expected success")
		}
	})

	t.Run("executes lock_account", func(t *testing.T) {
		result, err := d.Execute(context.Background(), "lock_account", ThreatTarget{UserID: "usr-1"})
		if err != nil {
			t.Fatalf("error: %v", err)
		}
		if !result.Success {
			t.Error("expected success")
		}
	})

	t.Run("unregistered action fails", func(t *testing.T) {
		_, err := d.Execute(context.Background(), "revoke_token", ThreatTarget{})
		if err == nil {
			t.Error("expected error for unregistered action")
		}
	})
}

func TestBlockDispatcher_HasAction(t *testing.T) {
	d := NewBlockDispatcher()
	d.Register(NewIPBlockAction())

	if !d.HasAction("block_ip") {
		t.Error("should have block_ip")
	}
	if d.HasAction("lock_account") {
		t.Error("should not have lock_account")
	}
}

func TestMockBlockAction(t *testing.T) {
	mock := NewMockBlockAction("test_block")

	t.Run("succeeds by default", func(t *testing.T) {
		result, err := mock.Execute(context.Background(), ThreatTarget{IP: "1.2.3.4"})
		if err != nil {
			t.Fatalf("error: %v", err)
		}
		if !result.Success {
			t.Error("expected success")
		}
	})

	t.Run("fails when configured", func(t *testing.T) {
		mock.SetShouldFail(true)
		_, err := mock.Execute(context.Background(), ThreatTarget{IP: "1.2.3.4"})
		if err == nil {
			t.Error("expected error")
		}
	})

	t.Run("tracks execution count", func(t *testing.T) {
		if mock.ExecCount() != 2 {
			t.Errorf("expected 2 executions, got %d", mock.ExecCount())
		}
	})
}
