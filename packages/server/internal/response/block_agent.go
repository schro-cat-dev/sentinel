package response

import (
	"context"
	"fmt"
	"log/slog"
	"sync"
	"time"
)

// BlockAction はブロック実行の抽象インターフェース
// IPブロック、アカウントロック等の実装を差し替え可能
// 将来的にgRPC/HTTP経由で外部エージェントに委任可能
type BlockAction interface {
	Execute(ctx context.Context, target ThreatTarget) (*BlockResult, error)
	ActionType() string
}

// BlockDispatcher は複数のBlockActionをアクションタイプで管理する
type BlockDispatcher struct {
	mu      sync.RWMutex
	actions map[string]BlockAction
}

// NewBlockDispatcher はBlockDispatcherを生成する
func NewBlockDispatcher() *BlockDispatcher {
	return &BlockDispatcher{
		actions: make(map[string]BlockAction),
	}
}

// Register はBlockActionを登録する
func (d *BlockDispatcher) Register(action BlockAction) {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.actions[action.ActionType()] = action
}

// Execute は指定アクションタイプのBlockActionを実行する
func (d *BlockDispatcher) Execute(ctx context.Context, actionType string, target ThreatTarget) (*BlockResult, error) {
	d.mu.RLock()
	action, ok := d.actions[actionType]
	d.mu.RUnlock()

	if !ok {
		return &BlockResult{
			ActionType: actionType,
			Target:     target.IP,
			Success:    false,
			Error:      fmt.Sprintf("no block action registered for type: %s", actionType),
			ExecutedAt: time.Now().UTC(),
		}, fmt.Errorf("no block action registered: %s", actionType)
	}

	result, err := action.Execute(ctx, target)
	if err != nil {
		slog.Error("block action failed",
			"actionType", actionType,
			"target", target.IP,
			"error", err,
		)
	} else {
		slog.Info("block action executed",
			"actionType", actionType,
			"target", result.Target,
			"success", result.Success,
		)
	}
	return result, err
}

// HasAction は指定アクションタイプが登録されているか確認する
func (d *BlockDispatcher) HasAction(actionType string) bool {
	d.mu.RLock()
	defer d.mu.RUnlock()
	_, ok := d.actions[actionType]
	return ok
}

// --- Built-in Block Actions ---

// IPBlockAction はIPアドレスをブロックする（TTL対応）
type IPBlockAction struct {
	mu      sync.Mutex
	blocked map[string]time.Time // IP → blocked at
	ttl     time.Duration        // 0 = 永続
}

func NewIPBlockAction() *IPBlockAction {
	return &IPBlockAction{blocked: make(map[string]time.Time)}
}

// NewIPBlockActionWithTTL はTTL付きIPBlockActionを生成する
func NewIPBlockActionWithTTL(ttl time.Duration) *IPBlockAction {
	a := &IPBlockAction{blocked: make(map[string]time.Time), ttl: ttl}
	if ttl > 0 {
		go a.cleanupLoop(ttl)
	}
	return a
}

// cleanupLoop は定期的に期限切れエントリを削除する
func (a *IPBlockAction) cleanupLoop(interval time.Duration) {
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for range ticker.C {
		a.mu.Lock()
		for ip, blockedAt := range a.blocked {
			if time.Since(blockedAt) > a.ttl {
				delete(a.blocked, ip)
			}
		}
		a.mu.Unlock()
	}
}

func (a *IPBlockAction) ActionType() string { return "block_ip" }

func (a *IPBlockAction) Execute(ctx context.Context, target ThreatTarget) (*BlockResult, error) {
	select {
	case <-ctx.Done():
		return &BlockResult{
			ActionType: "block_ip", Target: target.IP,
			Success: false, Error: "context cancelled",
			ExecutedAt: time.Now().UTC(),
		}, ctx.Err()
	default:
	}

	ip := target.IP
	if ip == "" || ip == "0.0.0.0" {
		return &BlockResult{
			ActionType: "block_ip", Target: ip,
			Success: false, Error: "no valid IP to block",
			ExecutedAt: time.Now().UTC(),
		}, fmt.Errorf("no valid IP to block")
	}

	a.mu.Lock()
	a.blocked[ip] = time.Now().UTC()
	a.mu.Unlock()

	return &BlockResult{
		ActionType: "block_ip",
		Target:     ip,
		Success:    true,
		ExecutedAt: time.Now().UTC(),
	}, nil
}

// IsBlocked はIPがブロック中か確認する（TTL考慮）
func (a *IPBlockAction) IsBlocked(ip string) bool {
	a.mu.Lock()
	defer a.mu.Unlock()
	blockedAt, ok := a.blocked[ip]
	if !ok {
		return false
	}
	if a.ttl > 0 && time.Since(blockedAt) > a.ttl {
		delete(a.blocked, ip)
		return false
	}
	return true
}

// BlockedCount はブロック中のIP数を返す（TTL期限切れは除外）
func (a *IPBlockAction) BlockedCount() int {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.ttl == 0 {
		return len(a.blocked)
	}
	count := 0
	for ip, blockedAt := range a.blocked {
		if time.Since(blockedAt) > a.ttl {
			delete(a.blocked, ip)
		} else {
			count++
		}
	}
	return count
}

// Unblock はIPのブロックを解除する
func (a *IPBlockAction) Unblock(ip string) {
	a.mu.Lock()
	defer a.mu.Unlock()
	delete(a.blocked, ip)
}

// AccountLockAction はアカウントをロックする
type AccountLockAction struct {
	mu     sync.Mutex
	locked map[string]time.Time
}

func NewAccountLockAction() *AccountLockAction {
	return &AccountLockAction{locked: make(map[string]time.Time)}
}

func (a *AccountLockAction) ActionType() string { return "lock_account" }

func (a *AccountLockAction) Execute(ctx context.Context, target ThreatTarget) (*BlockResult, error) {
	userID := target.UserID
	if userID == "" {
		return &BlockResult{
			ActionType: "lock_account", Target: "",
			Success: false, Error: "no user ID to lock",
			ExecutedAt: time.Now().UTC(),
		}, fmt.Errorf("no user ID to lock")
	}

	a.mu.Lock()
	a.locked[userID] = time.Now().UTC()
	a.mu.Unlock()

	return &BlockResult{
		ActionType: "lock_account",
		Target:     userID,
		Success:    true,
		ExecutedAt: time.Now().UTC(),
	}, nil
}

func (a *AccountLockAction) IsLocked(userID string) bool {
	a.mu.Lock()
	defer a.mu.Unlock()
	_, ok := a.locked[userID]
	return ok
}

// --- Mock Block Action (for testing) ---

// MockBlockAction はテスト用のモックブロックアクション
type MockBlockAction struct {
	actionType string
	shouldFail bool
	execCount  int
	mu         sync.Mutex
}

func NewMockBlockAction(actionType string) *MockBlockAction {
	return &MockBlockAction{actionType: actionType}
}

func (m *MockBlockAction) ActionType() string { return m.actionType }

func (m *MockBlockAction) SetShouldFail(fail bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.shouldFail = fail
}

func (m *MockBlockAction) ExecCount() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.execCount
}

func (m *MockBlockAction) Execute(ctx context.Context, target ThreatTarget) (*BlockResult, error) {
	m.mu.Lock()
	m.execCount++
	fail := m.shouldFail
	m.mu.Unlock()

	if fail {
		return &BlockResult{
			ActionType: m.actionType,
			Target:     target.IP,
			Success:    false,
			Error:      "mock block failed",
			ExecutedAt: time.Now().UTC(),
		}, fmt.Errorf("mock block failed")
	}

	return &BlockResult{
		ActionType: m.actionType,
		Target:     target.IP,
		Success:    true,
		ExecutedAt: time.Now().UTC(),
	}, nil
}
