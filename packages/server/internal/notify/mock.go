package notify

import (
	"context"
	"fmt"
	"sync"
)

// MockNotifier はテスト用のモック通知アダプタ
type MockNotifier struct {
	mu           sync.Mutex
	notifyType   string
	shouldFail   bool
	sent         []Notification
}

func NewMockNotifier(notifyType string) *MockNotifier {
	return &MockNotifier{notifyType: notifyType}
}

func (m *MockNotifier) Type() string { return m.notifyType }

func (m *MockNotifier) SetShouldFail(fail bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.shouldFail = fail
}

func (m *MockNotifier) Send(ctx context.Context, n Notification) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if m.shouldFail {
		return fmt.Errorf("mock %s notifier failed", m.notifyType)
	}

	m.sent = append(m.sent, n)
	return nil
}

// SentCount は送信された通知数を返す
func (m *MockNotifier) SentCount() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return len(m.sent)
}

// LastSent は最後に送信された通知を返す
func (m *MockNotifier) LastSent() (Notification, bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if len(m.sent) == 0 {
		return Notification{}, false
	}
	return m.sent[len(m.sent)-1], true
}

// AllSent は全送信通知を返す
func (m *MockNotifier) AllSent() []Notification {
	m.mu.Lock()
	defer m.mu.Unlock()
	result := make([]Notification, len(m.sent))
	copy(result, m.sent)
	return result
}

// Reset は送信記録をクリアする
func (m *MockNotifier) Reset() {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.sent = nil
}
