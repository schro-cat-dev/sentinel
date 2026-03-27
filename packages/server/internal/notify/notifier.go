package notify

import (
	"context"
	"fmt"
	"log/slog"
	"sync"

	"github.com/schro-cat-dev/sentinel-server/internal/retry"
)

// Notification は通知メッセージの統一構造
type Notification struct {
	Channel     string            // 送信先チャネル名 (e.g., "#security", "security@company.com")
	Subject     string            // 件名
	Body        string            // 本文
	Severity    string            // "critical", "high", "medium", "low", "info"
	Fields      map[string]string // 追加フィールド（キー→値）
	TraceID     string            // 関連するトレースID
	EventName   string            // 検知イベント名
}

// Notifier は通知チャネルの抽象インターフェース（アダプタパターン）
// Gmail, Slack, Webhook, Discord, PagerDuty 等を差し替え・追加可能
type Notifier interface {
	// Send は通知を送信する
	Send(ctx context.Context, n Notification) error
	// Type は通知チャネル種別を返す ("slack", "gmail", "webhook", "discord", "pagerduty")
	Type() string
}

// MultiNotifier は複数のNotifierに同時配信するディスパッチャ
type MultiNotifier struct {
	mu          sync.RWMutex
	notifiers   map[string]Notifier   // type → notifier
	routing     map[string][]string   // channel prefix → notifier types
	retryCfg    retry.Config          // リトライ設定
}

// NewMultiNotifier はMultiNotifierを生成する
func NewMultiNotifier() *MultiNotifier {
	return &MultiNotifier{
		notifiers: make(map[string]Notifier),
		routing:   make(map[string][]string),
		retryCfg:  retry.DefaultConfig(),
	}
}

// SetRetryConfig はリトライ設定を変更する
func (m *MultiNotifier) SetRetryConfig(cfg retry.Config) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.retryCfg = cfg
}

// Register はNotifierを登録する
func (m *MultiNotifier) Register(n Notifier) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.notifiers[n.Type()] = n
}

// SetRouting はチャネルプレフィックスとNotifier種別のマッピングを設定する
// e.g., "#" → ["slack"], "@" → ["gmail"], "https://" → ["webhook"]
func (m *MultiNotifier) SetRouting(prefix string, types []string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.routing[prefix] = types
}

// Send は通知をルーティングに基づいて適切なNotifierに送信する
func (m *MultiNotifier) Send(ctx context.Context, n Notification) error {
	m.mu.RLock()
	defer m.mu.RUnlock()

	sent := false
	var lastErr error

	// ルーティングベースの配信（リトライ付き）
	for prefix, types := range m.routing {
		if len(n.Channel) >= len(prefix) && n.Channel[:len(prefix)] == prefix {
			for _, t := range types {
				if notifier, ok := m.notifiers[t]; ok {
					nRef := notifier
					err := retry.Do(ctx, m.retryCfg, func() error {
						return nRef.Send(ctx, n)
					})
					if err != nil {
						slog.Error("notification failed after retries",
							"type", t, "channel", n.Channel, "error", err,
						)
						lastErr = err
					} else {
						sent = true
					}
				}
			}
		}
	}

	// ルーティングにマッチしない場合は全Notifierに配信
	if !sent {
		for _, notifier := range m.notifiers {
			nRef := notifier
			err := retry.Do(ctx, m.retryCfg, func() error {
				return nRef.Send(ctx, n)
			})
			if err != nil {
				slog.Error("notification failed after retries",
					"type", nRef.Type(), "channel", n.Channel, "error", err,
				)
				lastErr = err
			} else {
				sent = true
			}
		}
	}

	if !sent && lastErr != nil {
		return fmt.Errorf("all notifiers failed: %w", lastErr)
	}
	return nil
}

// SendAll は全登録Notifierに送信する（ルーティング無視）
func (m *MultiNotifier) SendAll(ctx context.Context, n Notification) []error {
	m.mu.RLock()
	defer m.mu.RUnlock()

	var errs []error
	for _, notifier := range m.notifiers {
		if err := notifier.Send(ctx, n); err != nil {
			errs = append(errs, fmt.Errorf("%s: %w", notifier.Type(), err))
		}
	}
	return errs
}

// HasType は指定種別のNotifierが登録されているか確認する
func (m *MultiNotifier) HasType(t string) bool {
	m.mu.RLock()
	defer m.mu.RUnlock()
	_, ok := m.notifiers[t]
	return ok
}

// RegisteredTypes は登録されている全Notifier種別を返す
func (m *MultiNotifier) RegisteredTypes() []string {
	m.mu.RLock()
	defer m.mu.RUnlock()
	types := make([]string, 0, len(m.notifiers))
	for t := range m.notifiers {
		types = append(types, t)
	}
	return types
}
