package detection

import (
	"sync"
	"time"
)

// Deduplicator は時間ウィンドウ内の重複イベントを抑制する
type Deduplicator struct {
	mu     sync.Mutex
	seen   map[string]time.Time // key → last seen time
	window time.Duration
}

// NewDeduplicator は指定ウィンドウの重複抑制フィルターを生成する
func NewDeduplicator(window time.Duration) *Deduplicator {
	return &Deduplicator{
		seen:   make(map[string]time.Time),
		window: window,
	}
}

// IsDuplicate はキーがウィンドウ内に既に存在するかチェックし、存在しなければ記録する
func (d *Deduplicator) IsDuplicate(key string) bool {
	d.mu.Lock()
	defer d.mu.Unlock()

	now := time.Now()

	// 期限切れエントリの掃除（最大100件）
	cleaned := 0
	for k, ts := range d.seen {
		if now.Sub(ts) > d.window {
			delete(d.seen, k)
			cleaned++
			if cleaned >= 100 {
				break
			}
		}
	}

	if lastSeen, exists := d.seen[key]; exists {
		if now.Sub(lastSeen) <= d.window {
			return true
		}
	}

	d.seen[key] = now
	return false
}

// Reset はすべての記録をクリアする
func (d *Deduplicator) Reset() {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.seen = make(map[string]time.Time)
}

// Size は現在記録されているエントリ数を返す
func (d *Deduplicator) Size() int {
	d.mu.Lock()
	defer d.mu.Unlock()
	return len(d.seen)
}
