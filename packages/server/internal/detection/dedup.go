package detection

import (
	"sync"
	"time"
)

// Deduplicator は時間ウィンドウ内の重複イベントを抑制する
type Deduplicator struct {
	mu      sync.Mutex
	seen    map[string]time.Time // key → last seen time
	window  time.Duration
	maxSize int // 最大エントリ数（0=無制限、デフォルト10000）
}

// NewDeduplicator は指定ウィンドウの重複抑制フィルターを生成する
func NewDeduplicator(window time.Duration) *Deduplicator {
	return &Deduplicator{
		seen:    make(map[string]time.Time),
		window:  window,
		maxSize: 10000,
	}
}

// IsDuplicate はキーがウィンドウ内に既に存在するかチェックし、存在しなければ記録する
func (d *Deduplicator) IsDuplicate(key string) bool {
	d.mu.Lock()
	defer d.mu.Unlock()

	now := time.Now()

	// 期限切れエントリの全件掃除
	for k, ts := range d.seen {
		if now.Sub(ts) > d.window {
			delete(d.seen, k)
		}
	}

	// maxSizeガード: サイズ超過時は最も古いエントリを削除
	if d.maxSize > 0 && len(d.seen) >= d.maxSize {
		var oldestKey string
		var oldestTime time.Time
		first := true
		for k, ts := range d.seen {
			if first || ts.Before(oldestTime) {
				oldestKey = k
				oldestTime = ts
				first = false
			}
		}
		if oldestKey != "" {
			delete(d.seen, oldestKey)
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
