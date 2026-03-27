package retry

import (
	"context"
	"fmt"
	"math"
	"math/rand"
	"time"
)

// Config はリトライの設定
type Config struct {
	MaxAttempts int           // 最大試行回数（1 = リトライなし）
	BaseDelay  time.Duration // 初回リトライ待機時間
	MaxDelay   time.Duration // 最大待機時間
	Multiplier float64       // 指数倍率（デフォルト2.0）
}

// DefaultConfig はデフォルトリトライ設定を返す
func DefaultConfig() Config {
	return Config{
		MaxAttempts: 3,
		BaseDelay:   100 * time.Millisecond,
		MaxDelay:    5 * time.Second,
		Multiplier:  2.0,
	}
}

// Do は関数を指数バックオフ + jitter 付きでリトライする
func Do(ctx context.Context, cfg Config, fn func() error) error {
	if cfg.MaxAttempts <= 0 {
		cfg.MaxAttempts = 1
	}
	if cfg.Multiplier <= 0 {
		cfg.Multiplier = 2.0
	}

	var lastErr error
	for attempt := 0; attempt < cfg.MaxAttempts; attempt++ {
		select {
		case <-ctx.Done():
			return fmt.Errorf("retry cancelled: %w", ctx.Err())
		default:
		}

		lastErr = fn()
		if lastErr == nil {
			return nil
		}

		// 最後の試行ならリトライしない
		if attempt == cfg.MaxAttempts-1 {
			break
		}

		delay := calculateDelay(cfg, attempt)

		select {
		case <-ctx.Done():
			return fmt.Errorf("retry cancelled during backoff: %w", ctx.Err())
		case <-time.After(delay):
		}
	}

	return fmt.Errorf("retry exhausted after %d attempts: %w", cfg.MaxAttempts, lastErr)
}

// DoWithResult は戻り値付き関数をリトライする
func DoWithResult[T any](ctx context.Context, cfg Config, fn func() (T, error)) (T, error) {
	var result T
	err := Do(ctx, cfg, func() error {
		var fnErr error
		result, fnErr = fn()
		return fnErr
	})
	return result, err
}

// calculateDelay は指数バックオフ + full jitter を計算する
// delay = random(0, min(maxDelay, baseDelay * multiplier^attempt))
func calculateDelay(cfg Config, attempt int) time.Duration {
	exp := math.Pow(cfg.Multiplier, float64(attempt))
	backoff := time.Duration(float64(cfg.BaseDelay) * exp)
	if backoff > cfg.MaxDelay {
		backoff = cfg.MaxDelay
	}
	// Full jitter: random between 0 and backoff
	jitter := time.Duration(rand.Int63n(int64(backoff) + 1))
	return jitter
}

// IsRetryable は一時的なエラーかどうかを判定するヘルパー
func IsRetryable(err error) bool {
	if err == nil {
		return false
	}
	// context.Canceled / context.DeadlineExceeded はリトライしない
	if err == context.Canceled || err == context.DeadlineExceeded {
		return false
	}
	return true
}
