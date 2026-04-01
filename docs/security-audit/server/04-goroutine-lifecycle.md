# Go Server goroutine ライフサイクル・リソースリーク監査

## 概要

Go サーバ内のgoroutineの生成・管理・終了を評価し、リソースリーク・ゾンビgoroutineのリスクを分析する。

---

## goroutine 生成箇所の一覧

### 1. Graceful Shutdown goroutine

**ファイル**: `cmd/server/main.go:288-304`

```go
go func() {
    sigCh := make(chan os.Signal, 1)
    signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
    <-sigCh
    // graceful stop with timeout
}()
```

| チェック項目 | 判定 | 根拠 |
|-------------|------|------|
| 終了条件 | **OK** | シグナル受信で終了 |
| タイムアウト | **OK** | `GracefulTimeoutSec` で制限 |
| 強制終了フォールバック | **OK** | `srv.Stop()` |
| **goroutineリーク** | **OK** | プロセス終了とともに回収 |

### 2. Webhook 通知 goroutine

**ファイル**: `internal/webhook/notifier.go:50-64`

```go
func (n *Notifier) NotifyApprovalRequired(ctx context.Context, payload ApprovalPayload) {
    go func() {
        if err := n.send(payload); err != nil {
            slog.Error("webhook notification failed", ...)
        }
    }()
}
```

| チェック項目 | 判定 | 根拠 |
|-------------|------|------|
| fire-and-forget | **要注意** | goroutine の完了を追跡しない |
| エラーハンドリング | **OK** | `slog.Error` で記録 |
| HTTP タイムアウト | **OK** | `http.Client.Timeout` で制限 |
| **shutdown時の挙動** | **NG** | graceful shutdown 時にインフライトの通知goroutineが中断される可能性 |
| **goroutine数の制限** | **NG** | 大量の承認リクエストが同時に発生するとgoroutineが爆発 |

**推奨パッチ**:
```go
type Notifier struct {
    url        string
    httpClient *http.Client
    secret     []byte
    wg         sync.WaitGroup  // goroutine追跡
    sem        chan struct{}    // 並行数制限
}

func NewNotifier(url string, timeoutSec int, secret string) *Notifier {
    return &Notifier{
        url:        url,
        httpClient: &http.Client{Timeout: time.Duration(timeoutSec) * time.Second},
        secret:     []byte(secret),
        sem:        make(chan struct{}, 10), // 最大10並行
    }
}

func (n *Notifier) NotifyApprovalRequired(ctx context.Context, payload ApprovalPayload) {
    n.wg.Add(1)
    go func() {
        defer n.wg.Done()
        n.sem <- struct{}{}        // セマフォ取得
        defer func() { <-n.sem }() // セマフォ解放
        if err := n.send(payload); err != nil {
            slog.Error("webhook notification failed", "taskId", payload.TaskID, "error", err.Error())
        }
    }()
}

func (n *Notifier) Shutdown(ctx context.Context) error {
    done := make(chan struct{})
    go func() { n.wg.Wait(); close(done) }()
    select {
    case <-done:
        return nil
    case <-ctx.Done():
        return ctx.Err()
    }
}
```

### 3. IPBlockAction クリーンアップ goroutine

**ファイル**: `internal/response/block_agent.go:97-98`

```go
func NewIPBlockActionWithTTL(ttl time.Duration) *IPBlockAction {
    a := &IPBlockAction{blocked: make(map[string]time.Time), ttl: ttl}
    if ttl > 0 {
        go a.cleanupLoop(ttl)
    }
    return a
}
```

| チェック項目 | 判定 | 根拠 |
|-------------|------|------|
| 定期クリーンアップ | **OK** | `time.Ticker` でTTL間隔 |
| **停止機構** | **NG** | `for range ticker.C` は無限ループ。context や done channel による停止なし |
| mutex 保護 | **OK** | `a.mu.Lock()` でスレッドセーフ |

**goroutineリークリスク**:
- `cleanupLoop` は永久に動作し続ける
- `IPBlockAction` インスタンスがGC されても、goroutine は存続（goroutine がインスタンスへの参照を保持）
- **影響**: テスト環境でgoroutineリーク検出ツール（`goleak`）が失敗する可能性

**推奨パッチ**:
```go
type IPBlockAction struct {
    mu      sync.Mutex
    blocked map[string]time.Time
    ttl     time.Duration
    done    chan struct{}  // 追加: 停止シグナル
}

func NewIPBlockActionWithTTL(ttl time.Duration) *IPBlockAction {
    a := &IPBlockAction{
        blocked: make(map[string]time.Time),
        ttl:     ttl,
        done:    make(chan struct{}),
    }
    if ttl > 0 {
        go a.cleanupLoop(ttl)
    }
    return a
}

func (a *IPBlockAction) cleanupLoop(interval time.Duration) {
    ticker := time.NewTicker(interval)
    defer ticker.Stop()
    for {
        select {
        case <-ticker.C:
            a.mu.Lock()
            for ip, blockedAt := range a.blocked {
                if time.Since(blockedAt) > a.ttl {
                    delete(a.blocked, ip)
                }
            }
            a.mu.Unlock()
        case <-a.done:
            return
        }
    }
}

func (a *IPBlockAction) Stop() {
    close(a.done)
}
```

### 4. gRPC Server.Serve goroutine

**ファイル**: `cmd/server/main.go:313`

```go
if err := srv.Serve(lis); err != nil {
    slog.Error("server error", "error", err)
    os.Exit(1)
}
```

| チェック項目 | 判定 | 根拠 |
|-------------|------|------|
| メインgoroutineでの実行 | **OK** | `main()` 関数内 |
| エラー時の終了 | **OK** | `os.Exit(1)` |
| Graceful Stop との連携 | **OK** | `GracefulStop()` が Serve() を終了させる |

---

## context 伝播の評価

### 5. gRPC context の伝播

| チェック項目 | 判定 | 根拠 |
|-------------|------|------|
| リクエスト context の使用 | **OK** | gRPC ハンドラが context を受け取る |
| context キャンセル時の処理停止 | **OK** | IPBlockAction で `ctx.Done()` チェック |
| **Pipeline 全体での context 伝播** | **要確認** | Pipeline 内の各ステージが context をチェックしているか |

### 6. Agent Executor の context

| チェック項目 | 判定 | 根拠 |
|-------------|------|------|
| タイムアウト | **OK** | `TimeoutSec` で制限 |
| ループ深度制限 | **OK** | `MaxLoopDepth` で再帰防止 |
| **並行実行数の制限** | **NG** | 同時にエージェントを実行するgoroutine数の上限なし |

---

## リソースリーク要約

| リソース | 生成箇所 | リーク可能性 | 修正優先度 |
|---------|---------|------------|-----------|
| Webhook goroutine | `notifier.go:51` | **あり** — shutdown時の未完了送信 | **MEDIUM** |
| CleanupLoop goroutine | `block_agent.go:97` | **あり** — 停止機構なし | **MEDIUM** |
| Rate Limiter マップ | `interceptors.go:47` | **あり** — エントリ削除なし | **LOW** |
| Agent Executor goroutine | Agent Bridge | **低い** — タイムアウトで制御 | **LOW** |

---

## 総合判定

**評価: B（改善推奨）**

| 項目 | 重大度 | ステータス | 備考 |
|------|--------|-----------|------|
| Graceful Shutdown | — | **OK** | タイムアウト付き |
| Webhook goroutine 追跡 | MEDIUM | **要改善** | WaitGroup + セマフォ追加 |
| CleanupLoop 停止機構 | MEDIUM | **要改善** | done channel 追加 |
| context 伝播 | — | **OK** | gRPCレイヤーで適切 |
| Agent 並行数制限 | LOW | **要改善** | セマフォ追加推奨 |
