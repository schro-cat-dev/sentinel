# Go Server 脅威レスポンス・ブロックエージェント監査

## 概要

脅威レスポンスオーケストレーター、ブロックディスパッチャ、承認ワークフローのセキュリティを評価する。

---

## チェック項目一覧

### 1. BlockDispatcher のインターフェース安全性

**ファイル**: `internal/response/block_agent.go`

| チェック項目 | 判定 | 根拠 |
|-------------|------|------|
| アクション登録の排他制御 | **OK** | `mu.Lock()` で保護 |
| アクション実行の排他制御 | **OK** | `mu.RLock()` で読み取りロック |
| 未登録アクションの処理 | **OK** | エラーメッセージ付き `BlockResult` を返却 |
| ログ出力 | **OK** | 成功/失敗の両方をログ |

### 2. IPBlockAction の安全性

| チェック項目 | 判定 | 根拠 |
|-------------|------|------|
| context キャンセル対応 | **OK** | `block_agent.go:120-128` — `select { case <-ctx.Done() }` |
| 無効IPの拒否 | **OK** | `ip == "" || ip == "0.0.0.0"` で拒否 |
| mutex 保護 | **OK** | `a.mu.Lock()` で保護 |
| TTL サポート | **OK** | `IsBlocked()` で期限切れチェック |
| Unblock 機能 | **OK** | 手動解除可能 |
| **IPアドレスのバリデーション** | **要注意** | IP形式のバリデーションなし。`"not_an_ip"` でもブロックリストに登録可能 |

**推奨パッチ**:
```go
func (a *IPBlockAction) Execute(ctx context.Context, target ThreatTarget) (*BlockResult, error) {
    // ... existing ctx check ...

    ip := target.IP
    if ip == "" || ip == "0.0.0.0" {
        // ... existing error handling ...
    }

    // IP形式の基本バリデーション
    if net.ParseIP(ip) == nil {
        return &BlockResult{
            ActionType: "block_ip", Target: ip,
            Success: false, Error: "invalid IP address format",
            ExecutedAt: time.Now().UTC(),
        }, fmt.Errorf("invalid IP address: %s", ip)
    }

    // ... existing block logic ...
}
```

### 3. AccountLockAction の安全性

| チェック項目 | 判定 | 根拠 |
|-------------|------|------|
| 空ユーザIDの拒否 | **OK** | `userID == ""` で拒否 |
| mutex 保護 | **OK** | `a.mu.Lock()` |
| **context キャンセル対応** | **NG** | `IPBlockAction` と異なり `ctx.Done()` チェックなし |
| **TTL サポート** | **NG** | 永久ロック。自動解除なし |

**推奨パッチ**: `IPBlockAction` と同様のTTLとcontext対応を追加。

### 4. EnhancedBlockDispatcher の承認フロー

**ファイル**: 想定される `internal/response/enhanced_block.go` 等

| チェック項目 | 判定 | 根拠 |
|-------------|------|------|
| REQUIRE_APPROVAL モード | **OK** | 即時実行と承認要求の切り替え |
| IMMEDIATE モード | **OK** | 承認なしで即時実行 |
| **承認のcontent_hash検証** | **OK** | DBのcontent_hashと照合し、改竄を検知 |

### 5. ThreatResponseOrchestrator

| チェック項目 | 判定 | 根拠 |
|-------------|------|------|
| ストラテジーの安全性 | **OK** | `BLOCK_ONLY`, `ANALYZE_ONLY`, `BLOCK_AND_ANALYZE`, `BLOCK_AND_NOTIFY` |
| ルールマッチング | **OK** | イベント名でルールを選択 |
| デフォルトストラテジー | **OK** | 設定で制御 |
| 永続化 | **OK** | `WithPersistFunc` でDB保存 |
| 通知 | **OK** | `WithNotifyFunc` で通知送信 |

### 6. ブロック状態の一貫性

| チェック項目 | 判定 | 根拠 |
|-------------|------|------|
| メモリとDBの同期 | **要注意** | IPBlockAction はメモリ内 map。DB には ThreatResponse として記録されるが、起動時にメモリへの復元なし |
| **プロセス再起動後のブロック状態** | **NG** | ブロック情報はメモリのみ。再起動でクリアされる |

**リスク分析**:
- プロセス再起動後、ブロック済みIPが解放される
- DB にはブロック記録が残るが、IPBlockAction のメモリ map には反映されない
- **影響**: セキュリティインシデント中の再起動で攻撃者が再アクセス可能

**推奨パッチ**:
```go
// サーバ起動時にDBからブロック状態を復元
func (a *IPBlockAction) RestoreFromStore(store *Store) error {
    records, err := store.GetActiveBlocks(context.Background())
    if err != nil {
        return err
    }
    a.mu.Lock()
    defer a.mu.Unlock()
    for _, r := range records {
        if r.IP != "" {
            a.blocked[r.IP] = r.BlockedAt
        }
    }
    return nil
}
```

---

## 承認ワークフローのセキュリティ

### 7. 多段承認チェーン

| チェック項目 | 判定 | 根拠 |
|-------------|------|------|
| ステップ順序の強制 | **OK** | `current_step` で現在のステップを追跡 |
| 各ステップのロール検証 | **OK** | `Role` フィールドで権限チェック |
| content_hash の改竄検知 | **OK** | 各ステップで content_hash を記録・検証 |
| **承認期限** | **要確認** | TTL の有無 |
| **承認のリプレイ防止** | **OK** | approval_id のユニーク制約 |

---

## 総合判定

**評価: B（良好、改善推奨）**

| 項目 | 重大度 | ステータス | 備考 |
|------|--------|-----------|------|
| BlockDispatcher の排他制御 | — | **OK** | |
| IPアドレスバリデーション | LOW | **要改善** | `net.ParseIP` 追加 |
| AccountLock のcontext対応 | LOW | **要改善** | |
| AccountLock のTTL | MEDIUM | **要改善** | 永久ロック回避 |
| ブロック状態の永続化 | HIGH | **要改善** | 再起動後の状態復元 |
| content_hash 改竄検知 | — | **OK** | |
| 承認ワークフロー | — | **OK** | |
