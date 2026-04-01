# Go Server データベース・永続化セキュリティ監査

## 概要

SQLite + SQLCipher によるデータ永続化のセキュリティを評価する。

---

## チェック項目一覧

### 1. SQL インジェクション防御

**ファイル**: `internal/store/sqlite.go`

| チェック項目 | 判定 | 根拠 |
|-------------|------|------|
| パラメータ化クエリ | **OK** | 全 INSERT/SELECT/UPDATE で `?` プレースホルダ使用 |
| 文字列連結によるクエリ構築 | **OK** | クエリ文字列にユーザ入力の直接連結なし |
| `database/sql` の使用 | **OK** | Go 標準ライブラリのプリペアドステートメント |

**検証ポイント**: スキーマ定義（`sqlite.go:16-97`）を確認し、全テーブルの INSERT 文を検証。全て `?` プレースホルダを使用。

### 2. 暗号化ドライバ

| チェック項目 | 判定 | 根拠 |
|-------------|------|------|
| SQLCipher サポート | **OK** | `store/sqlite_encrypted.go` で `go-sqlcipher/v4` 使用 |
| 暗号アルゴリズム | **OK** | AES-256-CBC (SQLCipher デフォルト) |
| 暗号化キー長 | **OK** | `config.go` で最低32バイトを検証 |
| ドライバ選択 | **OK** | `sqlite` と `sqlite_encrypted` を設定で切り替え |

### 3. 暗号化キーの取り扱い

| チェック項目 | 判定 | 根拠 |
|-------------|------|------|
| 環境変数からの読み込み | **OK** | `SENTINEL_STORE_ENCRYPTION_KEY` |
| **DSN への埋め込み** | **要注意** | 暗号化キーがDSN文字列に含まれる可能性 |
| **ログへの非出力** | **要確認** | DSN文字列がエラーログに出力されないこと |

**DSN 埋め込みリスク**:
- SQLCipher の DSN は `file:path?_key=...` 形式
- DSN をログに出力すると暗号化キーが漏洩する
- **緩和**: `main.go:49` でドライバ名のみログ出力 (`"driver", cfg.Store.Driver`)。DSNは出力しない

### 4. WAL モード

| チェック項目 | 判定 | 根拠 |
|-------------|------|------|
| WAL モード有効化 | **OK** | データベース初期化時に `PRAGMA journal_mode=WAL` |
| 書き込み耐久性 | **OK** | WAL は fsync によりクラッシュ耐性あり |
| **WAL ファイルの暗号化** | **OK** | SQLCipher 使用時は WAL ファイルも暗号化対象 |

### 5. トランザクション安全性

| チェック項目 | 判定 | 根拠 |
|-------------|------|------|
| トランザクション使用 | **OK** | `BEGIN IMMEDIATE` で排他ロック取得 |
| ロールバック | **OK** | エラー時に `ROLLBACK` |
| **コミットエラーハンドリング** | **OK** | コミット失敗時はエラーを返却 |

### 6. スキーマセキュリティ

| テーブル | 主キー | ユニーク制約 | 外部キー | 評価 |
|---------|--------|------------|---------|------|
| `logs` | `id` (AUTO) | `trace_id` UNIQUE | — | **OK** |
| `tasks` | `task_id` | — | — | **OK** |
| `approval_requests` | `approval_id` | `task_id` UNIQUE | — | **OK** |
| `approval_step_records` | `record_id` | — | — | **OK** |
| `task_modifications` | `modification_id` | — | — | **OK** |
| `task_results` | `id` (AUTO) | — | — | **OK** |
| `threat_responses` | `response_id` | — | — | **OK** |

**注意点**:
- 外部キー制約が設定されていない（SQLite のデフォルトでは `PRAGMA foreign_keys` が OFF）
- **影響**: 参照整合性がアプリケーション層で担保される必要あり。ただし、単一プロセスでのアクセスを前提とした設計のため、実質問題なし

### 7. content_hash による改竄検知

| チェック項目 | 判定 | 根拠 |
|-------------|------|------|
| approval_requests に content_hash | **OK** | 承認リクエストの改竄検知 |
| approval_step_records に content_hash | **OK** | 承認ステップの改竄検知 |
| task_modifications に content_hash | **OK** | タスク変更の改竄検知 |
| **ハッシュ検証の実装** | **OK** | server.go でハッシュ検証を実施 |

### 8. データ保持・削除ポリシー

| チェック項目 | 判定 | 根拠 |
|-------------|------|------|
| データ保持期間 | **未設定** | TTL や自動削除機構なし |
| ログの自動パージ | **未設定** | 蓄積され続ける |

**リスク**: 長期運用でデータベースサイズが無制限に増大。PII を含むマスキング済みデータも永続化される。

**推奨パッチ**:
```go
// store に定期パージ機能を追加
func (s *Store) PurgeBefore(ctx context.Context, before time.Time) error {
    _, err := s.db.ExecContext(ctx,
        "DELETE FROM logs WHERE created_at < ?",
        before.Format("2006-01-02T15:04:05Z07:00"))
    return err
}
```

---

## 総合判定

**評価: A-（良好）**

| 項目 | 重大度 | ステータス | 備考 |
|------|--------|-----------|------|
| SQL インジェクション防御 | — | **OK** | 全クエリがパラメータ化 |
| 暗号化 (SQLCipher) | — | **OK** | AES-256-CBC |
| 暗号化キーの安全性 | LOW | **OK** | DSNはログに出力されない |
| トランザクション安全性 | — | **OK** | |
| 外部キー制約なし | LOW | **許容** | 単一プロセス設計 |
| content_hash 改竄検知 | — | **OK** | |
| データ保持ポリシーなし | MEDIUM | **要改善** | 自動パージ推奨 |
