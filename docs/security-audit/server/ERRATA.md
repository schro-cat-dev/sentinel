# Server Security Audit 正誤表

```yaml
verified_at: "2026-04-02"
auditor: automated verification against source code
```

## 修正済みの誤り

| ドキュメント | 誤り | 正しい内容 | 対応 |
|---|---|---|---|
| 02-grpc-network.md | `credentials.NewServerTLSFromFile()` 使用 | `tls.LoadX509KeyPair` + `GetCertificate` callback + `credentials.NewTLS()` | コード更新済み（証明書ホットリロード対応） |
| 02-grpc-network.md | MinVersion未設定 | `tls.VersionTLS12` 明示的設定済み | コード更新済み |
| 02-grpc-network.md | mTLS非対応 | `RequireAndVerifyClientCert` + `TLSClientCAFile` 実装済み | コード更新済み |
| 03-database-persistence.md | WAL設定は`PRAGMA journal_mode=WAL` | DSNパラメータ `_journal=WAL` | 設計上の差異（結果は同等） |
| 03-database-persistence.md | `pending_blocks` テーブル未記載 | スキーマに存在するがストア接続がnilで未使用 | 設計上の課題として認識 |
| 06-threat-response.md | ブロック承認で`content_hash`検証 | タスク承認では検証あり、ブロック承認では未検証 | 責務の混同を修正 |
| 07-secret-management.md | 各種行番号参照 | main.go改修により行番号ずれ | 行番号は流動的のため、関数名で参照すべき |

## コードで対処した脆弱性

| ID | 重要度 | 問題 | 修正内容 |
|---|---|---|---|
| V-1 | MEDIUM | Email header injection | `sanitizeHeader()` で `\r\n` 除去 |
| V-2 | MEDIUM | ApproveBlock 認可なし | `AuthorizerForApproval` インターフェース + `CanApprove` チェック追加 |
| V-4 | LOW | 証明書ホットリロード競合 | `atomic.Pointer[tls.Certificate]` に変更 |

## 残存事項（設計上の判断）

| ID | 重要度 | 問題 | 判断 |
|---|---|---|---|
| V-3 | MEDIUM | EnhancedBlockDispatcher の store が nil | main.go でストア接続が必要。現在は response module 自体がオプショナルなため許容 |
| V-5 | LOW | pending_blocks テーブルが未使用 | V-3 と同根。ストア接続時に活性化 |
| V-6 | LOW | SIGHUP goroutine が停止しない | プロセス終了で回収。テスト時はgoroutineリーク |
