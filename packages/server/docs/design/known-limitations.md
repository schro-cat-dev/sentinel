# Known Limitations & N/A Items

現時点で未対応・制約がある項目の一覧。最終更新: 2026-03-28

---

## 対応済み（今回のセッションで修正）

| 項目 | 修正内容 |
|---|---|
| Pipeline永続化失敗がサイレント | `Degraded` フラグ + `Warnings` で伝播。`FailOnPersistError=true` でエラー返却も可 |
| Deduplicator メモリリーク | 全件クリーンアップ + `maxSize`(10000) ガード追加 |
| IPBlockAction メモリリーク | TTL時はバックグラウンドクリーンアップgoroutine追加 |
| Details map値の長さ未検証 | normalizer.go でキー長/値長/サニタイズ追加 |
| SDK Details/AgentBackLog 検証なし | log-validator.ts に追加 |
| HealthCheck が常にSERVING | Store接続チェック追加。DB異常時は `DEGRADED` 返却 |
| アクセスログなし | `AuditLogUnaryInterceptor` で全gRPCリクエストをslogに記録 |
| キーローテーション | `hmac_key_version` configフィールド追加 |

---

## 実プロバイダ未接続（Mock/I/F のみ）

外部サービスとの連携はアダプタI/Fが定義済み。環境変数未設定時はスキップされエラーにならない。

| 項目 | 現状 | 接続に必要なもの |
|---|---|---|
| AI分析エージェント | `MockProvider` (固定レスポンス返却) | Anthropic/OpenAI APIキー + `Provider` I/F の実装体を `main.go` で差し替え |
| Slack通知 | `SlackNotifier` 実装済み。env var未設定時はスキップ | `SENTINEL_SLACK_WEBHOOK_URL` 環境変数 |
| Gmail通知 | `GmailNotifier` 実装済み（`smtp.SendMail` 呼び出し）。env var未設定時スキップ | `SENTINEL_GMAIL_FROM` + `SENTINEL_GMAIL_PASSWORD` |
| Discord通知 | `DiscordNotifier` 実装済み。env var未設定時スキップ | `SENTINEL_DISCORD_WEBHOOK_URL` |
| AWS/GCP/Azure IPブロック | アダプタI/F定義のみ。`execFn` 未注入 | 各クラウドSDK + `execFn` 実装を `main.go` で注入 |

---

## セキュリティ

| 項目 | 現状 | 備考 |
|---|---|---|
| データ暗号化（at rest） | SQLite平文 | SQLCipher 導入 or ファイルシステムレベル暗号化で対応。Store I/Fで差し替え可能 |
| キーローテーション | `hmac_key_version` フィールド追加済み | 複数キー並行運用（old+new）は未実装。バージョン管理の仕組みのみ |
| TLS | gRPCサーバは plaintext のみ | 本番では TLS 証明書設定 or リバースプロキシが必要 |

---

## テスト

| 項目 | 現状 | 備考 |
|---|---|---|
| Go テスト | 632+テスト、`-race` 全PASS | 13パッケージ |
| TypeScript テスト | 208テスト、全PASS | 11テストファイル |
| SDK→Server ネットワーク統合テスト | なし | 両方同時起動してgrpc接続するE2Eテスト基盤が必要 |
| 負荷テスト / ベンチマーク | 既存だが新モジュール未カバー | 望ましい |
| Fuzzing | 未実装 | `go test -fuzz` 対応可能 |

---

## インフラ / 運用

| 項目 | 現状 | 備考 |
|---|---|---|
| Docker / Kubernetes | ドキュメント（Dockerfile/docker-compose/K8s manifest）のみ | 実ビルド・デプロイは未検証 |
| CI/CD | なし | GitHub Actions でのテスト自動化未設定 |
| ログローテーション | SQLiteファイル肥大化の制御なし | ログ保持期間/アーカイブ/パーティション必要 |
| メトリクス / Observability | なし | Prometheus exporter / OpenTelemetry 未対応 |
| gRPC streaming | 未対応 | リアルタイム通知にはstreaming or WebSocket |
