# Known Limitations & N/A Items

現時点で未対応・制約がある項目の一覧。最終更新: 2026-03-28

---

## 実プロバイダ未接続（Mock/I/F のみ）

外部サービスとの連携はアダプタI/Fが定義済み。環境変数未設定時はスキップされエラーにならない。

| 項目 | 現状 | 接続に必要なもの |
|---|---|---|
| AI分析エージェント | `MockProvider` (固定レスポンス返却) | Anthropic/OpenAI APIキー + `Provider` I/F の実装体を `main.go` で差し替え |
| Slack通知 | `SlackNotifier` 実装済み。`SENTINEL_SLACK_WEBHOOK_URL` 未設定時はスキップ | Slack Incoming Webhook URL |
| Gmail通知 | `GmailNotifier` 実装済み（`smtp.SendMail` 呼び出し）。env var 未設定時スキップ | `SENTINEL_GMAIL_FROM` + `SENTINEL_GMAIL_PASSWORD` |
| Discord通知 | `DiscordNotifier` 実装済み。env var 未設定時スキップ | `SENTINEL_DISCORD_WEBHOOK_URL` |
| AWS IPブロック | `AWSBlockAction` I/F定義のみ。`execFn` 未注入 | AWS SDK + `execFn` 実装を `main.go` で注入 |
| GCP IPブロック | `GCPBlockAction` I/F定義のみ | GCP SDK + `execFn` 実装 |
| Azure IPブロック | `AzureBlockAction` I/F定義のみ | Azure SDK + `execFn` 実装 |

---

## SDK → Server gRPC接続

| 項目 | 現状 | 備考 |
|---|---|---|
| SDK gRPCクライアント | `RemoteTransport` I/F + `examples/grpc-transport.ts` サンプル実装 | SDK本体はzero-dep維持。利用側が `@grpc/grpc-js` を追加して注入 |
| SDK Transport テスト | local/remote/dual 7テスト済み（MockTransport） | 実gRPC接続テストは両方同時起動が必要 |

---

## ブロック実行

| 項目 | 現状 | 備考 |
|---|---|---|
| IPブロック | in-memory map。TTL対応済み（`NewIPBlockActionWithTTL`）。`Unblock()` あり | 本番では外部ファイアウォール/WAF連携が必要（`BlockAction` I/Fで拡張可能） |
| `REQUIRE_APPROVAL` モード | config.yaml `response.block_mode: "REQUIRE_APPROVAL"` で切り替え可能。gRPC API（ApproveBlock/RejectBlock/ListPendingBlocks）実装済み | `ListPendingBlocks` はin-memory pendingBlocksを返す |
| `BlockApprovalStore` | SQLite実装済み（pending_blocks テーブル、CRUD 4メソッド） | `EnhancedBlockDispatcher` に渡せばDB永続化される |
| ブロック有効期限(TTL) | `NewIPBlockActionWithTTL(duration)` で設定可能。期限切れは `IsBlocked()` / `BlockedCount()` で自動除外 | TTL=0 で永続ブロック |

---

## 検知・設定

| 項目 | 現状 | 備考 |
|---|---|---|
| MaskingPolicy YAML設定 | config.yaml `masking_policies` セクションで設定可能。`convertMaskingPolicies()` で変換 | 実機検証済み |
| ApprovalRoutingRules YAML設定 | config.yaml `routing_rules` セクションで設定可能。`convertRoutingRules()` で変換 | 多段階承認チェーン実機検証済み |
| 異常検知のベースライン永続化 | in-memory（再起動でリセット） | 長期ベースラインの蓄積には外部ストレージが必要。`FrequencyTracker` のI/F抽出で拡張可能 |

---

## Proto / gRPC

| 項目 | 現状 | 備考 |
|---|---|---|
| `ListPendingBlocks` | 実装済み。`EnhancedBlockDispatcher.ListPending()` からデータ返却 | in-memory のpendingBlocksを列挙 |
| `GetThreatResponses` | 実装済み。`trace_id` でSQLiteから取得しprotoで返却 | 実機検証済み |
| `ApproveBlock` / `RejectBlock` | 実装済み | `REQUIRE_APPROVAL` モード時に使用 |
| ストリーミング（Server-Sent Events） | 未対応 | リアルタイム通知にはgRPC streaming or WebSocket |

---

## テスト

| 項目 | 現状 | 備考 |
|---|---|---|
| Go テスト | 622テスト、`-race` 全PASS | 12パッケージ |
| TypeScript テスト | 184テスト、全PASS | 10テストファイル |
| SDK→Server ネットワーク統合テスト | なし | 両方同時起動してgrpc接続するE2Eテスト基盤が必要 |
| 負荷テスト / ベンチマーク | `benchmark_test.go` は既存だが新モジュール未カバー | Ensemble/Anomaly/ThreatResponseのベンチマーク追加が望ましい |
| Fuzzing | 未実装 | `go test -fuzz` でSanitizer/Masking/Detectorのfuzz対象化が可能 |

---

## インフラ / 運用

| 項目 | 現状 | 備考 |
|---|---|---|
| Docker / Kubernetes | ドキュメント（Dockerfile/docker-compose/K8s manifest）のみ | 実ビルド・デプロイは未検証 |
| CI/CD | なし | GitHub Actions でのテスト自動化未設定 |
| ログローテーション | SQLiteファイル肥大化の制御なし | ログ保持期間/アーカイブ/パーティションが必要 |
| メトリクス / Observability | なし | Prometheus exporter / OpenTelemetry 未対応 |
| TLS | gRPCサーバは plaintext のみ | 本番では TLS 証明書設定 or リバースプロキシが必要 |
