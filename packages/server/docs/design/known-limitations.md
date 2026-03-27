# Known Limitations & N/A Items

現時点で未対応・制約がある項目の一覧。

---

## 実プロバイダ未接続（Mock/I/F のみ）

| 項目 | 現状 | 接続に必要なもの |
|---|---|---|
| AI分析エージェント | `MockProvider` (固定レスポンス) | Anthropic/OpenAI APIキー + 実Provider実装 |
| Slack通知 | `SlackNotifier` I/F実装済み、env var未設定時スキップ | `SENTINEL_SLACK_WEBHOOK_URL` 環境変数 |
| Gmail通知 | `GmailNotifier` I/F実装済み | `SENTINEL_GMAIL_FROM` + `SENTINEL_GMAIL_PASSWORD` 環境変数 |
| Discord通知 | `DiscordNotifier` I/F実装済み | `SENTINEL_DISCORD_WEBHOOK_URL` 環境変数 |
| AWS IPブロック | `AWSBlockAction` アダプタI/Fのみ、execFn未注入 | AWS SDK + IAMロール + execFn実装 |
| GCP IPブロック | `GCPBlockAction` アダプタI/Fのみ | GCP SDK + サービスアカウント + execFn実装 |
| Azure IPブロック | `AzureBlockAction` アダプタI/Fのみ | Azure SDK + 認証情報 + execFn実装 |

---

## SDK → Server gRPC接続

| 項目 | 現状 | 備考 |
|---|---|---|
| SDK gRPCクライアント | `RemoteTransport` I/F定義済み、`examples/grpc-transport.ts` にサンプル | SDK本体はzero-dep維持。利用側が `@grpc/grpc-js` を追加して注入する設計 |
| SDK→Server 自動テスト | なし | 実接続テストには両方を同時起動する統合テスト基盤が必要 |

---

## ブロック実行

| 項目 | 現状 | 備考 |
|---|---|---|
| IPブロック | in-memory map（プロセス再起動で消失） | 本番では外部ファイアウォール/WAF連携が必要 |
| `REQUIRE_APPROVAL` モード | gRPC API定義済み、`EnhancedBlockDispatcher` 実装済み | main.go では `ExecModeImmediate` で初期化。config切り替え未実装 |
| `BlockApprovalStore` | インターフェースのみ、SQLite実装なし | 現在はin-memory。永続化にはStore実装が必要 |
| ブロック有効期限(TTL) | 未実装 | 永続ブロックのみ。時間制限付きブロックは未対応 |

---

## 検知

| 項目 | 現状 | 備考 |
|---|---|---|
| MaskingPolicyのYAML設定 | `PipelineConfig` でコード上は対応 | config.yaml からの読み込み変換関数は未実装（main.go で直接設定する必要あり） |
| ApprovalRoutingRules のYAML設定 | config.yaml に該当セクションなし | コード上は `PipelineConfig.RoutingRules` で設定可能 |
| 異常検知のベースライン永続化 | in-memory（再起動でリセット） | 長期ベースラインの蓄積には外部ストレージが必要 |

---

## Proto / gRPC

| 項目 | 現状 | 備考 |
|---|---|---|
| `ListPendingBlocks` | proto定義+ハンドラ枠あり、中身は空レスポンス | `EnhancedBlockDispatcher` にListPending()メソッド追加が必要 |
| ThreatResponse のgRPC取得API | なし | `GetThreatResponsesByTraceID` はStore実装済みだがgRPC APIなし |
| ストリーミング（Server-Sent Events） | 未対応 | リアルタイム通知にはgRPC streaming or WebSocket |

---

## テスト

| 項目 | 現状 | 備考 |
|---|---|---|
| SDK→Server ネットワーク統合テスト | なし | 両方同時起動してgrpc接続するE2Eテスト基盤が必要 |
| 負荷テスト / ベンチマーク | `benchmark_test.go` は既存だが新モジュール未カバー | Ensemble/Anomaly/ThreatResponseのベンチマーク追加が望ましい |
| Fuzzing | 未実装 | `go test -fuzz` でSanitizer/Masking/Detectorのfuzz対象化が可能 |

---

## インフラ / 運用

| 項目 | 現状 | 備考 |
|---|---|---|
| Docker / Kubernetes | なし | Dockerfile / Helm chart 未作成 |
| CI/CD | なし | GitHub Actions でのテスト自動化未設定 |
| ログローテーション | SQLiteファイル肥大化の制御なし | ログ保持期間/アーカイブ/パーティションが必要 |
| メトリクス / Observability | なし | Prometheus exporter / OpenTelemetry 未対応 |
| TLS | gRPCサーバは plaintext のみ | 本番では TLS 証明書設定が必要 |
