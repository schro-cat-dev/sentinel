# Known Limitations & N/A Items

現時点で未対応・制約がある項目の一覧。最終更新: 2026-03-28

---

## 対応済み

| 項目 | 修正内容 |
|---|---|
| Pipeline永続化失敗がサイレント | `Degraded` フラグ + `Warnings` 伝播。`FailOnPersistError=true` でエラー返却 |
| Deduplicator メモリリーク | 全件クリーンアップ + `maxSize` ガード |
| IPBlockAction メモリリーク | TTL時のバックグラウンドクリーンアップgoroutine |
| Details map値の長さ未検証 | normalizer.go でキー長/値長/サニタイズ追加 |
| SDK Details/AgentBackLog 検証なし | log-validator.ts に追加 |
| HealthCheck常にSERVING | Store接続チェック → DB異常で `DEGRADED` |
| アクセスログなし | `AuditLogUnaryInterceptor` で全gRPCリクエスト記録 |
| データ暗号化 | SQLCipher (AES-256-CBC)。`store.driver: sqlite_encrypted` + `SENTINEL_STORE_ENCRYPTION_KEY` |
| TLS | `server.tls_cert_file` + `server.tls_key_file` でgRPC TLS有効化 |
| キーローテーション | `AddPreviousKey()` + `VerifyHashWithRotation()` で旧キー検証 |
| Store ドライバ切り替え | `store/factory.go` NewStore() で `sqlite` / `sqlite_encrypted` 選択 |

---

## 実プロバイダ未接続（Mock/I/F のみ）

アダプタI/F定義済み。env var 未設定時はスキップ。

| 項目 | 接続に必要なもの |
|---|---|
| AI分析エージェント | APIキー + `Provider` I/F 実装 |
| Slack/Gmail/Discord | 各環境変数（env varドキュメント参照） |
| AWS/GCP/Azure ブロック | 各クラウドSDK + `execFn` 注入 |

---

## テスト

| 項目 | 現状 |
|---|---|
| SDK→Server ネットワーク統合テスト | なし（両方同時起動が必要） |
| 負荷テスト / ベンチマーク | 新モジュール未カバー |
| Fuzzing | 未実装 |

---

## インフラ / 運用

| 項目 | 現状 |
|---|---|
| Docker / Kubernetes | ドキュメントのみ（実ビルド未検証） |
| CI/CD | なし |
| ログローテーション | SQLite肥大化制御なし |
| メトリクス / Observability | なし |
| gRPC streaming | 未対応 |
