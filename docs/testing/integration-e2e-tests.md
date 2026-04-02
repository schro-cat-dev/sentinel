# 統合・E2Eテスト一覧

**テスト数:** 65 (Integration 18 + E2E 47)（`npx vitest run tests/integration/ tests/e2e/` で最新数を確認）

## tests/integration/pipeline.test.ts (18テスト)

SDKローカルパイプラインのE2Eテスト。`Sentinel.initialize()` → `ingest()` の全フロー。

| テスト群 | テスト数 | 検証内容 | なぜ |
|---------|---------|---------|------|
| basic ingestion | 3 | 正常系ingest、traceId生成、hashChainValid | パイプラインの最小動作確認 |
| PII masking | 3 | EMAIL/CREDIT_CARD/複合マスキング | マスキングがingestを通じて動作 |
| event detection + task | 4 | critical→task、security→task、compliance→task、無検知 | イベント検知→タスク生成の連携 |
| hash chain | 3 | 連続ログのチェーン、enableHashChain=false | ハッシュチェーンの完全性 |
| execution levels | 3 | AUTO→dispatched、MANUAL→blocked、handler invocation | タスク実行レベルの分岐 |
| concurrent | 2 | 50並行ingest、高負荷 | 並行安全性（mutex） |

## tests/e2e/sdk-server.test.ts (15テスト)

**実際にGoサーバをビルド→起動し、gRPC経由で通信するクロスコンポーネントテスト。**

### テスト環境

- Goバイナリを `go build` でコンパイル（beforeAll, 120秒タイムアウト）
- ランダムポートでサーバ起動（`net.createServer` port 0方式）
- gRPC HealthCheck RPCでready待ち（最大15秒ポーリング）
- テスト終了後にSIGTERM→5秒後SIGKILL（afterAll）
- `go` コマンド不在時はdescribe.skipで全スキップ

### テスト設計

| テスト群 | テスト数 | 検証内容 | なぜ |
|---------|---------|---------|------|
| basic ingestion (remote) | 2 | SDK→gRPC→Server→レスポンス | プロトコル互換性の基本確認 |
| PII masking | 2 | サーバ側でmasked=true | Go側のマスキングが動作 |
| hash chain | 1 | 5連続ログのhashChainValid | チェーン状態管理の整合性 |
| error handling | 2 | 空メッセージ拒否、接続不能エラー | エラーパスのプロトコル確認 |
| dual mode | 2 | ローカル+リモート同時、リモート失敗時フォールバック | dualモードの実通信テスト |
| transport timeout | 2 | タイムアウト発火、タイムアウト+フォールバック | ネットワーク遅延のシミュレーション |
| health check | 2 | サーバヘルスチェック、transport helper | 生存確認の動作 |
| direct gRPC | 2 | 生gRPC呼出のレスポンス形状、criticalログのタスク生成 | Protobuf契約の直接検証 |

### テスト環境設定

```yaml
# tests/e2e/test-server-config.yaml
server:
  addr: ":0"  # ランダムポート
security:
  enable_masking: true
  enable_hash_chain: true
  hmac_key: "test-key-..."  # 32バイト以上
pipeline:
  service_id: "e2e-test"
store:
  driver: sqlite
  dsn: "file::memory:"  # インメモリDB
```

## tests/e2e/server-config-matrix.test.ts (25テスト)

**異なる設定でGoサーバを起動し、設定内容に応じた挙動変化を検証するコンフィグマトリクステスト。**

各テストが独立したサーバインスタンスを起動→検証→クリーンアップする設計。

| テスト群 | テスト数 | 検証内容 | なぜ |
|---------|---------|---------|------|
| ConfigSummary verification | 2 | HealthCheckが設定内容を正しく返す | SDK/Server設定整合性 |
| HMAC key and hash chain | 2 | ハッシュチェーン有効/無効の挙動 | セキュリティ機能のon/off確認 |
| Full pipeline | 2 | ログ投入→検知→タスク生成→レスポンス | 正常系E2Eフロー |
| Empty rules / all disabled | 2 | 空ルール・全機能無効でもサーバ動作 | エッジケース |
| Auth (API key) | 3 | 認証なし・有効キー・無効キー | 認証バリデーション |
| SDK dual mode | 1 | ローカル+リモート同時処理 | dualモード設定変更 |
| Response module toggle | 2 | response有効/無効でthreat_responses変化 | integration flag切替 |
| Connection timeout / fallback | 2 | タイムアウト・フォールバック | 異常系ネットワーク |
| Masking rule variations | 1 | PHONE-onlyルールでのマスキング動作 | ルール構成バリエーション |
| Multiple task rules | 1 | 3ルール構成で異なるイベント→別ルール発火 | タスクルールマッチング |
| ConfigSummary detectionRulesCount | 1 | detection_rulesのカウント検証 | 設定値精度 |
| Ensemble detection | 1 | ensemble有効時のスコア集約検知 | ensemble検知パイプライン |
| Anomaly detection | 1 | anomaly有効時の正常動作 | 異常検知パイプライン |
| Authorization (RBAC) | 3 | writer/reader権限、authz有効/無効 | RBAC権限制御 |
| Full feature config | 1 | masking+hash+ensemble+response全有効 | 全機能組み合わせ |

### 発見事項

- **`masked` フィールドの意味（修正済み）**: `masked=true` は「PIIが実際に検出・除去された」ことを示す。`enable_masking=true` でもPIIが含まれていなければ `masked=false` が返る。比較対象: message, actorId, input, tags, details, AIContext.ReasoningTrace, AgentBackLog[].Result の全7フィールド。`GetLog` RPC でマスク後の保存内容を直接検証可能。
- **Context Key 不一致（修正済み）**: `grpc/interceptors.go` の `clientIDKey = "clientID"` と `middleware/authorizer.go` の `ctxKeyClientID = "client_id"` が不一致だった。grpc interceptor が `middleware.ContextWithClientID()` を使うように修正し、client_roles による RBAC 権限切替が正しく機能するようになった。

### なぜE2Eテストが必要か

- **Protobuf型変換**: TS SDKのLog型とGo側のprotobuf間の変換が正しいか
- **マスキング一貫性**: TS側とGo側のマスキングルール解釈が一致するか
- **エラーコード**: gRPCステータスコードの翻訳が正しいか
- **設定反映**: Go側のconfig.yamlとSDK側のconfigが整合するか
- **設定バリエーション**: 機能フラグの組み合わせで挙動が正しく変化するか
