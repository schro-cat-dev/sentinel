# 統合・E2Eテスト一覧

**テスト数:** 33 (Integration 18 + E2E 15)

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

### なぜE2Eテストが必要か

- **Protobuf型変換**: TS SDKのLog型とGo側のprotobuf間の変換が正しいか
- **マスキング一貫性**: TS側とGo側のマスキングルール解釈が一致するか
- **エラーコード**: gRPCステータスコードの翻訳が正しいか
- **設定反映**: Go側のconfig.yamlとSDK側のconfigが整合するか
