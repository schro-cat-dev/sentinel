# 設定フィールドの実装反映状況

```yaml
analyzed_at: "2026-04-02"
based_on: "9d6b74e"
status: current
last_updated: "2026-04-02"
```

## SentinelConfig 全フィールド解析

| フィールド | 定義箇所 | 消費箇所 | ステータス |
|-----------|---------|---------|-----------|
| `projectName` | sentinel-config.ts:10 | LogNormalizer:37 で正規化ログに注入 | ✅ 反映済み |
| `serviceId` | sentinel-config.ts:13 | LogNormalizer constructor | ✅ 反映済み |
| `environment` | sentinel-config.ts:16 | reset()で環境チェック、logger抑制 | ✅ CFG-02対応済み |
| `masking.enabled` | sentinel-config.ts:20 | ingestion-engine.ts:82 | ✅ 反映済み |
| `masking.rules` | sentinel-config.ts:21 | ingestion-engine.ts:84-85 | ✅ 反映済み |
| `masking.preserveFields` | sentinel-config.ts:22 | ingestion-engine.ts:86 | ✅ 反映済み |
| `security.enableHashChain` | sentinel-config.ts:27 | ingestion-engine.ts:106 | ✅ 反映済み |
| `security.signingKeyId` | sentinel-config.ts:28 | **なし** | **GAP** — デジタル署名未実装 |
| `taskRules` | sentinel-config.ts:32 | TaskGenerator constructor (index.ts:46) | ✅ 反映済み |
| `onLogProcessed` | sentinel-config.ts:35 | ingestion-engine.ts:116 | ✅ 反映済み |
| `onTaskGenerated` | sentinel-config.ts:36 | ingestion-engine.ts:159 | ✅ 修正済 |
| `onTaskDispatched` | sentinel-config.ts:37 | ingestion-engine.ts:161 | ✅ 修正済 |
| `onError` | sentinel-config.ts:40 | ingestion-engine.ts emitSafe, index.ts dual | ✅ 新規追加 |

## createDefaultConfig deep-merge検証

| ネスト | マージ方式 | 正しいか |
|--------|----------|---------|
| `masking` | deep-merge (`{...defaults.masking, ...overrides.masking}`) | ✅ |
| `security` | deep-merge (`{...defaults.security, ...overrides.security}`) | ✅ |
| `taskRules` | 浅いマージ（配列全置換） | ✅ 適切 |
| callbacks | 浅いマージ | ✅ 適切 |

## GAP詳細

### projectName: ✅ 対応済み

`LogNormalizer` のコンストラクタで受け取り、`normalize()` でログオブジェクトに `projectName` として注入。

### environment: ✅ 対応済み (CFG-02)

`reset()` 内で環境チェック（production時エラーログ、非test/local時警告）。logger抑制にも使用。

### onTaskGenerated / onTaskDispatched: ✅ 対応済み (BUG-03/04)

`ingestion-engine.ts:159-161` で `emitSafe` 経由でコールバック呼出実装済み。
