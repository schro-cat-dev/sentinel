# 設定フィールドの実装反映状況

```yaml
analyzed_at: "2026-04-01"
based_on: "b14d263 + pending"
status: current
last_updated: "2026-04-01T13:50:00Z"
```

## SentinelConfig 全フィールド解析

| フィールド | 定義箇所 | 消費箇所 | ステータス |
|-----------|---------|---------|-----------|
| `projectName` | sentinel-config.ts:10 | **なし** | **GAP** — 定義のみ。ログにも含まれない |
| `serviceId` | sentinel-config.ts:13 | LogNormalizer constructor | ✅ 反映済み |
| `environment` | sentinel-config.ts:16 | **なし** | **GAP** — 条件分岐なし |
| `masking.enabled` | sentinel-config.ts:20 | ingestion-engine.ts:82 | ✅ 反映済み |
| `masking.rules` | sentinel-config.ts:21 | ingestion-engine.ts:84-85 | ✅ 反映済み |
| `masking.preserveFields` | sentinel-config.ts:22 | ingestion-engine.ts:86 | ✅ 反映済み |
| `security.enableHashChain` | sentinel-config.ts:27 | ingestion-engine.ts:106 | ✅ 反映済み |
| `security.signingKeyId` | sentinel-config.ts:28 | **なし** | **GAP** — デジタル署名未実装 |
| `taskRules` | sentinel-config.ts:32 | TaskGenerator constructor (index.ts:46) | ✅ 反映済み |
| `onLogProcessed` | sentinel-config.ts:35 | ingestion-engine.ts:116 | ✅ 反映済み |
| `onTaskGenerated` | sentinel-config.ts:36 | ingestion-engine.ts:100 | ✅ 修正済 |
| `onTaskDispatched` | sentinel-config.ts:37 | ingestion-engine.ts:102 | ✅ 修正済 |
| `onError` | sentinel-config.ts:40 | ingestion-engine.ts emitSafe, index.ts dual | ✅ 新規追加 |

## createDefaultConfig deep-merge検証

| ネスト | マージ方式 | 正しいか |
|--------|----------|---------|
| `masking` | deep-merge (`{...defaults.masking, ...overrides.masking}`) | ✅ |
| `security` | deep-merge (`{...defaults.security, ...overrides.security}`) | ✅ |
| `taskRules` | 浅いマージ（配列全置換） | ✅ 適切 |
| callbacks | 浅いマージ | ✅ 適切 |

## GAP詳細

### projectName: 定義のみ

`projectName` は必須フィールドだがパイプラインのどこにも注入されない。ログの `boundary` や `serviceId` には入らず、ハッシュ計算にも含まれず、タスク生成にも使われない。

**推奨:** ログの `boundary` フォールバックに使用するか、将来のマルチプロジェクト対応のためにメタデータとして保持する意図を明文化する。

### environment: 条件分岐なし

5つの環境値が定義されているが、パイプライン内でどの環境でも同じ動作をする。

**推奨:** 以下の条件分岐を追加するか、意図的に不使用であることを明文化する。
- `production`: masking強制ON、console.warn抑制
- `development`/`local`: 詳細エラー出力
- `test`: 決定論的UUID

### onTaskGenerated / onTaskDispatched: 未実装

設定インターフェースで宣言されているが、`IngestionEngine` で呼び出されていない。利用者が設定しても何も起きない。

**推奨:** `handleInternal()` 内のタスク生成・ディスパッチ後にコールバックを呼出。
