# ユニットテスト一覧・設計根拠

**テスト数:** 739（`npx vitest run tests/unit/` で最新数を確認）
**対象:** `tests/unit/`

## テストファイル一覧

### core/ — パイプラインコア

#### ingestion-engine.test.ts (12テスト)

パイプラインオーケストレーターの単体テスト。IngestionEngineに直接依存を注入してテスト。

| テスト | 分類 | なぜこのケースか |
|--------|------|----------------|
| agentBackLog passthrough | 正常系 | BUG-01修正: normalizeでagentBackLogが消失していた問題の再発防止 |
| traceInfo passthrough | 正常系 | BUG-02修正: normalizeでtraceInfoが消失していた問題の再発防止 |
| undefined agentBackLog | エッジ | optional fieldがundefinedでもクラッシュしない |
| onTaskGenerated fires | 正常系 | BUG-03修正: コールバック未接続だった問題の再発防止 |
| onTaskDispatched fires | 正常系 | BUG-04修正: 同上 |
| onLogProcessed with hash | 正常系 | hash chain更新後にコールバックが呼ばれることを検証 |
| onTaskGenerated throws | 異常系 | コールバック例外がパイプラインを壊さない |
| normalizeOnly with masking | 正常系 | remote送信前にマスキングが適用される |
| normalizeOnly without masking | 正常系 | masking disabled時は素通し |
| getLastProcessedLog | 正常系 | dual mode用ログ再利用メカニズム |
| concurrent hash chain | エッジ | 10並行呼出でhash chainが破壊されない（mutex検証） |
| callback error resilience | 異常系 | onLogProcessedの例外後も次のingestが正常動作 |

#### event-detector.test.ts (19テスト)

イベント検知ルールの網羅テスト。

| テスト群 | テスト数 | なぜ |
|---------|---------|------|
| critical failure | 4 | isCriticalフラグ最優先の検証。AI_AGENTでもcriticalなら検知 |
| security intrusion | 4 | SECURITY type + level >= 5の閾値検証。level 4は非検知 |
| compliance violation | 4 | "violation"文字列マッチ。大文字小文字混合も対応 |
| SLA violation | 3 | type=SLA + level >= 4の組合せ |
| AI loop prevention | 2 | origin=AI_AGENTのスキップとisCritical例外 |
| no detection | 2 | 通常ログで検知なし |

#### log-normalizer.test.ts (26テスト)

正規化のデフォルト値注入と防御的フォールバック。

| テスト群 | テスト数 | なぜ |
|---------|---------|------|
| defensive defaults | 4 | validate()削除後のフォールバック挙動。空/whitespace/長大メッセージ |
| defaults | 12 | traceId/timestamp/boundary/type/level/origin等の全デフォルト値 |
| type validation | 3 | 7種の有効type + 無効typeのフォールバック |
| message trimming | 2 | 前後空白のtrim |
| field preservation | 5 | spanId/aiContext/tags等のpassthrough |

#### task-executor-extended.test.ts (6テスト)

MEM-01/API-03修正のリグレッションテスト。

| テスト | なぜ |
|--------|------|
| removeHandlers | MEM-01: ハンドラ無限成長防止のAPI検証 |
| clearHandlers | 全ハンドラ解除の検証 |
| nonexistent type remove | エッジ: 存在しないtypeの除去でクラッシュしない |
| timeout exceeded | API-03: guardrails.timeoutMs強制のタイムアウト発火 |
| timeout not exceeded | 正常系: 時間内完了で正常dispatch |
| timeout=0 skip | エッジ: timeoutMs=0でタイムアウト無効 |

### intelligence/ — タスク生成・実行

#### task-generator.test.ts (15テスト)

ルールインデックス、重大度マッチング、タスク生成。

#### task-executor.test.ts (15テスト)

実行レベル分岐(AUTO/SEMI_AUTO/MANUAL/MONITOR)、ガードレール(requireHumanApproval)。

#### severity-classifier.test.ts (13テスト)

isCriticalオーバーライド、イベント種別×ログレベルの重大度マッピング。

### security/ — 暗号・マスキング

#### integrity-signer.test.ts (15テスト)

SHA-256ハッシュ計算、決定論的シリアライズ、チェーン状態管理、timingSafeEqual検証。

#### masking-service.test.ts (23テスト)

プリミティブ処理、REGEX/PII_TYPE/KEY_MATCHルール、循環参照、depth制限。

### validation/

#### log-validator.test.ts (24テスト)

SDK公開API境界のランタイム検証。message必須、type/level/origin ホワイトリスト。

### transport/

#### transport.test.ts (7テスト)

local/remote/dual モードの基本動作。

### remaining-backlog.test.ts (14テスト)

OBS-03/API-02/DEAD-04/CFG-02修正のリグレッションテスト。SentinelLogger DI、SEMI_AUTO確認ハンドラ、AI_ACTION_REQUIRED検知、onErrorコールバック。
