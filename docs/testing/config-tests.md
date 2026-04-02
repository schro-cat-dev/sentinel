# 設定マトリクステスト一覧・全設定パターン検証

**テスト数:** 603（`npx vitest run tests/config/` で最新数を確認）
**対象:** `tests/config/`

## テストファイル一覧

### config-matrix.test.ts (14テスト)

`createDefaultConfig` のdeep-merge挙動を検証。設定の組合せが意図通りマージされるか。

| テスト群 | テスト数 | 検証内容 | なぜ |
|---------|---------|---------|------|
| required fields | 1 | projectName, serviceId の注入 | 必須フィールドの基本契約 |
| defaults | 7 | 全デフォルト値の検証 | 未指定時のフォールバック値が正しいか |
| deep-merge: masking | 3 | 部分的override時のフィールド保持 | NEW-09修正: 浅いスプレッドでsecurity設定が消える問題の防止 |
| deep-merge: security | 2 | enableHashChain + signingKeyId の独立性 | 片方を指定しても他方のデフォルトが消えない |
| environment variants | 5 | 5種の環境値すべて受け入れ | TypeScript型が正しくランタイムでも動作するか |

### config-pipeline-reflection.test.ts (38テスト)

**各config値がパイプライン動作に実際に反映されるか**のE2Eテスト。Sentinelシングルトンを使用。

| テスト群 | テスト数 | 検証内容 | なぜ |
|---------|---------|---------|------|
| masking.enabled | 3 | ON→PII除去, OFF→素通し, ONでルール空 | マスキング有効/無効のスイッチが動作するか |
| masking.preserveFields | 2 | traceId保護あり/なし | preserveFieldsがKEY_MATCHに優先するか |
| security.enableHashChain | 3 | ON→hash生成, チェーン順序, OFF→hashなし | hash chain有効/無効とチェーン連続性 |
| taskRules | 5 | ルールマッチ/不一致/空/複数/重大度閾値 | ルール設定がタスク生成に正しく反映 |
| callbacks | 5 | onLogProcessed/onTaskGenerated/onTaskDispatched/onError/全undefined | 全コールバックの接続と例外安全性 |
| detection events | 8 | 5イベントタイプ + 無検知 + AI_AGENTスキップ + isCritical例外 | 検知条件の全分岐 |
| execution levels | 6 | AUTO/MANUAL/MONITOR/requireHumanApproval/SEMI_AUTO/timeoutMs | 全実行レベルとガードレール |
| combined config | 2 | フルON/全OFF | 全設定を組み合わせた統合動作 |
| logger injection | 1 | カスタムlogger注入 | SentinelLogger DIの動作確認 |
| shutdown | 2 | shutdown後のシングルトン/再初期化 | ライフサイクル管理 |

### transport-modes.test.ts (34テスト)

**Transport設定の全パターン**をモックtransportで検証。

| テスト群 | テスト数 | 検証内容 | なぜ |
|---------|---------|---------|------|
| local mode | 6 | デフォルト/明示local/検知結果/transport無視 | localモードが正しくリモートを無視 |
| remote mode | 12 | 正常送信/エラー伝播/fallback/timeout/マスク適用/timeout+fallback | remote固有の全異常系 |
| dual mode | 9 | 両方成功/リモート失敗/onError/traceId一致/timeout/タスク生成 | dual特有のローカル+リモートの組合せ |
| shutdown | 7 | close()呼出/エラー安全/再初期化 | transport lifecycle |

### masking-rules-exhaustive.test.ts (73テスト)

**全マスキングルールタイプの正常系/異常系/エッジケース**。

| テスト群 | テスト数 | 検証内容 | なぜ |
|---------|---------|---------|------|
| PII_TYPE CREDIT_CARD | 7 | ハイフン/スペース/連続数字/13桁/19桁/複数/非カード | クレジットカードパターンの網羅 |
| PII_TYPE PHONE | 7 | 日本形式/+81/ハイフンなし/0X0/固定電話/スペース/短い番号 | 電話番号パターンの網羅 |
| PII_TYPE EMAIL | 7 | 標準/+アドレス/サブドメイン/ドット/特殊文字/複数/非メール | メールパターンの網羅 |
| PII_TYPE GOV_ID | 4 | 12桁/スペース囲み/11桁不一致/13桁不一致 | 政府ID境界値 |
| REGEX rules | 6 | 基本/グローバル/キャプチャ/不一致/空置換/特殊文字 | カスタムパターンの全分岐 |
| KEY_MATCH | 11 | 完全一致/大小文字/複数キー/カスタム置換/デフォルト/ネスト/深いネスト/各型/不一致/文字列/空 | キーマッチの全パターン |
| combined | 4 | PII+KEY/REGEX+PII/全種/KEY優先 | ルール組合せの相互作用 |
| edge cases | 17 | null/undefined/数値/真偽値/深度/循環/配列/preserveFields/Unicode | 極端な入力 |
| full log masking | 6 | message/input/details/tags/sensitiveKeys/combined | ログ全体マスクの検証 |

### validation-normalizer-exhaustive.test.ts (159テスト)

**全入力フィールドの正常/異常/エッジケース**。

| テスト群 | テスト数 | 検証内容 |
|---------|---------|---------|
| message field | 10 | 必須/型/空/whitespace/最大長/null byte/境界値 |
| type field | 11 | 7種有効/無効/undefined/空文字/小文字 |
| level field | 11 | 1-6有効/0,7,float,負数,文字列,NaN,Infinity無効 |
| origin field | 6 | SYSTEM/AI_AGENT有効/無効/undefined/小文字 |
| isCritical | 4 | true/false/非boolean/undefined |
| tags | 12 | 有効/空/最大100/101/key長/category長/非配列/非文字列key/category |
| resourceIds | 6 | 有効/空/最大100/101/非配列/undefined |
| details | 5 | 有効/最大長/超過/undefined/null |
| agentBackLog | 5 | 有効object/配列拒否/文字列拒否/undefined/null |
| aiContext | 7 | 有効/負loopDepth/文字列loopDepth/ゼロ/大きい値/undefined/null |
| normalizer defaults | 30+ | 全フィールドのデフォルト値・passthrough・serviceId注入 |
| edge cases | 18 | 空入力/全フィールド/未知フィールド/Unicode(日本語/絵文字) |

### size-limits.test.ts (25テスト)

**ValidationLimitsの設定可能なサイズ制限の全パターン**。

| テスト群 | テスト数 | 検証内容 | なぜ |
|---------|---------|---------|------|
| size limits | 25 | actorId/traceId/spanId/boundary/traceInfo/input JSON/total logの各フィールドサイズ制限。デフォルト値・カスタム値・境界値・超過時エラー | 全フィールドのサイズ制限が正しく適用されるか |
