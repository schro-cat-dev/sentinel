# Config × Transport 交差テスト仕様書

- **日付**: 2026-04-02
- **対象**: `tests/config/yaml-transport-integration.test.ts` (105件)
- **目的**: YAML config の各フィールドが TaskTransport の動作に正しく反映されるかを全組み合わせで検証

---

## 1. テスト構成

| セクション | テスト数 | 対象 |
|-----------|----------|------|
| 1. 単一トランスポート正常系 | 6 | console / http_webhook 基本動作 |
| 2. enabled/disabled マトリクス | 7 | enabled × type の全パターン |
| 3. execution level × transport | 7 | AUTO / SEMI_AUTO / MANUAL / MONITOR / requireHumanApproval |
| 4. detection match/no-match × transport | 4 | 検知あり/なし、ルールあり/なし |
| 5. dispatch 結果マトリクス | 10 | HTTP 200/201/400/429/500/503、ECONNREFUSED/ETIMEDOUT、mixed |
| 6. user-injected + config merge | 6 | config only / user only / both / 実行順序 / 片方失敗 |
| 7. handler + transport 共存 | 6 | handler のみ / transport のみ / 両方 / 片方失敗 / deregister |
| 8. ライフサイクル | 6 | init→dispatch→shutdown / re-init / double shutdown / ingest after shutdown |
| 9. config バリデーション | 8 | name / type / endpoint / method のバリデーションエラー |
| 10. SSRF 防御マトリクス | 16 | 10種のプライベートIP拒否 + 4種の許可IP + HTTP拒否 + allowInsecure |
| 11. エッジケース | 4 | 空配列 / no config / タスクbody検証 / 10並列transport |
| 12. masking × transport | 3 | masking on/off でタスク内メッセージの変化検証 |
| 13. hashChain × transport | 3 | hashChain on/off で結果の hashChainValid 検証 |
| 14. callbacks × transport | 5 | onTaskGenerated / onTaskDispatched の発火順序と結果伝播 |
| 15. metrics × transport | 4 | onTaskDispatch / onIngest の発火と例外耐性 |
| 16. custom detectionRules × transport | 2 | カスタム検知ルール → タスク → transport E2E |
| 17. validationLimits × transport | 3 | oversized / empty メッセージでバリデーション拒否 |
| 18. environment × transport | 5 | 全5環境 (production/staging/development/local/test) |
| **合計** | **105** | |

---

## 2. 各テストの仕様詳細

### セクション 1: 単一トランスポート正常系

| ID | テスト名 | 期待動作 | 検証内容 |
|----|----------|----------|----------|
| 1-01 | console: creates, dispatches, outputs structured JSON | YAML type=console → ConsoleTaskTransport 生成 → dispatch → console.info 呼出し | console.info の JSON 出力に sentinel_task.eventName, sourceLog.message, timestamp を含む |
| 1-02 | http_webhook POST: dispatches via fetch | YAML type=http_webhook → HttpWebhookTransport 生成 → fetch 呼出し | URL, method=POST, body に eventName と sourceLog.message を含む |
| 1-03 | http_webhook PUT: method respected | YAML method=PUT → fetch の method が PUT | fetch mock の RequestInit.method === "PUT" |
| 1-04 | http_webhook custom headers | YAML headers → fetch headers にマージ | Authorization, X-Custom, Content-Type の全ヘッダー検証 |
| 1-05 | allow_insecure: HTTP localhost allowed | YAML allow_insecure=true → http://localhost 許可 | 例外なし + fetch 呼出し |
| 1-06 | console transport name preserved | YAML name → transport の name フィールドに反映 | console.info が呼ばれる |

### セクション 2: enabled/disabled マトリクス

| ID | 条件 | 期待動作 | 検証内容 |
|----|------|----------|----------|
| 2-01 | enabled=true (明示) | transport dispatch される | console.info 呼出し |
| 2-02 | enabled 省略 (デフォルト=true) | transport dispatch される | console.info 呼出し |
| 2-03 | enabled=false | transport dispatch されない | console.info 未呼出し |
| 2-04 | 2 enabled + 1 disabled | enabled のみ dispatch | console + fetch 呼出し、disabled は未呼出し |
| 2-05 | 全 disabled | dispatch なし、タスクは生成 | console.info 未呼出し、tasksGenerated > 0 |
| 2-06 | disabled + SSRF endpoint | init 成功（SSRF チェックスキップ） | 例外なし |
| 2-07 | enabled + SSRF endpoint | init 失敗（SSRF チェック） | 例外あり |

### セクション 3: execution level × transport

| ID | level | confirm | 期待 status | transport 呼出し |
|----|-------|---------|-------------|-----------------|
| 3-01 | AUTO | - | dispatched | あり |
| 3-02 | SEMI_AUTO | handler なし | dispatched (AUTO fallback) | あり |
| 3-03 | SEMI_AUTO | true | dispatched | あり |
| 3-04 | SEMI_AUTO | false | blocked_approval | なし |
| 3-05 | MANUAL | - | blocked_approval | なし |
| 3-06 | MONITOR | - | skipped | なし |
| 3-07 | AUTO + requireHumanApproval | - | blocked_approval | なし |

### セクション 4: detection match/no-match

| ID | 条件 | 期待タスク数 | transport |
|----|------|-------------|-----------|
| 4-01 | event matches (isCritical + level 6) | > 0 | 呼出し |
| 4-02 | event does NOT match (level 1) | 0 | 未呼出し |
| 4-03 | no task rules | 0 | 未呼出し |
| 4-04 | 2 matching rules → 2 tasks | 2 | 2回呼出し |

### セクション 5: dispatch 結果マトリクス

| ID | HTTP status / error | task status | error 内容 |
|----|---------------------|-------------|------------|
| 5-01 | 200 | dispatched | なし |
| 5-02 | 201 | dispatched | なし |
| 5-03 | 400 | failed | "400" |
| 5-04 | 429 | failed | "429" |
| 5-05 | 500 | failed | "500" |
| 5-06 | 503 | failed | "503" |
| 5-07 | ECONNREFUSED | failed | "ECONNREFUSED" |
| 5-08 | ETIMEDOUT | failed | "ETIMEDOUT" |
| 5-09 | 1 success + 1 failure | failed | "503" (集約) |
| 5-10 | console OK + webhook fail | failed | console は呼出し済み |

### セクション 12: masking × transport

| ID | masking.enabled | 期待 |
|----|-----------------|------|
| 12-01 | true | sourceLog.message に `[MASKED_EMAIL]` が含まれ、元のメールは含まれない |
| 12-02 | false | sourceLog.message に元のメールがそのまま含まれる |
| 12-03 | true + console | console.info 出力にマスク済みメッセージ |

### セクション 13: hashChain × transport

| ID | enableHashChain | 期待 |
|----|-----------------|------|
| 13-01 | true | result.hashChainValid === true |
| 13-02 | false | result.hashChainValid === false |
| 13-03 | true + 連続ingest | 2回とも hashChainValid=true、traceId は異なる |

### セクション 14: callbacks × transport

| ID | callback | 期待動作 |
|----|----------|----------|
| 14-01 | onTaskGenerated | transport dispatch より前に発火（実行順序検証） |
| 14-02 | onTaskGenerated throws | transport は依然 dispatch される（emitSafe 保護） |
| 14-03 | onTaskDispatched | dispatch 後に result.status="dispatched" で発火 |
| 14-04 | onTaskDispatched + transport fail | result.status="failed" + error="500" で発火 |
| 14-05 | onError + transport exception | fetch 例外が発生しても pipeline は続行 |

### セクション 15: metrics × transport

| ID | hook | 期待 |
|----|------|------|
| 15-01 | onTaskDispatch + 成功 | result.status="dispatched" で発火 |
| 15-02 | onTaskDispatch + 失敗 | result.status="failed" で発火 |
| 15-03 | onTaskDispatch throws | pipeline 続行（例外を握りつぶし） |
| 15-04 | onIngest + transport | 両方発火 |

### セクション 17: validationLimits × transport

| ID | 入力 | 期待 |
|----|------|------|
| 17-01 | message 70000文字 (> 65536) | ValidationError、transport 未呼出し |
| 17-02 | message 1000文字 | transport dispatch |
| 17-03 | message 空文字 | ValidationError、transport 未呼出し |

### セクション 18: environment × transport

| ID | environment | 期待 |
|----|-------------|------|
| 18-01 ~ 18-05 | production / test / local / development / staging | 全環境で transport は正常 dispatch |

---

## 3. 対応しなかったケース（と理由）

| ケース | 理由 |
|--------|------|
| whitelist.level × transport | whitelist は init 時の config 検証であり、transport dispatch 前に reject される。config-loader テストでカバー済み。 |
| errorRouting × transport failure | ErrorRouter は emitSafe（コールバック例外）のルーティングであり、transport の dispatch 結果はコールバック例外ではなく TaskResult として返される。交差点は onTaskDispatched callback 経由でカバー済み（14-04）。 |
| security.signingKeyId × transport | signingKeyId は hash chain の署名キー識別子であり、task オブジェクトには含まれない（ログの hash フィールドにのみ反映）。transport に直接影響しない。 |

---

## 4. テスト結果

| 項目 | 値 |
|------|------|
| テストファイル | `tests/config/yaml-transport-integration.test.ts` |
| テスト数 | 105 |
| パス | 105 |
| 失敗 | 0 |
| 全体テスト数 | 2778 (77ファイル) |
| 型チェック | エラー 0 |
