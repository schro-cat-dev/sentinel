# 2026-04-02: テスト品質強化 — 弱いテストの修正

```yaml
date: "2026-04-02"
scope: tests/ 全体の品質監査 + 修正
tests_before: 2633
tests_after: 2696
weak_tests_found: 23
actually_fixed: 9 (残り14件は精査の結果問題なしと判断)
status: completed
```

---

## 監査方法

全76テストファイルを以下の観点で精査:

1. **Trivial assertions** — `toBeDefined()` のみ、`toBeTruthy()` のみで具体値を検証していない
2. **Missing negative tests** — ハッピーパスのみ、エラーケースなし
3. **Incomplete mock verification** — mock呼出を検証せず
4. **Copy-paste smell** — ほぼ同一の assertion が別テストに存在
5. **Shallow assertions on complex objects** — 配列の `length > 0` のみで内容未検証

---

## 修正した9件

### HIGH (偽の安心感を与えていたもの)

#### 1. sentinel-error.test.ts — stack trace 検証強化

| Before | After |
|--------|-------|
| `expect(err.stack).toContain("SentinelError")` | `toMatch(/at\s+/)` + `toMatch(/\.ts:\|\.js:/)` でファイル名・行番号の存在を検証 |

#### 2. task-generator.test.ts — タスク内容検証追加

| Before | After |
|--------|-------|
| `expect(tasks.length).toBeGreaterThan(0)` | タスクの `eventName`, `ruleId`, `severity`, `actionType`, `executionLevel`, `guardrails.timeoutMs` を個別検証 |

#### 3. ingestion-engine.test.ts — agentBackLog 全フィールド検証

| Before | After |
|--------|-------|
| `toBeDefined()` + `agentId` のみ | `taskId`, `status`, `model` も検証 |

### MEDIUM (カバレッジ不足)

#### 4-6. masking-service.test.ts — PII マスキング強化 (3件)

| Before | After |
|--------|-------|
| `not.toContain("4111")` のみ | `toContain("[MASKED_CREDIT_CARD]")` で置換マーカーも検証 |
| 負のテストなし | `"Order #12345 confirmed"` 等が誤マスクされないことを検証 (3件追加) |

#### 7. masking-service.test.ts — 循環参照テスト強化

| Before | After |
|--------|-------|
| `expect(result).toBeDefined()` | `result.name === "test"` (非循環フィールド保持) + `result.self === "[CIRCULAR_REFERENCE_OR_TOO_DEEP]"` (置換確認) |

#### 8. sentinel.test.ts — deregister 動作検証

| Before | After |
|--------|-------|
| `deregister()` 呼ぶだけで効果を検証なし | ingest → handler呼出確認 → deregister → ingest → handler非呼出確認 |

#### 9. event-detector.test.ts — IP デフォルト値テスト追加

| Before | After |
|--------|-------|
| 空配列 `tags: []` のみ | `tags: [{key: "region", ...}, {key: "env", ...}]` (ipキーなしのtags)でもデフォルト `"0.0.0.0"` を検証 |

### 追加テスト

#### 10. remaining-backlog.test.ts — logger.warn 呼出テスト追加

マスキングルールが例外をthrowした場合に `logger.warn("Masking rule failed: REGEX")` が呼ばれることを検証。
既存テストは「呼ばれない」ことの検証のみだったため、正のケースを追加。

---

## 精査の結果「問題なし」と判断した14件

| テスト | 判断理由 |
|--------|---------|
| severity-classifier:19-36 | 異なる `eventName` と `priority` で検証しており、コピペではなく妥当 |
| integrity-signer:141-168 | 167行目で改竄検知テスト (`message = "tampered"` → `verifyHash = false`) が既にある |
| circuit-breaker:11-14 | 初期状態テストは単体で妥当。状態遷移は別テスト (16-20行) で網羅 |
| error-classifier:66-73 | `null message` と `non-Error object` を検証しており十分 |
| sentinel.test.ts:457-472 | `"11 handlers registered"` を文字列マッチ済みで十分 |
| console-task-transport:56-62 | `JSON.parse` + 具体プロパティ (`taskId`, `severity`, `traceId`) を検証済み |
| error-utils:218-226 | circular ref の型チェックが目的で妥当 |
| http-webhook-transport:194-198 | `ECONNREFUSED` は代表的ネットワークエラー。他の種類も同じ fetch rejection パスを通る |
| task-transport-factory:91-117 | インスタンス生成の検証が目的。dispatch検証は別テスト |
| log-validator:329-342 | `not.toThrow()` はバリデーション通過の検証として十分 |
| remaining-backlog:23-56 | 1件目と2件目は異なるルール種別 (REGEX vs PII_TYPE) で検証しており妥当 |
| log-normalizer:104-107 | 1つの invalid case で十分（バリデーション側で網羅） |
| task-executor-extended:91-104 | タイミング境界テストは不安定になるため避ける判断として妥当 |
| config-validator:51-68 | `not.toThrow()` は拡張値受理の検証として十分 |
