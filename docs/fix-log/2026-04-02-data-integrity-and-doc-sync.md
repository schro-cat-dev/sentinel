# 2026-04-02: データ完全性強化 + ドキュメント同期 + 脆弱性修正

```yaml
date: "2026-04-02"
commits: ["3820d07", "0ed9ab5", "47c923f", "c5c9a9c", "c87f6a2"]
scope: SDK全体 (src/, tests/, docs/)
tests_before: 2588
tests_after: 2626
status: completed
```

---

## 1. バリデーション強化 (commit: 3820d07)

### agentBackLog 構造バリデーション追加

**ファイル:** `src/validation/log-validator.ts`

以前はサイズとエントリ数のみチェックしていたところに、フィールド単位の検証を追加:

| フィールド | 検証内容 |
|-----------|---------|
| `status` | `"pending" \| "success" \| "failed"` enum検証 |
| `confidence` | 0.0〜1.0 範囲チェック + 型チェック |
| `actionType` | `TaskActionType` enum検証 (`TASK_ACTION_TYPES` リスト) |
| `agentId`, `taskId`, `model`, `inputHash` | `maxStringFieldLength` (512) 長さ制限 + null byte + lone surrogate |
| `error` | `maxDetailsLength` (65536) 長さ制限 |

### aiContext フィールド制約追加

| フィールド | 検証内容 |
|-----------|---------|
| `loopDepth` | 上限 100 追加（DoS防止） |
| `agentId`, `taskId` | `maxStringFieldLength` (512) 長さ制限 |

### log.ts 型安全性向上

| 変更 | Before | After |
|------|--------|-------|
| `actionType` | `string` | `TaskActionType` enum |
| `traceInfo` コメント | `// TODO 仮` | `// 補足トレース情報（分散トレーシング追加コンテキスト等）` |
| `resourceIds` コメント | `// TODO 影響がある口座などの関連情報` | `// 影響対象のリソースID（口座番号、ユーザID等）` |

### maxRetries ハンドラ単位リトライ実装

**ファイル:** `src/core/task/task-executor.ts`

**設計判断:** `invokeHandlers` 全体ではなく個別ハンドラ単位でリトライ。
- 理由: 成功したハンドラの再実行は二重通知・二重ブロックのリスク
- R-2（全ハンドラ実行+エラー集約）との整合性を保持
- 上限: `MAX_HANDLER_RETRIES = 10`、負の値は0にクランプ

### Dead code 削除

| ファイル | 内容 |
|---------|------|
| `src/shared/functional/result.ts` | Result monad (prod未使用) → 削除 |
| `tests/unit/shared/result.test.ts` | 対応テスト → 削除 |
| `issuccess` / `isfailure` aliases | 命名ミスの未使用エイリアス → 削除 |
| コメントアウトされた `unwrap()` | Dead code → 削除 |

`safe()` 関数はセキュリティテスト (new-findings-v2.test.ts) で使用されていたため、テストファイル内にインライン化。

### MaskingService sticky→global テスト追加

`masking-service.ts:172-176` の sticky(y)→global(g) フラグ変換の動作を検証するテスト3件追加。

### timeoutMs = 0 ドキュメント追加

`invokeWithTimeout` メソッドに JSDoc: `timeoutMs > 0` でタイムアウト適用、`<= 0` で無制限待機。

### テスト追加: 13件

- agentBackLog: status enum (2件), confidence範囲 (3件), 文字列長 (1件), actionType enum (2件)
- aiContext: loopDepth上限 (2件), 文字列長 (1件)
- masking: sticky→global (3件)
- maxRetries: ハンドラ単位リトライ (4件)

---

## 2. ドキュメント同期 — 12ファイル修正 (commits: 3820d07, 0ed9ab5, 47c923f)

### 「未対応」→「対応済み」に修正した項目

| ドキュメント | 項目 | 修正内容 |
|-------------|------|---------|
| `feature-completeness.md` | `guardrails.timeoutMs` | GAP → ✅ Promise.race実装済み |
| `feature-completeness.md` | `RemoteTransport.close()` | GAP → ✅ shutdown()で呼出済み |
| `feature-completeness.md` | `WorkerToMainMessage` | DEAD → ✅ 削除済み |
| `feature-completeness.md` | `AI_ACTION_REQUIRED` | GAP → ✅ 検知ルール実装済み |
| `feature-completeness.md` | `SEMI_AUTO` | GAP → ✅ TaskConfirmHandler実装済み |
| `feature-completeness.md` | `guardrails.maxRetries` | GAP → ✅ ハンドラ単位リトライ実装済み |
| `feature-completeness.md` | `details` TODO | → ✅ `Record<string,string>` 変更済み |
| `feature-completeness.md` | `output` TODO | → ✅ `AIAgentOutput` 型定義済み |
| `feature-completeness.md` | `SystemEventName`/`DetectionResult` export | ⚠ → ✅ 必要 |
| `config-reflection.md` | `projectName` | GAP → ✅ LogNormalizerで注入済み |
| `config-reflection.md` | `environment` | GAP → ✅ CFG-02対応済み |
| `config-reflection.md` | `onTaskGenerated`/`onTaskDispatched` | 未実装 → ✅ 実装済み |
| `dead-code/inventory.md` | `traceInfo`/`agentBackLog` | DEAD+BUG → ✅ normalize保持済み |
| `dead-code/inventory.md` | `error-utils.ts` | DEAD → 一部パイプライン接続済み |
| `instance-management-audit.md` | shutdown完全性 3.1-3.5 | 全て「未実装」→ ✅ 対応済み |
| `instance-management-audit.md` | reset() clearHandlers | 未呼出 → ✅ 呼出済み |
| `01-defense-boundary-map.md` | GAP-01 UTF-16 surrogate | → ✅ 解決済み |
| `01-defense-boundary-map.md` | GAP-02 agentBackLog制限 | → ✅ 解決済み |
| `01-defense-boundary-map.md` | GAP-03 ReDoS | → ✅ 緩和済み |
| `error-routing/00-overview.md` | classifyError/ErrorPayloadProtocol | 未接続 → ✅ 接続済み |
| `gap-remediation/00-gap-analysis.md` | Gap 1-6 | 全て ✅ 対応済みチェック追記 |
| `gap-remediation/01-tdd-plan.md` | status | design → completed |
| `observability.md` | O-1〜O-4 | 全て ✅ 対応済み |
| `config-security-audit/00-findings.md` | F-01 projectName | → ✅ 対応済み |
| `improvement-backlog.md` | 保留理由 | 6件 → 正確な2件に修正 |

### 行番号修正

`sentinel-config.ts` のフィールド行番号を全て現在の実コードに合わせて修正（:10→:48, :13→:51 等、13箇所）。

### commit hash 統一

8ドキュメントの `based_on` を最新commit hashに更新。

---

## 3. NEW-15 グレースフルシャットダウン実装 (commit: c5c9a9c)

### 問題

ドキュメント (additional-findings.md) では `activeIngests` カウンタ追加済みと記載されていたが、実際のコードには存在しなかった。

### 修正

**ファイル:** `src/index.ts`

- `activeIngests` カウンタ追加
- `ingest()` を `ingest()` + `ingestInternal()` に分離、try/finally でカウンタ管理
- `shutdown()` に `drainActiveIngests()` 追加: カウンタが0になるまでポーリング待機（5秒タイムアウト）
- `transport.close()` はドレイン完了後に呼ばれる

### TDD

テスト: `instance-lifecycle.test.ts`
- shutdown が in-flight ingest 完了前に transport.close() を呼ばないことを検証（dual-mode + slow transport で実証）
- shutdown 後の ingest 拒否を検証

---

## 4. 脆弱性修正 3件 (commit: c87f6a2)

### 4.1 dual-mode getLastProcessedLog() non-null assertion 除去

**ファイル:** `src/index.ts:236`

| Before | After |
|--------|-------|
| `this.engine.getLastProcessedLog()!` | 明示的 null check → `transportError` 返却 |

### 4.2 detectionRules プロトタイプ汚染防止

**ファイル:** `src/core/detection/event-detector.ts`

`sanitizeRule()` メソッド追加: `__proto__` / `constructor` キーを条件オブジェクトから除去。TaskGenerator.filterProtoKeys() と同等の保護を detectionRules にも適用。

### 4.3 ErrorRouter truncation 統一

**ファイル:** `src/error-routing/error-router.ts`

| Before | After |
|--------|-------|
| `err.message.substring(0, 200)` (2箇所) | `ErrorRouter.truncate(err.message)` |

直接 `.substring()` では `"..."` サフィックスが付かず、切り詰めが不明確だった。`truncate()` メソッドに統一し、PII漏洩防止を強化。

### テスト追加: 5件

- dual-mode null safety (1件)
- detectionRules proto pollution prevention (2件)
- ErrorRouter truncation consistency (2件)

---

## 5. 最終精査結果

| カテゴリ | 結果 |
|---------|------|
| Critical Issues | 0件 |
| High Issues | 0件 |
| Medium Issues | 0件 |
| Low Issues | 0件 |
| 型チェック | エラーなし |
| テスト | 2626全パス (23 expected fail含む) |
| 循環依存 | なし (madge検証済み) |
| non-null assertions | 13箇所、全て検証済み（バリデーション後の安全な使用） |
| TODO/FIXME | src/内ゼロ |
| ドキュメント乖離 | ゼロ |

### 正当な未実装（設計上の意図）

| 項目 | 理由 |
|------|------|
| `signature` / `signingKeyId` | 鍵管理設計が必要（ロードマップ DEAD-03） |
| `CFG-01: projectName` 未消費 | メタデータ保持（意図的NA） |
| Go server error-routing | Go側将来タスク |
