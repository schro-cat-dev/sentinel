# SDK 追加脆弱性診断 (v2) — 発見・チェック項目・対策

**診断日**: 2026-04-02
**前提**: docs/security-audit/sdk/ の初回診断 + 修正済み (VULN-001〜VULN-015, SDK-A〜SDK-C) を踏まえた深堀り

---

## チェック項目一覧

### NEW-01: concurrent ingest の lastProcessedLog 競合 (MEDIUM)

| チェック項目 | 対策前 | 対策後 |
|-------------|-------|-------|
| `lastProcessedLog` への排他制御 | NG — 複数の concurrent `handle()` が上書き | ✅ `chainLock` 内で代入 |
| dual モードでの整合性 | NG — stale ログがリモートに送信される可能性 | ✅ handle 戻り値からコピーを取得 |

**ファイル**: `src/core/engine/ingestion-engine.ts:190`
**対策**: `lastProcessedLog` の代入を `withChainLock` 内に移動、または `handle()` の戻り値にログコピーを含め `getLastProcessedLog()` を廃止。

---

### NEW-05: ErrorRouter の再帰ループ防止 (MEDIUM)

| チェック項目 | 対策前 | 対策後 |
|-------------|-------|-------|
| `onTaskRequest` コールバックからの `ingest()` 再帰 | NG — 無限ループ可能 | ✅ `isRouting` フラグで再入防止 |
| ルーティング深度制限 | 部分的 — コメントのみ | ✅ 実行時チェック |

**ファイル**: `src/error-routing/error-router.ts:30-47`
**対策**: `route()` 内に `isRouting` フラグを追加。既にルーティング中なら即座に `console.error` に出力して return。

---

### NEW-06: ErrorRouter 経由のエラーメッセージ PII 漏洩 (MEDIUM)

| チェック項目 | 対策前 | 対策後 |
|-------------|-------|-------|
| task destination の description にPII | NG — `error.message` がそのまま含まれる | ✅ 200文字に切り詰め |
| ai_agent destination の description にPII | NG — 同上 | ✅ 同上 |

**ファイル**: `src/error-routing/error-router.ts:73-86`
**対策**: `description` フィールドのエラーメッセージを200文字に切り詰め。

---

### NEW-09: preserveFields によるマスキングバイパス (MEDIUM)

| チェック項目 | 対策前 | 対策後 |
|-------------|-------|-------|
| `preserveFields` に機密フィールド名の設定防止 | NG — 任意のフィールド名を設定可能 | ✅ 禁止フィールドリスト追加 |

**ファイル**: `src/validation/config-validator.ts` or `src/configs/config-loader.ts`
**対策**: `preserveFields` に `password`, `secret`, `apiKey`, `token`, `creditCard` 等が含まれる場合に警告。

---

### NEW-14: config.metrics/tracer コールバックの例外未捕捉 (MEDIUM)

| チェック項目 | 対策前 | 対策後 |
|-------------|-------|-------|
| `metrics.onIngest()` の try-catch | NG — `emitSafe()` 内で呼ばれているが一部のパスで漏れ | ✅ 全コールバックを `emitSafe()` 経由 |
| `tracer.onPipelineStart/End()` の try-catch | OK — 既に `emitSafe()` 内 | ✅ 維持 |

**ファイル**: `src/core/engine/ingestion-engine.ts:131-188`
**対策**: `emitSafe()` の適用状況を再確認。漏れがあれば修正。

---

### NEW-15: shutdown() と ingest() の並行実行 (MEDIUM)

| チェック項目 | 対策前 | 対策後 |
|-------------|-------|-------|
| in-flight リクエストのカウント | NG — なし | ✅ `activeIngests` カウンタ追加 |
| shutdown 時の待機 | NG — 即座に close | ✅ カウンタ 0 まで待機（タイムアウト付き） |

**ファイル**: `src/index.ts` — `activeIngests` カウンタ + `drainActiveIngests()` メソッド
**対策**: `activeIngests` カウンタを追加し、`shutdown()` でカウンタが 0 になるまで待機（DRAIN_TIMEOUT_MS=5000ms）。テスト: instance-lifecycle.test.ts で検証済み。

---

## Go Server 追加チェック項目

### V-7: RejectBlock/RejectTask 認可チェック欠如 (HIGH)

| チェック項目 | 対策前 | 対策後 |
|-------------|-------|-------|
| RejectBlock の CanApprove チェック | NG — 認可なし | ✅ ApproveBlock と同等のチェック追加 |
| RejectTask の CanApprove チェック | NG — 認可なし | ✅ 追加 |

**ファイル**: `internal/grpc/server.go:111-127, 391-434`

---

### V-8: ListTasks 認可チェック欠如 (HIGH)

| チェック項目 | 対策前 | 対策後 |
|-------------|-------|-------|
| ListTasks の CanRead チェック | NG | ✅ 追加 |

**ファイル**: `internal/grpc/server.go:243-274`

---

### V-9: GetTaskStatus 認可チェック欠如 (MEDIUM)

| チェック項目 | 対策前 | 対策後 |
|-------------|-------|-------|
| GetTaskStatus の CanRead チェック | NG | ✅ 追加 |

**ファイル**: `internal/grpc/server.go:224-239`

---

### V-10: GetThreatResponses 認可チェック欠如 (HIGH)

| チェック項目 | 対策前 | 対策後 |
|-------------|-------|-------|
| GetThreatResponses の CanRead チェック | NG | ✅ 追加 |

**ファイル**: `internal/grpc/server.go:131-167`

---

### V-11: LoopDepth クライアント偽装 (MEDIUM)

| チェック項目 | 対策前 | 対策後 |
|-------------|-------|-------|
| LoopDepth のサーバ側リセット | NG — クライアント値をそのまま使用 | ✅ origin=SYSTEM のログはLoopDepth=0 に強制 |

**ファイル**: `internal/grpc/server.go:483`

---

### V-19: RejectBlock の content_hash 検証欠如 (MEDIUM)

| チェック項目 | 対策前 | 対策後 |
|-------------|-------|-------|
| 拒否時の改竄検知 | NG — hash検証なし | ✅ ApproveBlock と同等の検証追加 |

**ファイル**: `internal/grpc/server.go:111-127`
