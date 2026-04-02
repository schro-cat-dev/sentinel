# 設計 ↔ 実装 ギャップ分析

```yaml
created_at: "2026-04-02"
status: implemented
```

## 発見されたギャップ 6件

### Gap 1: ErrorRouter の task/ai_agent/notification が空実装

**設計:** CRITICAL → task生成 + 通知 + 監査
**実装:** audit_sink と dead_letter のみ動作。task/ai_agent/notification は `break;` で何もしない。

**修正方針:**
- `task` → 既存の TaskGenerator.generate() + TaskExecutor.dispatch() を呼ぶ
- `notification` → config.onError 経由ではなく、専用の NotificationSink インターフェースで送信
- `ai_agent` → Go Server側の責務。SDK側は task destination で `actionType: "AI_ANALYZE"` のタスクを生成する形で委任

**実装量:** ErrorRouter.execute() の3ケースに実ロジック追加

### Gap 2: serializeForAudit/logFinancialError がパイプライン未接続 — ✅ 対応済み

**設計:** 監査ログの構造化出力 → Datadog/Sentry連携
**実装:** `ConsoleAuditSink` を作成し、`maskPiiContext()` 経由で error-utils.ts をパイプラインに接続済み。`serializeForAudit` 相当の構造化JSON出力を実装。

### Gap 3: サンプルコードが古い

**修正方針:**
- `samples/basic_usage.ts` を新API対応に更新
- `samples/advanced_usage.ts` を新規作成（detectionRules + whitelist + metrics + tracer + errorRouting）

### Gap 4: テスト数の手動管理が構造的問題

**修正方針:**
- テスト数はREADMEに「`npm test` で確認」と記載し、具体的な数値は1箇所（Projectステータス表）のみに集約
- dir_structure.txt と benchmark は「最終更新日」を記載し、数値は概算

### Gap 5: Go server側のerror-routing未実装

**修正方針:**
- sentinel.yaml に `error_routing` セクションを追加（設定のみ、実装はGo側の将来タスク）
- ドキュメントに「Go Server側は将来実装」と明記

### Gap 6: updateCallbacks() のE2Eテストが薄い

**修正方針:**
- onLogProcessed の動的差し替えテスト
- onTaskGenerated の動的差し替えテスト
- null で明示クリアしたコールバックが呼ばれないテスト
