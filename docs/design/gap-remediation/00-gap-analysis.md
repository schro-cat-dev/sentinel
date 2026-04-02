# 設計 ↔ 実装 ギャップ分析

```yaml
created_at: "2026-04-02"
status: implemented
```

## 発見されたギャップ 6件

### Gap 1: ErrorRouter の task/ai_agent/notification が空実装 — ✅ 対応済み

**設計:** CRITICAL → task生成 + 通知 + 監査
**実装:** `onTaskRequest` コールバック方式で task/ai_agent を実装。`onNotification` コールバックで notification を実装。error-router.ts:87-105 で全3ケースにロジック追加済み。テスト: error-router-integration.test.ts (8件パス)

### Gap 2: serializeForAudit/logFinancialError がパイプライン未接続 — ✅ 対応済み

**設計:** 監査ログの構造化出力 → Datadog/Sentry連携
**実装:** `ConsoleAuditSink` を作成し、`maskPiiContext()` 経由で error-utils.ts をパイプラインに接続済み。`serializeForAudit` 相当の構造化JSON出力を実装。

### Gap 3: サンプルコードが古い — ✅ 対応済み

`samples/basic_usage.ts`, `samples/advanced_usage.ts`, `samples/security_anomaly_ai.ts` を新API対応で作成済み。

### Gap 4: テスト数の手動管理が構造的問題 — ✅ 対応済み

READMEに「`npm test` で確認」と記載。具体的な数値はProjectステータス表に集約。

### Gap 5: Go server側のerror-routing未実装 — ⚠ Go側の将来タスク

sentinel.yaml に `error_routing` セクションを追加済み（設定のみ）。ドキュメントに「Go Server側は将来実装」と明記済み。

### Gap 6: updateCallbacks() のE2Eテストが薄い — ✅ 対応済み

`update-callbacks-e2e.test.ts` で以下を検証済み:
- onLogProcessed の動的差し替え
- onTaskGenerated の動的差し替え
- null で明示クリアしたコールバックが呼ばれないこと

---

## 解消状況サマリ (2026-04-02)

| Gap | 内容 | 状態 |
|-----|------|------|
| Gap 1 | ErrorRouter task/ai_agent/notification | ✅ onTaskRequest + onNotification コールバック方式で実装 |
| Gap 2 | serializeForAudit パイプライン接続 | ✅ ConsoleAuditSink + maskPiiContext |
| Gap 3 | サンプルコード更新 | ✅ 3ファイル作成 |
| Gap 4 | テスト数の手動管理 | ✅ README集約 |
| Gap 5 | Go server error-routing | ⚠ Go側将来タスク（SDK側対応不要） |
| Gap 6 | updateCallbacks E2Eテスト | ✅ 5テスト作成 |

**SDK側: 5/5 解消済み。Go側: 1件は将来タスク。**
