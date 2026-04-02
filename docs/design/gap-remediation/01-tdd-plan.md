# ギャップ修正 TDD計画

```yaml
status: completed
estimated_tests: 25
completed_at: "2026-04-02"
```

## テスト一覧

### Gap 1: ErrorRouter task/notification 実行 (8テスト)

| # | テスト | ファイル |
|---|-------|---------|
| 1 | CRITICAL error → task生成される | error-router-integration.test.ts |
| 2 | 生成されたtaskのeventNameがERROR_ESCALATION | 同上 |
| 3 | notification destination → NotificationSink.send() 呼ばれる | 同上 |
| 4 | ai_agent → actionType=AI_ANALYZE のtask生成 | 同上 |
| 5 | sink未設定時はスキップ（エラーにならない） | 同上 |
| 6 | task生成失敗 → console.error、他destination継続 | 同上 |
| 7 | notification送信失敗 → console.error、他継続 | 同上 |
| 8 | 全destination同時実行 | 同上 |

### Gap 2: ConsoleAuditSink + serializeForAudit接続 (4テスト)

| # | テスト | ファイル |
|---|-------|---------|
| 9 | ConsoleAuditSink.send() → console.error にJSON出力 | console-audit-sink.test.ts |
| 10 | 出力JSONにserializeForAuditのフォーマットが含まれる | 同上 |
| 11 | PII含有contextがマスクされて出力 | 同上 |
| 12 | ErrorRouter + ConsoleAuditSink E2E | 同上 |

### Gap 6: updateCallbacks E2E (5テスト)

| # | テスト | ファイル |
|---|-------|---------|
| 13 | onLogProcessed動的差替え → 新コールバックが呼ばれる | update-callbacks-e2e.test.ts |
| 14 | onTaskGenerated動的差替え → 新コールバックが呼ばれる | 同上 |
| 15 | null設定 → コールバック呼ばれない | 同上 |
| 16 | 差替え後のshutdown → クリーンアップ | 同上 |
| 17 | 元のconfig.onLogProcessedは呼ばれない（オーバーライド優先） | 同上 |

## 実施順序

1. ✅ テスト作成（全17件）
2. ✅ ConsoleAuditSink実装
3. ✅ ErrorRouter.execute() task/notification/ai_agent 実装
4. ✅ updateCallbacks E2Eテスト実装
5. ✅ サンプルコード更新（Gap 3）
6. ✅ ドキュメント整合性修正（Gap 4, 5）
7. ✅ 全体リグレッション — 2597テスト全パス
