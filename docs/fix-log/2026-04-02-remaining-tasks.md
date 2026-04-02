# 残タスクリスト（2026-04-02 セッション末）

```yaml
created_at: "2026-04-02T20:00:00Z"
status: done
```

## 完了タスク

### ~~1. E2E サーバ立ち上げ動作確認テスト [HIGH]~~ ✅ 完了

Go Server を実際に起動し、sentinel.yaml の設定内容に応じて正しく動作するかを検証。

- [x] Go Server 起動 + SDK remote モード接続
- [x] integration flags (threat_response_enabled, task_approval_enabled 等) の on/off で挙動変化を検証
- [x] HMAC 鍵設定 → SDK/Server 間のハッシュチェーン検証
- [x] 設定不一致時の警告（ConfigSummary 比較）
- [x] 正常系: ログ投入 → 検知 → タスク生成 → レスポンス
- [x] 異常系: 不正設定 / 認証失敗 / タイムアウト
- [x] エッジケース: 空ルール / 全機能無効 / dual モード

実装: `tests/e2e/server-config-matrix.test.ts` (25テスト)

### ~~1b. Context Key 不一致バグ修正~~ ✅ 完了

- [x] `grpc/interceptors.go` の `clientIDKey` を `middleware.ContextWithClientID()` に統一
- [x] `RateLimitUnaryInterceptor` / `ClientIDFromContext` も middleware に委譲
- [x] `interceptors_test.go` も middleware パッケージ使用に修正
- [x] Go 全テスト パス（`-race` 付き）
- [x] E2E で RBAC writer/reader/disabled の3パターン検証

### ~~1c. GetLog RPC 追加 + PII除去の実内容検証~~ ✅ 完了

- [x] Proto: `GetLogRequest`/`GetLogResponse` + `GetLog` RPC 追加
- [x] サーバ: `GetLog` ハンドラ実装（store.GetLogByTraceID 委譲、CanRead 権限チェック付き）
- [x] E2E: Ingest → GetLog でマスク後のメッセージにPIIが含まれていないことを直接検証
- [x] masked=true だけでなく実際のコンテンツ変更を証明

### ~~2. README テスト数更新~~ ✅ 完了

### ~~3. dir_structure.txt 新テストファイル追記~~ ✅ 完了

### ~~4. architecture-integration.md 更新~~ ✅ 完了

### ~~5. readme/en(default).md + readme/ja.md 更新~~ ✅ 完了

- [x] テスト数更新
- [x] 概要にPIIマスキング・異常検知等の詳細追記
- [x] 英語disclaimerを両言語版に追加
