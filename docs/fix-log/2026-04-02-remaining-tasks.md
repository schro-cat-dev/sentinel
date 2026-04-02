# 残タスクリスト（2026-04-02 セッション末）

```yaml
created_at: "2026-04-02T20:00:00Z"
status: pending
```

## 未対応タスク

### 1. E2E サーバ立ち上げ動作確認テスト [HIGH]

Go Server を実際に起動し、sentinel.yaml の設定内容に応じて正しく動作するかを検証。

- [ ] Go Server 起動 + SDK remote モード接続
- [ ] integration flags (threat_response_enabled, task_approval_enabled 等) の on/off で挙動変化を検証
- [ ] HMAC 鍵設定 → SDK/Server 間のハッシュチェーン検証
- [ ] 設定不一致時の警告（ConfigSummary 比較）
- [ ] 正常系: ログ投入 → 検知 → タスク生成 → レスポンス
- [ ] 異常系: 不正設定 / 認証失敗 / タイムアウト
- [ ] エッジケース: 空ルール / 全機能無効 / dual モード

### ~~2. README テスト数更新~~ ✅ 完了

### ~~3. dir_structure.txt 新テストファイル追記~~ ✅ 完了

### ~~4. architecture-integration.md 更新~~ ✅ 完了
