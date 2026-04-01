# 高度脅威ベクトル対策計画

```yaml
created_at: "2026-04-02"
status: implementation
findings: 10
```

## CRITICAL

### #1: Hash chain SDK/Server直列化乖離
- **問題:** SDK=SHA-256(カスタム直列化), Server=HMAC-SHA256(json.Marshal)。同じログで異なるハッシュ
- **対策:** SDKのハッシュ計算をHMAC-SHA256に統一は不可（SDKにHMAC鍵がない）。代わりに:
  - ドキュメントに「hash chainはSDK/Server各自で独立。cross-verificationは行わない」と明記
  - SDK側のhash計算にJSON.stringifyベースの正規化を追加（Go json.Marshalと互換）
  - 将来的にはサーバ側でSDKハッシュを再計算・検証する仕組みを設計

## HIGH

### #2: CachedTokenValidator キャッシュ無制限
- **対策:** maxCacheSize設定追加。超過時はLRU的に古いエントリ削除

### #3: Webhook goroutine無制限
- **対策:** セマフォ（buffered channel）でworker pool制限。デフォルト100

## MEDIUM

### #4: estimateJsonSizeSeen グローバルWeakSet
- **対策:** 関数引数でWeakSetを渡す（呼び出しごとに新規作成）

### #5: コールバック経由のログ改竄
- **対策:** onLogProcessed に防御コピー（shallow copy）を渡す

### #6: Proto details型不一致
- **対策:** ドキュメント注記（既知の互換性制約）

### #7: logicalClock乖離
- **対策:** ドキュメント注記（SDK/Server独立カウンタ）

### #8: ErrorRouter isRouting非同期抑制
- **対策:** isRoutingを削除、Promiseベースの並行制御に変更

### #9: SQLite無制限成長
- **対策:** retention設定追加（Go config）。デフォルト30日

### #10: StaticTokenValidator キー数タイミング
- **対策:** 常に全キーをイテレート（early returnしない）
