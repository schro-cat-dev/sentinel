# 侵入経路設計（Attack Path Analysis）

```yaml
created_at: "2026-04-02"
status: active
```

## 攻撃パス（Kill Chain形式）

### Path 1: サプライチェーン経由の侵入（libpng型）

```
攻撃者がdevDepsの脆弱性を悪用（rollup/picomatch等）
  → ビルド時にバンドルにバックドア注入
    → npm publish → 利用者のランタイムで実行
      → ログ窃取/PII漏洩/hash chain偽装
```

**現状防御:**
- ランタイム依存ゼロ → 攻撃面がビルドツールチェインに限定
- npm audit 0件 → 既知脆弱性なし
- .npmignore → src/tests/docs を配布物から除外

**残存リスク:** rollupプラグインの未知の脆弱性（zero-day）。対策:
- npm provenance（署名付きpublish）の将来導入
- CI/CDでのSBOM生成 + 定期監査

### Path 2: 入力経由のPII窃取

```
攻撃者がログ入力にUnicode trick注入
  → PIIマスキングを回避（NFC/NFD混在、homoglyph）
    → マスクされていないPIIがサーバに送信
      → Datadog/Sentry経由で第三者に漏洩
```

**現状防御:**
- encoding-bypass.test.ts で主要パターンテスト済み
- MaskingService.mask() の正規表現はバイト列マッチ（Unicode正規化は未実施）

**残存リスク:** 新しいUnicodeバージョンの文字でのバイパス。対策:
- Unicode正規化（NFC）をマスキング前に適用（将来）
- PIIパターンの定期更新

### Path 3: 設定改竄経由のセキュリティ無効化

```
攻撃者がアプリケーションコードにconfig mutation注入
  → deepFreeze回避を試みる
    → hashChain=false, masking.enabled=false に変更
      → 以降のログがPII露出 + 改竄不検知
```

**現状防御:**
- deepFreeze は strict mode で mutation を TypeError にする
- テストで検証済み（state-manipulation.test.ts）

**残存リスク:** Object.defineProperty による freeze bypass（理論的可能性）。対策:
- Object.isFrozen() による事後チェック（将来）
- configの定期整合性検証

### Path 4: 内部者によるエラーログ経由の情報窃取

```
内部者がonErrorコールバックに細工
  → エラーペイロードを外部サーバに送信
    → traceId/actorId/サービス情報が漏洩
```

**現状防御:**
- errorRouting設計: maskPiiContext で PII除去してから外部送信
- コールバックは利用者責任（SDK側で制限不可）

**残存リスク:** コールバック内で元の error オブジェクトから情報抽出。対策:
- エラーペイロードの情報量を最小化（errorDetails の切り詰め）
- 監査ログで異常なコールバック登録パターンを検知（将来）

### Path 5: gRPC経由のサーバ侵入

```
攻撃者がgRPCエンドポイントに不正リクエスト
  → 認証回避 or レートリミット回避
    → 大量のタスク生成 → AIエージェント不正利用
      → サーバリソース枯渇 or 不正操作
```

**現状防御:**
- AuthUnaryInterceptor + API key検証
- RateLimitUnaryInterceptor (10 rps / 50 burst)
- RBACAuthorizer で権限分離

**残存リスク:** API keyのブルートフォース（16文字最小）。対策:
- API keyローテーション機能
- IP制限
