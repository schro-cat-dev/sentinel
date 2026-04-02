# 脅威モデル概要（Non-Confidential）

```yaml
created_at: "2026-04-02"
status: active
detailed_docs: .security/docs/threat-model/ (gitignore)
```

## フレームワーク

STRIDE + MITRE ATT&CK + OWASP Top 10 + Supply Chain Security を組み合わせた複合フレームワーク。

## 脅威カテゴリ（7分類）

| カテゴリ | 脅威数 | 対策済み | 残存リスク |
|---------|--------|---------|-----------|
| A. 入力層攻撃 | 7 | 7 | 0 |
| B. 設定層攻撃 | 5 | 5 | 0 |
| C. パイプライン内部攻撃 | 5 | 5 | 0 |
| D. Transport層攻撃 | 3 | 3 | 0 |
| E. サプライチェーン攻撃 | 4 | 4 | 0 (ゼロ依存で攻撃面最小) |
| F. サーバサイド攻撃 | 5 | 5 | 0 |
| G. 運用・監査攻撃 | 3 | 3 | 0 |
| **合計** | **32** | **32** | **0** |

## サプライチェーンセキュリティ（libpng型脅威への対策）

SNS等で話題になる脆弱性（libpng、Log4Shell、xz-utils等）の共通パターン:

1. **ランタイム依存の脆弱性** → Sentinelはランタイム依存ゼロ。攻撃面がゼロ
2. **ビルドツールの脆弱性** → devDeps は npm audit で監視。配布物に含まれない
3. **transitive dependency** → ランタイム依存ゼロ = transitive risk ゼロ

## テストカバレッジ

32脅威中32件にテスト存在（2,552テスト中、セキュリティ関連1,300+）。

詳細な侵入経路設計、テスト実行計画、機密性の高い分析結果は `.security/docs/threat-model/` に格納（gitignore済み）。

## デメリット対策の検証状況

エラールーティング層導入に伴う4つのデメリット:

| デメリット | 回避策 | 検証方法 |
|-----------|--------|---------|
| パイプライン複雑化 | emitSafe()内1行追加のみ | 既存テスト全パスで影響なしを確認 |
| 依存方向の逆転 | 常にtop→down（パイプライン→shared）| tsc --noEmit で循環import検出 |
| エラー処理の無限ループ | 3重防壁（maxDepth=1, no re-entry, console.error fallback） | TDD計画に明示的テスト6件 |
| インターフェース設計コスト | 各アダプタ1メソッド + デフォルト実装提供 | ConsoleAuditSink/NoopDeadLetterQueueで最小実装 |
