# 最終修正: 全30件の発見事項

```yaml
created_at: "2026-04-02"
status: remediation
total_findings: 30
```

## P0: テスト誤魔化し (10件)

| ID | 問題 | 対策 |
|----|------|------|
| T-01 | expectSafeOrRejected() 成功パスでアサーションなし | 成功時: result.traceId + detection/masked の値を検証 |
| T-02 | expect(true).toBe(true) トートロジー | process.exit mock + 実行後のプロセス状態検証に置換 |
| T-03 | .toBeDefined() だけのセキュリティテスト 15+ | 具体的な値アサーション追加 |
| T-04 | DoSテストが名前詐欺 | マスキング結果の正しさも検証 |
| F-01 | type-confusion テストの全ヘルパーが成功パス無検証 | ヘルパーに成功時アサーション追加 |
| F-02 | encoding-bypass 69テストがtypeof === "string"のみ | PII除去の有無を検証するアサーション追加 |
| F-03 | Logger mock にassertionなし | expect(warn).not.toHaveBeenCalled() 追加 |
| F-06 | NaN/Infinity ハッシュテストがハッシュ比較しない | hashA !== hashB を検証 |
| F-04 | result.status が .toBeDefined() だけ | 具体値 (dispatched/skipped) を検証 |
| F-07 | getter注入テストがgetter呼出し未検証 | getterCalls > 0 を検証 |

## P1: 脆弱性 (9件)

| ID | 問題 | 対策 |
|----|------|------|
| V-01 | resourceIds 非string要素が無視される | typeof !== "string" でValidationError |
| V-02 | validateStringField() 非string型無視 | typeof チェック追加 |
| V-03 | details 非string型無視 | typeof チェック追加 |
| V-04 | maxRetries 宣言のみで未実装 | タイプ定義のJSDocに「将来実装」と明記。現時点ではドキュメント対応 |
| V-05 | console.error 4箇所がスタックトレース漏洩 | logger.error経由に変更、未設定時のみconsole.error |
| V-06 | deepFreeze がRegExpスキップ | RegExpはimmutableなのでOK (sourceとflagsはreadonly)。ドキュメント注記 |
| V-08 | estimateJsonSize 循環参照防御なし | WeakSetで既訪問オブジェクトをスキップ |
| V-09 | logicalClock が Date.now() で非単調 | performance.now() + offsetで単調増加に変更 |
| V-07 | maskPiiContext 防御が偶然動作 | コメントで意図を明確化(spread + hasOwnPropertyの二重防壁) |

## P2: ロジックバグ (5件)

| ID | 問題 | 対策 |
|----|------|------|
| L-01 | WeakSet が DAG を循環と誤判定 | パス追跡方式に変更（visitedをSetからパス配列に） |
| L-02 | 未知severity が -1 >= -1 でマッチ | indexOf === -1 のとき false を返す |
| L-03 | deriveKind context先行チェックで誤分類 | パターンマッチを先行、contextは補助条件に |
| L-04 | reset() async close が unhandled rejection | Promise.resolve()でラップしてcatch |
| L-05 | remote-only hash chain なし | ドキュメント注記（設計通り） |

## P3: コード品質 (6件)

| ID | 問題 | 対策 |
|----|------|------|
| A-01 | src/index.ts ユニットテスト欠落 | 専用テスト作成 |
| A-02 | error-utils.ts テスト欠落 | 専用テスト作成 |
| A-03 | サイレントcatch 3箇所 | logger経由に統一 |
| A-04 | TODO型定義 5件 | JSDoc注釈で意図を明確化 |
| A-05 | as any 乱用 20箇所 | as unknown as Type に変更（型安全性向上） |
| F-05 | .toBeDefined() on non-nullable | 具体値アサーションに変更 |
