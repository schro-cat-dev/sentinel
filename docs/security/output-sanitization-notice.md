# ログ出力時の XSS / インジェクション注意事項

## 概要

Sentinel SDK はログの **収集・検知・タスク生成** を担当する。
ログの **表示・レンダリング** はSDKの責務外であり、表示側で適切なサニタイズが必要。

## SDK が行うこと

| 防御 | 対象 | 処理内容 |
|------|------|----------|
| PII マスキング | `message`, `details`, `input`, オブジェクト全フィールド | 正規表現ベースで `[MASKED_EMAIL]` 等に置換 |
| Null byte 除去 | 全 string フィールド | ValidationError で拒否 |
| Lone surrogate 除去 | 全 string フィールド | ValidationError で拒否 |
| Unicode 正規化 | PII 検出時 | NFKC 正規化 + invisible 文字除去で bypass 防止 |

## SDK が行わないこと

| 処理 | 理由 |
|------|------|
| HTML エスケープ | SDK はログを構造化データとして扱い、HTML を生成しない |
| SQL エスケープ | SDK はデータベースに直接アクセスしない |
| JavaScript エスケープ | ログの内容はそのまま保持（改変するとログの証拠性を損なう） |

## 表示側で必要な対策

### 1. Web ダッシュボードでログを表示する場合

ログメッセージには任意の文字列が含まれる可能性がある:

```
<script>alert(document.cookie)</script>
'; DROP TABLE logs; --
${process.exit(1)}
```

これらは SDK のバリデーションを通過する（ログの内容として正当な文字列）。

**対策**: 表示時に必ず HTML エスケープを行うこと。

```typescript
// React: JSX は自動エスケープ
<span>{log.message}</span>  // 安全

// innerHTML は危険
element.innerHTML = log.message;  // XSS 脆弱性！

// テンプレートリテラルを HTML に埋め込む場合
const safe = escapeHtml(log.message);
```

### 2. ログを SQL に保存する場合

パラメータ化クエリを使用:

```typescript
// 安全
db.query("INSERT INTO logs (message) VALUES ($1)", [log.message]);

// 危険！
db.query(`INSERT INTO logs (message) VALUES ('${log.message}')`);
```

### 3. ログをコマンドラインに出力する場合

ANSI エスケープシーケンスを含むログがターミナルの表示を変える可能性:

```
\x1b[31mRED TEXT\x1b[0m
```

**対策**: 制御文字をストリップしてから出力。

### 4. ハッシュチェーンとの関係

SDK はログメッセージのハッシュチェーンを構築する。
メッセージを表示側でサニタイズすると、ハッシュ検証時に不一致が起きる。

**推奨**: 保存時は原文のまま保持し、表示時にのみサニタイズ。

```
[Storage] → 原文保持（ハッシュ検証可能）
[Display] → エスケープ済み表示（XSS 防止）
```

## テスト

SDK のインジェクション攻撃テスト（`tests/security/advanced/injection-attacks.test.ts`、382テスト）は
「SDK がクラッシュしない」「ValidationError で拒否される」ことを検証している。
「インジェクションペイロードが出力に含まれない」ことは検証していない（SDK の責務外）。
