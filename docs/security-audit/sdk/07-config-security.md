# SDK 設定セキュリティ・プロトタイプ汚染防御監査

## 概要

SDK は設定システムにおいてプロトタイプ汚染攻撃、設定インジェクション、サイレントオーバーライドへの防御を実装している。

---

## チェック項目一覧

### 1. プロトタイプ汚染防御

| チェック項目 | 判定 | 箇所 | 根拠 |
|-------------|------|------|------|
| whitelist-registry の `__proto__` ガード | **OK** | `whitelist-registry.ts` | `filter(([k]) => k !== "__proto__" && k !== "constructor")` |
| config-validator の `__proto__` ガード | **OK** | `config-validator.ts` | 同上 |
| task-generator の `__proto__` ガード | **OK** | `task-generator.ts` | `executionParams` のキーフィルタリング |
| masking-service の hasOwnProperty | **OK** | `masking-service.ts:108` | `Object.prototype.hasOwnProperty.call(obj, key)` |
| deepFreeze の安全性 | **OK** | `index.ts:231-243` | `Object.values()` はプロトタイプチェーンを辿らない |

**テストカバレッジ**: `tests/security/` に専用のプロトタイプ汚染テストが11ファイル存在し、各防御箇所のバイパスを検証済み。

### 2. 環境変数展開の安全性

| チェック項目 | 判定 | 根拠 |
|-------------|------|------|
| 展開パターンの制限 | **OK** | `config-loader.ts:178` — `${VAR_NAME}` と `${VAR_NAME:-default}` のみ |
| コマンド実行防止 | **OK** | `$()` はパターンにマッチしない（`[A-Za-z_][A-Za-z0-9_]*` で先頭が英字/アンダースコア必須） |
| ネスト展開防止 | **OK** | 展開は1パスのみ。展開結果内の `${...}` は再展開されない |
| 変数名の制限 | **OK** | `[A-Za-z_][A-Za-z0-9_]*` — 英数字とアンダースコアのみ |
| 未定義変数のデフォルト値 | **OK** | `${VAR:-default}` のみサポート。`:=` は非サポート |
| 未定義・デフォルトなしの処理 | **要注意** | `config-loader.ts:183` — 空文字列を返却。エラーではない |

**未定義変数のサイレント空文字列化リスク**:
```yaml
security:
  hmac_key: ${SENTINEL_HMAC_KEY}  # 未設定の場合は空文字列に
```
- HMAC キーが空文字列になるとセキュリティが無効化される
- **緩和策**: Go サーバ側で HMAC キー長の最低32バイトバリデーションがある
- **SDK側**: ハッシュチェーンはキーなし（SHA-256）のため、空文字列による直接的リスクはない

**推奨パッチ**: 必須セキュリティ変数の未定義検出
```typescript
// config-loader.ts
function expandEnvVars(content: string, env: Record<string, string | undefined>): string {
    const missingRequired: string[] = [];
    const result = content.replace(
        /\$\{([A-Za-z_][A-Za-z0-9_]*)(?::-(.*?))?\}/g,
        (_match, varName: string, defaultValue: string | undefined) => {
            const value = env[varName];
            if (value !== undefined) return value;
            if (defaultValue !== undefined) return defaultValue;
            missingRequired.push(varName);
            return "";
        },
    );
    if (missingRequired.length > 0) {
        // 警告ログを出力（エラーにはしない — 後方互換性）
        console.warn(`[Sentinel] Undefined environment variables (resolved to ""): ${missingRequired.join(", ")}`);
    }
    return result;
}
```

### 3. Deep Merge の安全性

| チェック項目 | 判定 | 根拠 |
|-------------|------|------|
| サイレントオーバーライド防止 | **OK** | `sentinel-config.ts:137-145` — ネストされたオブジェクトは shallow merge ではなく deep merge |
| デフォルト値の保持 | **OK** | ユーザ設定が `undefined` のフィールドはデフォルト値を維持 |
| 配列の取扱い | **OK** | 配列はオーバーライド（merge ではない）。ルール配列はユーザ指定が優先 |

### 4. ホワイトリストバリデーション

| チェック項目 | 判定 | 根拠 |
|-------------|------|------|
| environment の許可値 | **OK** | `config-loader.ts:221` — 5値のみ |
| masking.type の許可値 | **OK** | `config-loader.ts:222` — 3値のみ |
| PII category の許可値 | **OK** | `config-loader.ts:223-226` — 8値のみ |
| whitelist.level の許可値 | **OK** | `config-loader.ts:227` — 4値のみ |
| task_rules の必須フィールド | **OK** | `config-loader.ts:265-268` — rule_id, event_name, action_type |

### 5. YAML パーサーの安全性

| チェック項目 | 判定 | 根拠 |
|-------------|------|------|
| YAML デシリアライゼーション攻撃 | **OK** | `yaml` パッケージ (v2.x) はデフォルトでオブジェクトインスタンス化を行わない（YAML 1.2準拠） |
| require 注入 | **OK** | `config-loader.ts:212-214` — `require("yaml")` のみ。ユーザ入力によるモジュール名注入は不可 |
| カスタムパーサー注入 | **OK** | `yamlParser` オプションでテスト用にオーバーライド可能だが、これはコード上の意図的な注入ポイント |

---

## ConfigLoadError の情報漏洩

| チェック項目 | 判定 | 根拠 |
|-------------|------|------|
| フィールド名の露出 | **低リスク** | `config-loader.ts:112` — `Config error [${field}]: ${message}` |
| 設定値の露出 | **低リスク** | `config-loader.ts:245` — `invalid category "${rule.category}"` — ユーザが設定した値を含む |

**リスク評価**: 設定ロードエラーは初期化時にのみ発生し、通常はサーバログに出力される。外部攻撃者が直接観察できるものではないため、リスクは低い。

---

## 総合判定

**評価: A（優秀）**

| 項目 | 重大度 | ステータス | 備考 |
|------|--------|-----------|------|
| プロトタイプ汚染防御 | — | **OK** | 4箇所で一貫した防御 |
| 環境変数展開 | — | **OK** | コマンド実行防止、ネスト防止 |
| 未定義変数のサイレント空文字列化 | LOW | **要改善** | 警告ログ追加推奨 |
| Deep Merge | — | **OK** | |
| ホワイトリスト | — | **OK** | |
| YAML パーサー | — | **OK** | |
