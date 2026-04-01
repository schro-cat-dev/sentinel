# OSINT / サプライチェーン分析

**監査日:** 2026-03-30
**対象:** @schro-cat-dev/sentinel v0.1.0-alpha.2

---

## 1. 依存関係ツリー

### ランタイム依存
```
(なし — ゼロ依存)
```
**評価:** 最高ランク。サプライチェーン攻撃面がゼロ。

### 開発依存 (devDependencies: 10パッケージ)
```
@eslint/js          ^9.39.2     ESLint core
@rollup/plugin-typescript ^11.1.6  Rollupプラグイン
@types/node         ^20.19.30   型定義
eslint              ^9.39.2     リンター
globals             ^17.1.0     グローバル変数定義
rollup              ^4.56.0     バンドラー
ts-node             ^10.9.0     TypeScript実行
typescript          ^5.0.0      コンパイラ
typescript-eslint   ^8.53.1     ESLint TS統合
vitest              ^4.0.18     テストフレームワーク
```

### 推移的依存
```
total resolved: 218 パッケージ
SHA-512ハッシュ: 218/218 (100%)
SHA-1ハッシュ: 0 (なし — 良好)
```

---

## 2. 既知CVE一覧

**総数:** 6件（すべてdevDependencies — ランタイム影響なし）

### HIGH

| パッケージ | バージョン | CVE/GHSA | 脆弱性 | 修正バージョン |
|-----------|-----------|----------|--------|--------------|
| rollup | 4.57.0 | GHSA-mw96-cpmx-2vgx | Path Traversal (任意ファイル書込) | >= 4.59.0 |
| minimatch | 3.1.2 | GHSA-3ppc-4f35-3m26 | ReDoS | >= 3.1.3 |
| minimatch | 9.0.5 | GHSA-7r86-cg39-jmmj | ReDoS | >= 9.0.7 |
| flatted | 3.3.3 | GHSA-25h7-pfq9-p65f | DoS (無限再帰) | >= 3.4.2 |
| flatted | 3.3.3 | GHSA-rf6f-7fwh-wjgh | Prototype Pollution | >= 3.4.2 |
| picomatch | 4.0.3 | GHSA-3v7f-55p6-f55p | Method Injection | >= 4.0.4 |
| picomatch | 4.0.3 | GHSA-c2c7-rcm5-vvqj | ReDoS | >= 4.0.4 |

### MODERATE

| パッケージ | バージョン | CVE/GHSA | 脆弱性 | 修正バージョン |
|-----------|-----------|----------|--------|--------------|
| ajv | 6.12.6 | GHSA-2g4f-4pwh-qvx6 | ReDoS ($data使用時) | >= 6.14.0 |
| brace-expansion | 1.1.12 | GHSA-f886-m6hf-6m8v | DoS (ゼロステップ) | >= 1.1.13 |
| brace-expansion | 2.0.2 | — | DoS | >= 2.0.3 |

---

## 3. リスク評価

### サプライチェーン攻撃面

| 攻撃ベクトル | リスク | 根拠 |
|-------------|--------|------|
| ランタイム依存の汚染 | **なし** | 依存0 |
| devDeps経由のビルド汚染 | **低** | ビルドはrollup + tsc。出力は検証可能 |
| npm registryからの悪意パッケージ | **低** | devDepsのみ。直接依存10パッケージはすべてメジャー/公式 |
| タイポスクワッティング | **なし** | すべて公式パッケージ名 |
| 悪意あるinstallスクリプト | **なし** | postinstall等のスクリプトなし |

### 信頼度スコア

```
ランタイムセキュリティ:  ████████████ 10/10 (依存0)
ビルドセキュリティ:      ████████░░░░  7/10 (CVE未修正)
ロックファイル整合性:    ████████████ 10/10 (SHA-512 100%)
パッケージ信頼度:        ████████████ 10/10 (全公式パッケージ)
```

---

## 4. npmパッケージメタデータ確認

### 確認項目チェックリスト

- [x] `package.json` の `files` フィールドが制限的 (`["dist", "README.md", "LICENSE"]`)
- [x] `.npmignore` が適切（テスト、ソース、設定ファイルを除外）
- [x] `prepublishOnly` でビルドを強制
- [x] `engines` フィールドで Node >= 20.0.0 を要求
- [ ] npm provenance (Sigstore) は未設定 → **v1.0で設定推奨**
- [ ] `npm pack --dry-run` でパッケージ内容を確認 → **リリース前に実施**

---

## 5. 対応アクションリスト

### 即時対応

```bash
# rollup を安全なバージョンへ更新
npm install -D rollup@">=4.59.0"

# 全体更新 + 監査
npm update
npm audit fix
```

### 定期実施

| 頻度 | アクション |
|------|-----------|
| 毎週 | `npm audit` 実行 |
| 毎月 | `.security/scan.sh --deps --npm-audit` 実行 |
| リリース前 | `npm pack --dry-run` でパッケージ内容確認 |
| 四半期 | 本ドキュメントの全面更新 |

---

## 6. OSINT: パッケージ公開情報

### 公開されている情報
- パッケージ名: `@schro-cat-dev/sentinel`
- 作者: `sy (schro-cat-dev)`
- リポジトリ: （package.jsonに未記載 — **追加推奨**）
- ライセンス: MIT

### 情報漏洩チェック

- [x] `.env` が `.gitignore` に含まれる
- [x] `.npmignore` でテスト・設定を除外
- [x] `files` フィールドでdistのみに制限
- [x] ソースコード内にハードコード秘密なし（Gitleaksで検証）
- [ ] GitHub Actionsのシークレット管理 → **CI/CD設定時に確認**
