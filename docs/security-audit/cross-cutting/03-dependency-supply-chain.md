# 依存関係・サプライチェーンセキュリティ分析

## 概要

SDK と Go Server の依存関係を評価し、サプライチェーン攻撃のリスクを分析する。

---

## 1. TypeScript SDK 依存関係

### 本番依存関係

**依存数: 0（ゼロ）**

SDK は本番環境でゼロ依存。これは非常に強いセキュリティ特性。

| チェック項目 | 判定 | 根拠 |
|-------------|------|------|
| ランタイム依存ゼロ | **OK** | `package.json` の `dependencies` が空 |
| Node.js 組込みモジュールのみ | **OK** | `node:crypto`, `node:fs`, `node:path` |
| トランスポートの外部注入 | **OK** | gRPC は devDependencies。ユーザが注入 |

**サプライチェーンリスク**: **極めて低い**。本番バンドルに第三者コードが含まれない。

### 開発依存関係

| パッケージ | バージョン | 用途 | リスク |
|-----------|-----------|------|--------|
| `@grpc/grpc-js` | ^1.14.3 | テスト・例示 | 低 — 本番バンドルに含まれない |
| `@grpc/proto-loader` | ^0.8.0 | テスト・例示 | 低 |
| `typescript` | ^5.0.0 | コンパイル | 低 — ビルド時のみ |
| `rollup` | ^4.56.0 | バンドル | 低 — ビルド時のみ |
| `vitest` | ^4.0.18 | テスト | 低 |
| `eslint` | ^9.30.1 | リント | 低 |
| `yaml` | ^2.8.3 | 設定パース例 | 低 |
| `@types/node` | ^20.19.30 | 型定義 | 低 |

### npm パッケージ整合性

| チェック項目 | 判定 | 根拠 |
|-------------|------|------|
| package-lock.json | **OK** | バージョンロック |
| integrity ハッシュ | **OK** | SHA-512 ハッシュによる整合性検証 |
| npm audit | **推奨** | 定期的な脆弱性スキャン |

---

## 2. Go Server 依存関係

### 直接依存関係

| パッケージ | バージョン | 用途 | リスク評価 |
|-----------|-----------|------|-----------|
| `google.golang.org/grpc` | v1.79.3 | gRPC フレームワーク | **低** — Google 管理、活発にメンテナンス |
| `google.golang.org/protobuf` | v1.36.11 | Protocol Buffers | **低** — Google 管理 |
| `gopkg.in/yaml.v3` | v3.0.1 | YAML パース | **低** — 広く使用、安定版 |
| `modernc.org/sqlite` | v1.47.0 | SQLite (Pure Go) | **低** — CGO不要、セキュリティ監査済み |
| `github.com/google/uuid` | v1.6.0 | UUID 生成 | **低** — Google 管理 |
| `golang.org/x/time` | v0.15.0 | レート制限 | **低** — Go 公式準標準ライブラリ |
| `github.com/mutecomm/go-sqlcipher/v4` | v4.4.2 | SQLite暗号化 | **中** — メンテナンス頻度を要確認 |

### go-sqlcipher のリスク評価

| チェック項目 | 判定 | 根拠 |
|-------------|------|------|
| メンテナンス状況 | **要確認** | 最新リリース日を確認 |
| CGO 依存 | **あり** | CGOが必要。ビルド環境にCコンパイラが必要 |
| SQLCipher バージョン | **要確認** | 使用している SQLCipher のバージョン |
| **代替パッケージ** | **検討** | `cznic/sqlite` (pure Go) + 別の暗号化レイヤーで CGO 依存を排除可能 |

### 間接依存関係

Go モジュールシステムにより、間接依存は `go.sum` で厳密にロックされている。

| チェック項目 | 判定 | 根拠 |
|-------------|------|------|
| go.sum のロック | **OK** | ハッシュによる整合性検証 |
| `go mod verify` | **推奨** | CI/CD で定期実行推奨 |
| `govulncheck` | **推奨** | Go 公式の脆弱性スキャナ |

---

## 3. サプライチェーン攻撃ベクトル

### 3.1 パッケージレジストリ攻撃

| 攻撃ベクトル | SDK リスク | Server リスク | 対策 |
|-------------|-----------|--------------|------|
| タイポスクワッティング | **極低** | **低** | 依存数ゼロ(SDK) / 著名パッケージのみ(Server) |
| 依存関係混同 (Dependency Confusion) | **極低** | **低** | プライベートレジストリ未使用 |
| アカウント乗っ取り | **極低** | **低** | Google管理パッケージが大部分 |
| 悪意あるアップデート | **極低** | **低** | バージョンロック |

### 3.2 ビルドパイプライン攻撃

| 攻撃ベクトル | リスク | 対策 |
|-------------|-------|------|
| CI/CD 環境の侵害 | **要確認** | CI環境のセキュリティ設定を確認 |
| ビルドスクリプトの改竄 | **低** | `rollup.config.js`, `tsconfig.json` は VCS 管理下 |
| postinstall スクリプト | **低** | SDK はpostinstallなし |

### 3.3 ランタイム攻撃

| 攻撃ベクトル | SDK リスク | Server リスク | 対策 |
|-------------|-----------|--------------|------|
| 動的 import/require | **低** | **N/A** | `yaml` パッケージのみ動的require |
| eval/Function | **なし** | **なし** | 使用されていない |
| 環境変数インジェクション | **低** | **低** | パターン制限あり |

---

## 4. 推奨アクション

### 即時

1. **npm audit**: SDK の devDependencies の脆弱性スキャン
2. **govulncheck**: Go サーバの脆弱性スキャン
3. **go-sqlcipher のメンテナンス状況確認**: 最新リリース日、未対応CVE

### CI/CD 統合

```yaml
# GitHub Actions example
- name: npm audit
  run: npm audit --production  # 本番依存のみ（空なのでパス）

- name: govulncheck
  run: |
    go install golang.org/x/vuln/cmd/govulncheck@latest
    govulncheck ./...

- name: Trivy scan
  uses: aquasecurity/trivy-action@master
  with:
    scan-type: 'fs'
```

### 定期レビュー

- **月次**: `npm audit` + `govulncheck` の実行
- **四半期**: 依存関係のアップデートレビュー
- **年次**: go-sqlcipher の代替検討

---

## 総合判定

**評価: A（優秀）**

| 項目 | 重大度 | ステータス | 備考 |
|------|--------|-----------|------|
| SDK 本番依存ゼロ | — | **OK** | 理想的な設計 |
| Go 依存関係の品質 | — | **OK** | Google/Go公式パッケージ中心 |
| バージョンロック | — | **OK** | package-lock.json + go.sum |
| go-sqlcipher のCGO依存 | LOW | **要確認** | 代替検討 |
| 脆弱性スキャン自動化 | — | **推奨** | CI/CD統合 |
