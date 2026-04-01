# Sentinel セキュリティ監査レポート

**監査日:** 2026-03-30
**対象バージョン:** v0.1.0-alpha.2
**監査者:** Claude Code (AI-assisted manual review)
**対象コミット:** 19791fc
**スコープ:** クライアントSDK (TypeScript) + サーバ (Go) — ソースコード、設定、依存関係

---

## エグゼクティブサマリー

Sentinel は「ログからタスクを自動生成する」パイプラインSDK。クライアント側は**ランタイム依存ゼロ**の設計で、サプライチェーンリスクは極小。ただし、正規表現処理・ユーザー提供ルール・ログマスキング周りにいくつかの脆弱性が存在する。

### リスク全体像

| 深刻度 | クライアント (TS) | サーバ (Go) | 合計 |
|--------|------------------|-------------|------|
| CRITICAL | 1 | 2 | 3 |
| HIGH | 2 | 3 | 5 |
| MEDIUM | 4 | 3 | 7 |
| LOW | 3 | 1 | 4 |
| INFO | 2 | 1 | 3 |
| **合計** | **12** | **10** | **22** |

---

## 全脆弱性一覧

詳細は以下に分離：
- [クライアントSDK脆弱性](client/findings.md)
- [サーバサイド脆弱性](server/findings.md)
- [サプライチェーン分析](osint/supply-chain.md)

---

## 対応優先度マトリクス

### 即時対応（P0 — 1週間以内）

| ID | コンポーネント | 問題 | 影響 |
|----|--------------|------|------|
| C-001 | Client | CREDIT_CARD ReDoS | CPU枯渇によるDoS |
| S-001 | Server | HMAC鍵未検証 | 完全性検証の無効化 |
| S-002 | Server | API Key空文字許容 | 認証バイパス |

### 高優先度（P1 — 2週間以内）

| ID | コンポーネント | 問題 | 影響 |
|----|--------------|------|------|
| C-002 | Client | 動的RegExp未検証 | ユーザー入力によるReDoS |
| C-003 | Client | errorオブジェクト漏洩 | 内部情報の露出 |
| S-003 | Server | TLSデフォルト無効 | 通信傍受 |
| S-004 | Server | gRPC insecure credentials | MITM攻撃 |
| S-005 | Server | 暗号化鍵強度未検証 | SQLCipher保護無効 |

### 通常優先度（P2 — 1ヶ月以内）

| ID | コンポーネント | 問題 |
|----|--------------|------|
| C-004 | Client | Prototype Pollution リスク |
| C-005 | Client | タスク実行パラメータ未検証 |
| C-006 | Client | PII正規表現の過剰マッチ |
| S-006 | Server | レートリミット100RPS |
| D-001 | Deps | rollup CVE (Path Traversal) |
| D-002 | Deps | minimatch / flatted / picomatch CVE |

---

## ポジティブ所見（セキュリティ強度の根拠）

1. **ランタイム依存ゼロ** — サプライチェーン攻撃面が事実上ゼロ
2. **動的コード実行なし** — `eval()`, `new Function()`, `child_process` 不使用
3. **SHA-256ハッシュチェーン** — 暗号学的に堅牢な整合性検証
4. **WeakSetによる循環参照保護** — メモリリーク防止
5. **null byte検証** — C系バックエンド向けのインジェクション防御
6. **TypeScript strict mode** — 型安全性による暗黙的バグ防止
7. **ログバリデーション** — 最大長制限、必須フィールド検証

---

## 再監査スケジュール

| イベント | アクション |
|---------|-----------|
| 依存関係更新時 | `scan.sh --deps --npm-audit` |
| リリース前 | `scan.sh --all` |
| 月次 | `scan.sh --trivy --secrets` |
| 新機能追加時 | `scan.sh --semgrep --regex` |
