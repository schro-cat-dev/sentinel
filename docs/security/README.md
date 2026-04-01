# .security/ — Sentinel Security Suite

> このディレクトリはgitignoreされています。pushされません。

## ディレクトリ構成

```
.security/
├── README.md                    # 本ファイル（全体索引）
├── scan.sh                      # 統合セキュリティスキャンスクリプト
├── rules/                       # Semgrep カスタムルール
│   └── sentinel-custom.yaml
├── docs/                        # セキュリティドキュメント
│   ├── audit-report.md          # 監査結果レポート v1（ツール主体）
│   ├── audit-report-v2.md      # 監査結果レポート v2（手動精査・15件新規発見）
│   ├── final-assurance-v3.md   # 最終保証レポート v3（全修正完了・302テスト・CWE Top 25検証）
│   ├── defense-boundary.md      # 防御境界設計と根拠
│   ├── client/                  # クライアントSDK固有
│   │   └── findings.md          # TS SDK脆弱性と対策
│   ├── server/                  # Goサーバ固有
│   │   └── findings.md          # サーバサイド脆弱性と対策
│   ├── pentest/                 # ペネトレーションテスト
│   │   └── methodology.md       # テスト手法・チェックリスト
│   └── osint/                   # OSINT・サプライチェーン
│       └── supply-chain.md      # 依存関係・CVE情報
└── reports/                     # スキャン実行結果（自動生成）
    ├── trivy_YYYYMMDD_*.json
    ├── npm_audit_YYYYMMDD_*.json
    ├── semgrep_YYYYMMDD_*.json
    ├── gitleaks_YYYYMMDD_*.json
    └── custom_rules_YYYYMMDD_*.txt
```

## クイックスタート

```bash
# 全スキャン実行
./.security/scan.sh

# 個別実行
./.security/scan.sh --regex       # ルールベースチェック（Docker不要）
./.security/scan.sh --deps        # 依存関係整合性（Docker不要）
./.security/scan.sh --trivy       # Trivy脆弱性スキャン
./.security/scan.sh --npm-audit   # npm audit
./.security/scan.sh --semgrep     # Semgrep SAST
./.security/scan.sh --secrets     # Gitleaks秘密検出
```

## ツール一覧と分離方針

| ツール | Docker分離 | イメージ固定 | 用途 |
|--------|-----------|-------------|------|
| Custom Rules | 不要 | — | grep/正規表現ベースの静的チェック |
| Trivy | Yes (read-only, no-network) | sha256 pinned | ファイルシステム脆弱性スキャン |
| Semgrep | Yes (no-network) | sha256 pinned | SAST（静的アプリケーションセキュリティテスト） |
| Gitleaks | Yes (read-only, no-network) | sha256 pinned | シークレット検出 |
| npm audit | Yes (read-only) | sha256 pinned | CVE / サプライチェーン |
