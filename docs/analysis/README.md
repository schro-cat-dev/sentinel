# docs/analysis/ — Sentinel 内部解析ログ

**目的:** コードベースの機能・非機能品質を継続的に追跡し、改善判断の根拠を残す。

## ディレクトリ構成

```
docs/analysis/
├── README.md                          # 本ファイル（索引 + 方針）
├── functional/
│   ├── config-reflection.md           # 設定フィールドの実装反映状況
│   ├── module-integration.md          # モジュール間連携の完全性
│   └── feature-completeness.md        # 機能の実装状況・TODO追跡
├── non-functional/
│   ├── performance.md                 # パフォーマンス解析
│   ├── resilience.md                  # 耐障害性・フォールトトレランス
│   ├── observability.md               # 可観測性・ログ・メトリクス
│   └── compatibility.md               # ESM/CJS・Node.js互換性
├── dead-code/
│   └── inventory.md                   # 未使用コードの棚卸し
└── roadmap/
    └── improvement-backlog.md         # 優先度付き改善バックログ
```

## タイムスタンプ規約

各ドキュメントのヘッダーに以下を含む:
- `analyzed_at`: 解析実施日（ISO 8601）
- `based_on`: 対象コミットハッシュ
- `status`: `current` / `stale` / `superseded`

`stale` 判定基準: 対象ファイルに変更が入ったが本ドキュメントが未更新の場合。
