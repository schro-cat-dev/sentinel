# 優先度付き改善バックログ

```yaml
analyzed_at: "2026-04-01"
based_on: "pending commit"
status: current
last_updated: "2026-04-01T17:00:00Z"
```

## 全項目ステータス

### P0: 即時修正 — 全4件完了

| ID | 問題 | ステータス |
|----|------|-----------|
| BUG-01 | `agentBackLog` がnormalizeで欠落 | ✅ |
| BUG-02 | `traceInfo` がnormalizeで欠落 | ✅ |
| BUG-03 | `onTaskGenerated` 未呼出 | ✅ |
| BUG-04 | `onTaskDispatched` 未呼出 | ✅ |

### P1: 次リリース — 全6件完了

| ID | 問題 | ステータス |
|----|------|-----------|
| RES-01 | transport timeout | ✅ sendWithTimeout |
| RES-02 | dual 2度正規化 | ✅ getLastProcessedLog |
| OBS-01 | エラーswallow | ✅ onError callback |
| PERF-01 | RegExp再コンパイル | ✅ lastIndex reset |
| COMPAT-01 | exports types条件 | ✅ |
| API-01 | initialize重複 | ✅ 既存インスタンス返却 |

### P2: 計画的対応 — 11/14件完了

| ID | 問題 | ステータス |
|----|------|-----------|
| PERF-02 | preserveFields Array | ✅ Set化 |
| PERF-03 | context copy | ✅ 除去 |
| PERF-04 | async mutex粒度 | ✅ hash更新のみロック |
| MEM-01 | handler無限成長 | ✅ removeHandlers/clearHandlers |
| OBS-02 | IngestionResult情報不足 | ✅ detection追加 |
| OBS-03 | ロガーインターフェース | ✅ SentinelLogger DI |
| API-02 | SEMI_AUTO=AUTO | ✅ TaskConfirmHandler |
| API-03 | timeoutMs未実装 | ✅ TaskExecutor実装 |
| API-04 | shutdown()なし | ✅ Sentinel.shutdown() |
| CFG-01 | projectName未消費 | ⚠ NA — メタデータ保持（intentional） |
| CFG-02 | environment条件分岐 | ✅ logger抑制 |
| INT-01 | MaskingServiceインスタンス | ✅ 除去 |
| INT-02 | ILogNormalizer未活用 | ✅ constructorで使用 |
| COMPAT-02 | DOM lib | ✅ 除去 |

### P3: 推奨 — 6/9件完了

| ID | 問題 | ステータス |
|----|------|-----------|
| DEAD-01 | shared/ dead code | ✅ constants/ 削除、空ファイル削除、protocol簡素化 |
| DEAD-02 | WorkerToMainMessage | ✅ 削除 |
| DEAD-03 | signature/signingKeyId | ⚠ NA — ロードマップ |
| DEAD-04 | AI_ACTION_REQUIRED | ✅ 検知ルール追加 |
| MT-01 | validate二重定義 | ✅ normalizer.validate()削除 |
| MT-02 | I-prefix不統一 | ⚠ NA |
| TEST-01 | IngestionEngineテスト | ✅ 12テスト |
| TEST-02 | normalizeOnly()テスト | ✅ |
| TEST-03 | mutex検証 | ✅ |

### Go Server — 全4件完了

| ID | 問題 | ステータス |
|----|------|-----------|
| S-002 | API Key空文字列 | ✅ |
| S-002ext | API Key最小長 | ✅ |
| S-005 | 暗号化鍵検証 | ✅ |
| S-006 | レートリミット | ✅ |

---

## 最終集計

| 優先度 | 合計 | ✅完了 | ⚠保留/NA | 理由 |
|--------|------|--------|----------|------|
| P0 | 4 | 4 | 0 | |
| P1 | 6 | 6 | 0 | |
| P2 | 14 | 13 | 1 | CFG-01: 意図的NA |
| P3 | 9 | 8 | 1 | DEAD-03: 鍵管理設計必要 |
| Go | 4 | 4 | 0 | |
| **合計** | **37** | **35** | **2** | |

**残り6件の保留理由:**
- OBS-03: ロガーI/Fは利用者のログ基盤との統合設計が必要
- API-02: SEMI_AUTOはServer側の承認フロー実装待ち
- CFG-01/02: 設計上の意図的NA（projectNameはメタデータ、environmentは利用者判断）
- DEAD-03/04: ロードマップ項目として保持（型定義はAPIの将来拡張ポイント）
