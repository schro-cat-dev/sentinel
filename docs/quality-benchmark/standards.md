# 品質ベンチマーク基準

```yaml
created_at: "2026-04-01"
benchmark_reference: "Google SRE / Production Readiness Review"
status: active
```

## 概要

Sentinel SDK の品質を Google Production Readiness Review 水準で評価するためのベンチマーク基準。各カテゴリで「必須（MUST）」「推奨（SHOULD）」「理想（NICE）」の3段階で水準を定義する。

---

## A. インスタンス管理・ライフサイクル

| ID | 水準 | 基準 |
|----|------|------|
| A-01 | MUST | シングルトンの生成・アクセス・破棄が明確に定義されている |
| A-02 | MUST | shutdown() は全内部状態を解放する（ハンドラ、コールバック参照、チェーン状態） |
| A-03 | MUST | shutdown() は冪等（idempotent）である |
| A-04 | SHOULD | 設定オブジェクトは初期化後に凍結（Object.freeze）される |
| A-05 | SHOULD | 入力配列（taskRules, detectionRules）は防御コピーされる |
| A-06 | SHOULD | reset() はテスト専用であり、非テスト環境で警告を出す |
| A-07 | SHOULD | 二重初期化は警告を出し、既存インスタンスを返す |
| A-08 | NICE | ハンドラの個別解除API（unregisterHandler）が存在する |

## B. 並行性・スレッドセーフティ

| ID | 水準 | 基準 |
|----|------|------|
| B-01 | MUST | 可変共有状態にはmutex/lockが存在する |
| B-02 | MUST | lockはデッドロックしない |
| B-03 | MUST | lockは例外時に確実に解放される |
| B-04 | SHOULD | shutdown()中のingest()は安全に処理される |
| B-05 | SHOULD | 並行shutdown()呼び出しは安全である |

## C. エラーハンドリング・耐障害性

| ID | 水準 | 基準 |
|----|------|------|
| C-01 | MUST | ユーザーコールバックの例外がパイプラインをクラッシュさせない |
| C-02 | MUST | エラーメッセージにフィールド名・理由・制限値が含まれる |
| C-03 | SHOULD | onError自体の例外が少なくともstderrに記録される |
| C-04 | SHOULD | dual-modeのtransportエラーがcallerに通知される |
| C-05 | SHOULD | パイプライン内のどのステージでエラーが起きても一貫した状態が保たれる |

## D. メモリ管理

| ID | 水準 | 基準 |
|----|------|------|
| D-01 | MUST | shutdown()後に全ユーザー参照（ハンドラ、コールバック）が解放される |
| D-02 | MUST | ハンドラが無制限に蓄積しない仕組みがある |
| D-03 | SHOULD | WeakRef/WeakSet を適切に使用している |
| D-04 | NICE | メモリ使用量の上限が設定可能 |

## E. セキュリティ

| ID | 水準 | 基準 |
|----|------|------|
| E-01 | MUST | Prototype pollution 防御が全入力処理箇所にある |
| E-02 | MUST | PII マスキングが正しく動作する |
| E-03 | MUST | Hash chain が改竄不可能 |
| E-04 | MUST | ホワイトリスト検証が初期化時に実行される |
| E-05 | SHOULD | ReDoS 耐性がテストされている |
| E-06 | SHOULD | 設定レベル（strict/standard/permissive/off）で検証強度を制御可能 |

## F. 可観測性

| ID | 水準 | 基準 |
|----|------|------|
| F-01 | SHOULD | 構造化ログ出力が可能（logger DI） |
| F-02 | NICE | メトリクス収集フック（処理時間、エラー率、タスク数） |
| F-03 | NICE | 分散トレーシング対応（OpenTelemetry等） |

## G. ビルド・パッケージング

| ID | 水準 | 基準 |
|----|------|------|
| G-01 | MUST | ビルドが成功する（CJS + ESM） |
| G-02 | MUST | ランタイム依存がゼロ |
| G-03 | MUST | devDependencies に既知の重大脆弱性がない |
| G-04 | SHOULD | TypeScript strict mode が全フラグ有効 |
| G-05 | SHOULD | .npmignore が正しくテスト・ソースを除外 |

## H. テスト品質

| ID | 水準 | 基準 |
|----|------|------|
| H-01 | MUST | 全テストがパスする |
| H-02 | MUST | 正常系・異常系・エッジケースが網羅されている |
| H-03 | MUST | セキュリティテスト（ペネトレーション、fuzzing）が存在する |
| H-04 | SHOULD | フレーキーテストがゼロ |
| H-05 | SHOULD | skip されたテストがゼロ（条件付きskipを除く） |

## I. API設計

| ID | 水準 | 基準 |
|----|------|------|
| I-01 | MUST | 公開APIが最小限で一貫している |
| I-02 | MUST | 内部実装が公開されていない |
| I-03 | SHOULD | 全公開APIにJSDocがある |
| I-04 | SHOULD | 設定のデフォルト値が安全側に倒れている |

## J. ドキュメント

| ID | 水準 | 基準 |
|----|------|------|
| J-01 | MUST | READMEに正確なテスト数・ステータスが記載されている |
| J-02 | MUST | 全ドキュメントリンクが実在するファイルを指している |
| J-03 | SHOULD | アーキテクチャ図がコードと一致している |
| J-04 | SHOULD | 設計判断の根拠が文書化されている |
