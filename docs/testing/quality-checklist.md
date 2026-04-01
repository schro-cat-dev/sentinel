# 定性的品質チェックリスト

**用途:** リリース前、PR レビュー時、および定期的な品質評価に使用。

---

## 1. 機能品質チェック

### 設定反映

- [ ] `masking.enabled` ON/OFFでマスキング動作が切り替わるか
- [ ] `masking.rules` の各ルールタイプ（REGEX/PII_TYPE/KEY_MATCH）が正しく動作するか
- [ ] `masking.preserveFields` がKEY_MATCHより優先されるか
- [ ] `security.enableHashChain` ON/OFFでhash計算が切り替わるか
- [ ] `taskRules` のルールがイベント名・重大度で正しくマッチするか
- [ ] 全コールバック（onLogProcessed, onTaskGenerated, onTaskDispatched, onError）が呼ばれるか
- [ ] `logger` 注入でMaskingServiceのログ出力先が変わるか

### パイプラインデータフロー

- [ ] `agentBackLog`/`traceInfo` がnormalize→mask→hash→callbackまで保持されるか
- [ ] `input`/`details`/`tags` がマスキング対象になっているか（messageだけではない）
- [ ] hash chain計算時に`hash`と`signature`フィールドが除外されるか
- [ ] detection結果がIngestionResult.detectionに含まれるか

### Transport

- [ ] localモードでtransportオブジェクトが無視されるか
- [ ] remoteモードでマスキング済みログが送信されるか
- [ ] dualモードでローカルとリモートが同じtraceIdを使うか
- [ ] timeoutMsでPromise.raceが正しくタイムアウトするか
- [ ] fallbackToLocalでリモート失敗時にローカル処理に切り替わるか
- [ ] shutdown()でtransport.close()が呼ばれるか

### タスク実行

- [ ] AUTO → dispatch / MANUAL → blocked / MONITOR → skipped
- [ ] SEMI_AUTO + confirmHandler(false) → blocked
- [ ] SEMI_AUTO + confirmHandler未登録 → dispatch（後方互換）
- [ ] requireHumanApproval=true がexecutionLevelより優先されるか
- [ ] timeoutMs内に完了しないhandlerがfailedになるか

---

## 2. セキュリティ品質チェック

### 入力境界

- [ ] undefined/null messageが拒否されるか
- [ ] null byteを含むmessageが拒否されるか
- [ ] 65536文字超のmessageが拒否されるか
- [ ] 無効なtype/level/originが拒否されるか
- [ ] tags 101件 / resourceIds 101件が拒否されるか

### マスキング

- [ ] 全PIIカテゴリ（CREDIT_CARD, PHONE, EMAIL, GOVERNMENT_ID）が検出・マスクされるか
- [ ] KEY_MATCHが大文字小文字を区別しないか（PASSWORD = password）
- [ ] 循環参照でクラッシュしないか
- [ ] maxDepth超過で安全に打ち切られるか

### ハッシュチェーン

- [ ] 1フィールドの変更で異なるハッシュが生成されるか
- [ ] previousHash依存で順序が強制されるか
- [ ] timingSafeEqualで比較されるか（===ではない）
- [ ] NaN/Infinityがシリアライズで拒否されるか

### Prototype Pollution

- [ ] __proto__ / constructor がexecutionParams/guardrailsからフィルタされるか
- [ ] Object.prototypeが汚染されないか

### 情報漏洩

- [ ] エラーメッセージにファイルパスが含まれないか
- [ ] rawLogにactorId/input/details/tagsが含まれないか（SafeLogSubset）
- [ ] console.warnが直接呼ばれないか（logger DI経由）

---

## 3. 非機能品質チェック

### パフォーマンス

- [ ] RegExpが毎回再コンパイルされていないか（lastIndex reset方式）
- [ ] preserveFieldsがSet<string>でO(1)ルックアップか
- [ ] async mutexがhash更新のみに限定されているか（パイプライン全体をロックしていない）

### 耐障害性

- [ ] transport.send()にタイムアウトがあるか
- [ ] setTimeoutがclearTimeoutされるか（timer leak防止）
- [ ] コールバック例外がパイプラインを壊さないか
- [ ] getLastProcessedLog()が防御的コピーを返すか

### 互換性

- [ ] package.json exports に `types` 条件があるか
- [ ] tsconfig.json lib に `DOM` が含まれていないか
- [ ] .npmignore に `*.map` が含まれるか

---

## 4. テスト品質チェック

### 網羅性

- [ ] 全設定フィールドに対して最低1つのテストがあるか
- [ ] 全detection eventタイプに対するテストがあるか
- [ ] 全execution levelに対するテストがあるか
- [ ] 全masking ruleタイプに対するテストがあるか
- [ ] 全transport modeに対するテストがあるか

### 定性的正しさ

- [ ] テストのラベル（describe/it文字列）が実際のテスト内容と一致するか
- [ ] 正常系テストが「期待する動作」を検証しているか（単に「クラッシュしない」ではなく）
- [ ] 異常系テストが「期待するエラー」を検証しているか
- [ ] エッジケースが境界値（ちょうど最大/ちょうど超過）を含むか

### リグレッション

- [ ] 修正した脆弱性に対するテストが存在するか
- [ ] `it.fails` でマークされた既知脆弱性テストが無いか（全修正済みのはず）
