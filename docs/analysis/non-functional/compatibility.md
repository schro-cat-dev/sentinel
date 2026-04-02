# ESM/CJS互換性・プラットフォーム

```yaml
analyzed_at: "2026-04-01"
based_on: "7bf6f11"
status: current
last_updated: "2026-04-02"
```

## 所見一覧

### C-1: exports map に types 条件がない [MEDIUM]

**箇所:** `package.json:8-11`

```json
"exports": {
  "import": "./dist/index.mjs",
  "require": "./dist/index.cjs"
}
```

TypeScript 5+ の `moduleResolution: "bundler"` / `"node16"` で型解決が失敗する可能性。

**改善案:**
```json
"exports": {
  ".": {
    "types": "./dist/index.d.ts",
    "import": "./dist/index.mjs",
    "require": "./dist/index.cjs"
  }
}
```

### C-2: node:crypto 依存でブラウザ使用不可 [MEDIUM]

**箇所:** `integrity-signer.ts:1`, `log-normalizer.ts:1`

`createHash`, `timingSafeEqual`, `randomUUID` を `node:crypto` から import。ブラウザ環境では動作しない。

`tsconfig.json:5` で `"lib": ["ES2022", "DOM"]` に `DOM` が含まれるが、実際にはブラウザ対応していない。

**改善案:** ブラウザ非対応なら `DOM` を lib から除外し、package.json に `"browser": false` を明記。

### C-3: Rollup出力にソースマップなし [LOW]

**箇所:** `rollup.config.js`

tsconfig.json で `sourceMap: true` だが、rollupの最終出力にはソースマップが含まれない。.npmignore で `*.map` を除外したため出荷物にも入らない。開発時のデバッグには rollup設定に `sourcemap: true` を追加すべき。

### C-4: Node.js >=20 制約は適切 [INFO]

使用API (`createHash`, `timingSafeEqual`, `randomUUID`) は Node 15+ で利用可能。>=20 は保守的で安全な制約。
