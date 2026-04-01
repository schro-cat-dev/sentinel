# 残存タスク + mTLS 対応計画

```yaml
created_at: "2026-04-02"
status: implementation
```

## 1. mTLS対応

### 現状
- Go server: `tls_cert_file` + `tls_key_file` でサーバTLS設定可能
- クライアント証明書検証なし（一方向TLSのみ）
- SDK側: transport interfaceに証明書フィールドなし

### 修正内容

**Go server (config + gRPC server):**
- sentinel.yaml に `tls_client_ca_file` 追加
- cmd/server/main.go でmTLS用 `tls.Config` 設定
- クライアント証明書未提示時は接続拒否

**TS SDK (transport型):**
- `TransportConfig` に `tlsCert`/`tlsKey`/`tlsCa` フィールド追加
- examples/grpc-transport.ts にmTLS設定例追加

**証明書生成スクリプト:**
- `scripts/gen-dev-certs.sh` — 開発用CA + サーバ/クライアント証明書生成

### セキュリティ考慮
- CA証明書はconfig経由（env varでもオーバーライド可能）
- クライアント証明書のCN/SANは検証するがRBACとは独立
- 証明書ファイルはgitignore対象

## 2. v1→v2移行ガイド

### 内容
- API変更点（onTaskAction戻り値、config freeze、新フィールド）
- 破壊的変更（なし — v2は後方互換）
- 新機能の段階的導入手順

## 3. ローカルTLSテスト手順

### 内容
- scripts/gen-dev-certs.sh
- docker-compose.yaml への証明書マウント例
- SDK側の接続設定例
