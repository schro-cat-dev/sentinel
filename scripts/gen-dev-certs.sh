#!/bin/bash
# ============================================================================
# Sentinel 開発用証明書生成スクリプト（mTLS対応）
#
# 生成物:
#   certs/ca.pem          — ルートCA証明書
#   certs/ca-key.pem      — ルートCA秘密鍵
#   certs/server.pem      — サーバ証明書
#   certs/server-key.pem  — サーバ秘密鍵
#   certs/client.pem      — クライアント証明書
#   certs/client-key.pem  — クライアント秘密鍵
#
# 使い方:
#   chmod +x scripts/gen-dev-certs.sh
#   ./scripts/gen-dev-certs.sh
#
# 注意: 開発・テスト専用。本番では正規のCAから証明書を取得すること。
# ============================================================================

set -euo pipefail

CERT_DIR="${1:-certs}"
DAYS=365
CN_CA="Sentinel Dev CA"
CN_SERVER="localhost"
CN_CLIENT="sentinel-client"

mkdir -p "$CERT_DIR"

echo "=== Generating CA certificate ==="
openssl genrsa -out "$CERT_DIR/ca-key.pem" 4096
openssl req -new -x509 -days "$DAYS" \
    -key "$CERT_DIR/ca-key.pem" \
    -out "$CERT_DIR/ca.pem" \
    -subj "/CN=$CN_CA/O=Sentinel Dev"

echo "=== Generating server certificate ==="
openssl genrsa -out "$CERT_DIR/server-key.pem" 2048
openssl req -new \
    -key "$CERT_DIR/server-key.pem" \
    -out "$CERT_DIR/server.csr" \
    -subj "/CN=$CN_SERVER/O=Sentinel Dev"

cat > "$CERT_DIR/server-ext.cnf" <<EOF
subjectAltName=DNS:localhost,IP:127.0.0.1
EOF

openssl x509 -req -days "$DAYS" \
    -in "$CERT_DIR/server.csr" \
    -CA "$CERT_DIR/ca.pem" \
    -CAkey "$CERT_DIR/ca-key.pem" \
    -CAcreateserial \
    -out "$CERT_DIR/server.pem" \
    -extfile "$CERT_DIR/server-ext.cnf"

echo "=== Generating client certificate ==="
openssl genrsa -out "$CERT_DIR/client-key.pem" 2048
openssl req -new \
    -key "$CERT_DIR/client-key.pem" \
    -out "$CERT_DIR/client.csr" \
    -subj "/CN=$CN_CLIENT/O=Sentinel Dev"

openssl x509 -req -days "$DAYS" \
    -in "$CERT_DIR/client.csr" \
    -CA "$CERT_DIR/ca.pem" \
    -CAkey "$CERT_DIR/ca-key.pem" \
    -CAcreateserial \
    -out "$CERT_DIR/client.pem"

# Cleanup CSR and temporary files
rm -f "$CERT_DIR"/*.csr "$CERT_DIR"/*.srl "$CERT_DIR"/*.cnf

echo ""
echo "=== Certificates generated in $CERT_DIR/ ==="
echo "Server config (sentinel.yaml):"
echo "  tls_cert_file: $CERT_DIR/server.pem"
echo "  tls_key_file: $CERT_DIR/server-key.pem"
echo "  tls_client_ca_file: $CERT_DIR/ca.pem"
echo ""
echo "Client config (SDK transport):"
echo "  caCertPath: $CERT_DIR/ca.pem"
echo "  clientCertPath: $CERT_DIR/client.pem"
echo "  clientKeyPath: $CERT_DIR/client-key.pem"
