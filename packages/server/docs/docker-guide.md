# Sentinel Server — Docker 導入ガイド

---

## Dockerfile

```dockerfile
# --- Build stage ---
FROM golang:1.22-alpine AS builder
WORKDIR /app
COPY packages/server/go.mod packages/server/go.sum ./
RUN go mod download
COPY packages/server/ ./
RUN CGO_ENABLED=1 go build -o sentinel-server ./cmd/server/

# --- Runtime stage ---
FROM alpine:3.20
RUN apk add --no-cache sqlite-libs ca-certificates
COPY --from=builder /app/sentinel-server /usr/local/bin/
COPY packages/server/config/sentinel.yaml /etc/sentinel/config.yaml

EXPOSE 50051
ENTRYPOINT ["sentinel-server", "-config", "/etc/sentinel/config.yaml"]
```

**注意**: SQLite は CGO を使うため `CGO_ENABLED=1` が必要。Alpine の場合は `musl` 用のビルド。

---

## docker-compose.yml

```yaml
version: "3.8"

services:
  sentinel:
    build:
      context: .
      dockerfile: packages/server/Dockerfile
    ports:
      - "50051:50051"
    environment:
      - SENTINEL_HMAC_KEY=your-secret-key-at-least-32-bytes-long!!
      - SENTINEL_ENSEMBLE_ENABLED=true
      - SENTINEL_ANOMALY_ENABLED=true
      - SENTINEL_AGENT_ENABLED=true
      - SENTINEL_RESPONSE_ENABLED=true
      - SENTINEL_RESPONSE_DEFAULT_STRATEGY=BLOCK_AND_NOTIFY
      # 通知（必要な場合のみ）
      # - SENTINEL_SLACK_WEBHOOK_URL=https://hooks.slack.com/services/...
      # - SENTINEL_DISCORD_WEBHOOK_URL=https://discord.com/api/webhooks/...
      # - SENTINEL_GMAIL_FROM=sentinel@company.com
      # - SENTINEL_GMAIL_PASSWORD=app-password
    volumes:
      - sentinel-data:/data
      - ./config/sentinel.yaml:/etc/sentinel/config.yaml:ro
    restart: unless-stopped
    healthcheck:
      test: ["CMD", "grpcurl", "-plaintext", "localhost:50051", "sentinel.v1.SentinelService/HealthCheck"]
      interval: 30s
      timeout: 5s
      retries: 3

volumes:
  sentinel-data:
```

---

## 起動

```bash
# ビルド + 起動
docker compose up -d

# ログ確認
docker compose logs -f sentinel

# ヘルスチェック
docker compose exec sentinel grpcurl -plaintext localhost:50051 sentinel.v1.SentinelService/HealthCheck

# 停止
docker compose down
```

---

## 設定のマウント

本番用の設定ファイルをボリュームマウント:

```bash
docker run -d \
  -p 50051:50051 \
  -v $(pwd)/config/production.yaml:/etc/sentinel/config.yaml:ro \
  -v sentinel-data:/data \
  -e SENTINEL_HMAC_KEY="$SENTINEL_HMAC_KEY" \
  -e SENTINEL_RESPONSE_ENABLED=true \
  sentinel-server
```

---

## Kubernetes

```yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: sentinel
spec:
  replicas: 1
  selector:
    matchLabels:
      app: sentinel
  template:
    metadata:
      labels:
        app: sentinel
    spec:
      containers:
        - name: sentinel
          image: sentinel-server:latest
          ports:
            - containerPort: 50051
              name: grpc
          envFrom:
            - secretRef:
                name: sentinel-secrets
            - configMapRef:
                name: sentinel-config
          volumeMounts:
            - name: config
              mountPath: /etc/sentinel
            - name: data
              mountPath: /data
          livenessProbe:
            exec:
              command: ["grpcurl", "-plaintext", "localhost:50051", "sentinel.v1.SentinelService/HealthCheck"]
            initialDelaySeconds: 5
            periodSeconds: 30
          resources:
            requests:
              cpu: 100m
              memory: 128Mi
            limits:
              cpu: 500m
              memory: 512Mi
      volumes:
        - name: config
          configMap:
            name: sentinel-yaml
        - name: data
          persistentVolumeClaim:
            claimName: sentinel-pvc
---
apiVersion: v1
kind: Service
metadata:
  name: sentinel
spec:
  selector:
    app: sentinel
  ports:
    - port: 50051
      targetPort: grpc
      name: grpc
```

---

## 注意事項

- SQLite はシングルライターのため、**レプリカ数は1**を推奨。スケールアウトにはPostgreSQL等への移行が必要
- TLS は `server.tls_cert_file` / `server.tls_key_file` でサーバ側で有効化可能。または Envoy/Nginx 等のリバースプロキシで TLS 終端する
- データの永続化は `/data` ディレクトリにマウント。SQLite ファイルが保存される
