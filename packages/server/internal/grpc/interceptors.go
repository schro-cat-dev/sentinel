package grpc

import (
	"context"
	"log/slog"
	"sync"

	ggrpc "google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"

	"golang.org/x/time/rate"
)

type contextKey string

const clientIDKey contextKey = "clientID"

// AuthUnaryInterceptor はAPI Key認証インターセプター
func AuthUnaryInterceptor(validKeys map[string]bool) ggrpc.UnaryServerInterceptor {
	return func(ctx context.Context, req any, info *ggrpc.UnaryServerInfo, handler ggrpc.UnaryHandler) (any, error) {
		// HealthCheckは認証不要
		if info.FullMethod == "/sentinel.v1.SentinelService/HealthCheck" {
			return handler(ctx, req)
		}

		md, ok := metadata.FromIncomingContext(ctx)
		if !ok {
			return nil, status.Error(codes.Unauthenticated, "missing metadata")
		}

		keys := md.Get("x-api-key")
		if len(keys) == 0 || !validKeys[keys[0]] {
			slog.Warn("authentication failed", "method", info.FullMethod)
			return nil, status.Error(codes.Unauthenticated, "invalid or missing API key")
		}

		ctx = context.WithValue(ctx, clientIDKey, keys[0])
		return handler(ctx, req)
	}
}

// RateLimitUnaryInterceptor はクライアント別レート制限インターセプター
func RateLimitUnaryInterceptor(rps float64, burst int) ggrpc.UnaryServerInterceptor {
	var mu sync.Mutex
	limiters := make(map[string]*rate.Limiter)

	getLimiter := func(clientID string) *rate.Limiter {
		mu.Lock()
		defer mu.Unlock()
		if l, ok := limiters[clientID]; ok {
			return l
		}
		l := rate.NewLimiter(rate.Limit(rps), burst)
		limiters[clientID] = l
		return l
	}

	return func(ctx context.Context, req any, info *ggrpc.UnaryServerInfo, handler ggrpc.UnaryHandler) (any, error) {
		clientID, _ := ctx.Value(clientIDKey).(string)
		if clientID == "" {
			clientID = "__anonymous__"
		}

		if !getLimiter(clientID).Allow() {
			slog.Warn("rate limit exceeded", "clientID", clientID, "method", info.FullMethod)
			return nil, status.Error(codes.ResourceExhausted, "rate limit exceeded")
		}

		return handler(ctx, req)
	}
}

// ClientIDFromContext はコンテキストからクライアントIDを取得する
func ClientIDFromContext(ctx context.Context) string {
	id, _ := ctx.Value(clientIDKey).(string)
	return id
}

// AuditLogUnaryInterceptor は全gRPCリクエストのアクセスログを記録する
func AuditLogUnaryInterceptor() ggrpc.UnaryServerInterceptor {
	return func(ctx context.Context, req interface{}, info *ggrpc.UnaryServerInfo, handler ggrpc.UnaryHandler) (interface{}, error) {
		clientID := ClientIDFromContext(ctx)
		if clientID == "" {
			clientID = "anonymous"
		}

		resp, err := handler(ctx, req)

		status := "ok"
		if err != nil {
			status = "error"
		}

		slog.Info("audit",
			"method", info.FullMethod,
			"clientId", clientID,
			"status", status,
		)

		return resp, err
	}
}
