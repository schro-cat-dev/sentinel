package grpc

import (
	"context"
	"testing"

	ggrpc "google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
)

// mock handler that records calls
func mockHandler(resp interface{}) ggrpc.UnaryHandler {
	return func(ctx context.Context, req interface{}) (interface{}, error) {
		return resp, nil
	}
}

func mockInfo(method string) *ggrpc.UnaryServerInfo {
	return &ggrpc.UnaryServerInfo{FullMethod: method}
}

// ===== AuthUnaryInterceptor =====

func TestAuth_ValidKey(t *testing.T) {
	interceptor := AuthUnaryInterceptor(map[string]bool{"valid-key-123": true})
	ctx := metadata.NewIncomingContext(context.Background(), metadata.Pairs("x-api-key", "valid-key-123"))

	resp, err := interceptor(ctx, nil, mockInfo("/sentinel.v1.SentinelService/IngestLog"), mockHandler("ok"))
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	if resp != "ok" {
		t.Errorf("expected 'ok', got %v", resp)
	}
}

func TestAuth_InvalidKey(t *testing.T) {
	interceptor := AuthUnaryInterceptor(map[string]bool{"valid-key-123": true})
	ctx := metadata.NewIncomingContext(context.Background(), metadata.Pairs("x-api-key", "wrong-key"))

	_, err := interceptor(ctx, nil, mockInfo("/sentinel.v1.SentinelService/IngestLog"), mockHandler("ok"))
	if err == nil {
		t.Fatal("expected unauthenticated error")
	}
	if s, ok := status.FromError(err); !ok || s.Code() != codes.Unauthenticated {
		t.Errorf("expected Unauthenticated, got %v", err)
	}
}

func TestAuth_MissingKey(t *testing.T) {
	interceptor := AuthUnaryInterceptor(map[string]bool{"valid-key-123": true})
	ctx := metadata.NewIncomingContext(context.Background(), metadata.Pairs())

	_, err := interceptor(ctx, nil, mockInfo("/sentinel.v1.SentinelService/IngestLog"), mockHandler("ok"))
	if err == nil {
		t.Fatal("expected unauthenticated error for missing key")
	}
}

func TestAuth_MissingMetadata(t *testing.T) {
	interceptor := AuthUnaryInterceptor(map[string]bool{"valid-key-123": true})

	_, err := interceptor(context.Background(), nil, mockInfo("/sentinel.v1.SentinelService/IngestLog"), mockHandler("ok"))
	if err == nil {
		t.Fatal("expected unauthenticated error for missing metadata")
	}
}

func TestAuth_HealthCheckBypass(t *testing.T) {
	interceptor := AuthUnaryInterceptor(map[string]bool{"valid-key-123": true})

	// HealthCheck should bypass auth even without metadata
	resp, err := interceptor(context.Background(), nil, mockInfo("/sentinel.v1.SentinelService/HealthCheck"), mockHandler("healthy"))
	if err != nil {
		t.Fatalf("expected no error for HealthCheck, got %v", err)
	}
	if resp != "healthy" {
		t.Errorf("expected 'healthy', got %v", resp)
	}
}

func TestAuth_EmptyKeyString(t *testing.T) {
	interceptor := AuthUnaryInterceptor(map[string]bool{"valid-key-123": true})
	ctx := metadata.NewIncomingContext(context.Background(), metadata.Pairs("x-api-key", ""))

	_, err := interceptor(ctx, nil, mockInfo("/sentinel.v1.SentinelService/IngestLog"), mockHandler("ok"))
	if err == nil {
		t.Fatal("expected unauthenticated error for empty key")
	}
}

func TestAuth_ClientIDPropagation(t *testing.T) {
	interceptor := AuthUnaryInterceptor(map[string]bool{"my-key": true})
	ctx := metadata.NewIncomingContext(context.Background(), metadata.Pairs("x-api-key", "my-key"))

	var capturedCtx context.Context
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		capturedCtx = ctx
		return "ok", nil
	}

	_, err := interceptor(ctx, nil, mockInfo("/sentinel.v1.SentinelService/IngestLog"), handler)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	clientID := ClientIDFromContext(capturedCtx)
	if clientID != "my-key" {
		t.Errorf("expected clientID='my-key', got '%s'", clientID)
	}
}

// ===== RateLimitUnaryInterceptor =====

func TestRateLimit_AllowsWithinLimit(t *testing.T) {
	interceptor := RateLimitUnaryInterceptor(100, 10) // 100 rps, burst 10
	ctx := context.WithValue(context.Background(), clientIDKey, "client-1")

	for i := 0; i < 10; i++ {
		_, err := interceptor(ctx, nil, mockInfo("/test"), mockHandler("ok"))
		if err != nil {
			t.Fatalf("request %d should be allowed, got %v", i, err)
		}
	}
}

func TestRateLimit_BlocksExcessBurst(t *testing.T) {
	interceptor := RateLimitUnaryInterceptor(1, 2) // 1 rps, burst 2
	ctx := context.WithValue(context.Background(), clientIDKey, "client-burst")

	// First 2 should pass (burst)
	for i := 0; i < 2; i++ {
		_, err := interceptor(ctx, nil, mockInfo("/test"), mockHandler("ok"))
		if err != nil {
			t.Fatalf("burst request %d should be allowed", i)
		}
	}

	// 3rd should be rate limited
	_, err := interceptor(ctx, nil, mockInfo("/test"), mockHandler("ok"))
	if err == nil {
		t.Fatal("expected rate limit error after burst exceeded")
	}
	if s, ok := status.FromError(err); !ok || s.Code() != codes.ResourceExhausted {
		t.Errorf("expected ResourceExhausted, got %v", err)
	}
}

func TestRateLimit_PerClientIsolation(t *testing.T) {
	interceptor := RateLimitUnaryInterceptor(1, 1)
	ctx1 := context.WithValue(context.Background(), clientIDKey, "client-A")
	ctx2 := context.WithValue(context.Background(), clientIDKey, "client-B")

	// Client A exhausts its limit
	interceptor(ctx1, nil, mockInfo("/test"), mockHandler("ok"))
	_, err := interceptor(ctx1, nil, mockInfo("/test"), mockHandler("ok"))
	if err == nil {
		t.Fatal("client-A should be rate limited")
	}

	// Client B should still be allowed
	_, err = interceptor(ctx2, nil, mockInfo("/test"), mockHandler("ok"))
	if err != nil {
		t.Fatalf("client-B should not be rate limited, got %v", err)
	}
}

func TestRateLimit_AnonymousClient(t *testing.T) {
	interceptor := RateLimitUnaryInterceptor(1, 1)
	ctx := context.Background() // no clientID → __anonymous__

	_, err := interceptor(ctx, nil, mockInfo("/test"), mockHandler("ok"))
	if err != nil {
		t.Fatalf("first anonymous request should be allowed, got %v", err)
	}

	_, err = interceptor(ctx, nil, mockInfo("/test"), mockHandler("ok"))
	if err == nil {
		t.Fatal("second anonymous request should be rate limited")
	}
}

// ===== AuditLogUnaryInterceptor =====

func TestAuditLog_DoesNotBlockRequest(t *testing.T) {
	interceptor := AuditLogUnaryInterceptor()
	ctx := context.WithValue(context.Background(), clientIDKey, "audit-client")

	resp, err := interceptor(ctx, nil, mockInfo("/test"), mockHandler("audited"))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if resp != "audited" {
		t.Errorf("expected 'audited', got %v", resp)
	}
}
