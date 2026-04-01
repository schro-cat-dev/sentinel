package webhook

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"
)

func TestNotifier_SendSuccess(t *testing.T) {
	var received []byte
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		received, _ = io.ReadAll(r.Body)
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	n := NewNotifier(srv.URL, 5, "")
	err := n.send(ApprovalPayload{TaskID: "t-1", RuleID: "r-1", EventName: "SYSTEM_CRITICAL_FAILURE"})
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}

	var p ApprovalPayload
	if err := json.Unmarshal(received, &p); err != nil {
		t.Fatalf("failed to unmarshal: %v", err)
	}
	if p.TaskID != "t-1" {
		t.Errorf("expected task_id=t-1, got %s", p.TaskID)
	}
}

func TestNotifier_SendHTTPError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer srv.Close()

	n := NewNotifier(srv.URL, 5, "")
	err := n.send(ApprovalPayload{TaskID: "t-1"})
	if err == nil {
		t.Fatal("expected error for 500 response")
	}
	if err.Error() != "webhook returned 500" {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestNotifier_SendTimeout(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(3 * time.Second)
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	n := NewNotifier(srv.URL, 1, "") // 1 second timeout
	err := n.send(ApprovalPayload{TaskID: "t-1"})
	if err == nil {
		t.Fatal("expected timeout error")
	}
}

func TestNotifier_HMACSignature(t *testing.T) {
	secret := "test-secret-key"
	var receivedSig string
	var receivedBody []byte

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		receivedSig = r.Header.Get("X-Sentinel-Signature")
		receivedBody, _ = io.ReadAll(r.Body)
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	n := NewNotifier(srv.URL, 5, secret)
	payload := ApprovalPayload{TaskID: "t-sig", RuleID: "r-sig"}
	if err := n.send(payload); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Verify signature
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write(receivedBody)
	expected := fmt.Sprintf("%x", mac.Sum(nil))

	if receivedSig != expected {
		t.Errorf("signature mismatch: got %s, want %s", receivedSig, expected)
	}
}

func TestNotifier_NoSignatureWithoutSecret(t *testing.T) {
	var receivedSig string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		receivedSig = r.Header.Get("X-Sentinel-Signature")
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	n := NewNotifier(srv.URL, 5, "")
	if err := n.send(ApprovalPayload{TaskID: "t-1"}); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if receivedSig != "" {
		t.Errorf("expected no signature header, got %s", receivedSig)
	}
}

func TestNotifier_ContentTypeJSON(t *testing.T) {
	var contentType string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		contentType = r.Header.Get("Content-Type")
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	n := NewNotifier(srv.URL, 5, "")
	if err := n.send(ApprovalPayload{TaskID: "t-1"}); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if contentType != "application/json" {
		t.Errorf("expected application/json, got %s", contentType)
	}
}

func TestNotifier_NotifyApprovalRequired_NonBlocking(t *testing.T) {
	var mu sync.Mutex
	calls := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		calls++
		mu.Unlock()
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	n := NewNotifier(srv.URL, 5, "")
	n.NotifyApprovalRequired(nil, ApprovalPayload{TaskID: "t-async"})

	// Give goroutine time to complete
	time.Sleep(100 * time.Millisecond)

	mu.Lock()
	defer mu.Unlock()
	if calls != 1 {
		t.Errorf("expected 1 call, got %d", calls)
	}
}

func TestNotifier_InvalidURL(t *testing.T) {
	n := NewNotifier("http://invalid-host-that-does-not-exist:9999", 1, "")
	err := n.send(ApprovalPayload{TaskID: "t-1"})
	if err == nil {
		t.Fatal("expected error for invalid URL")
	}
}
