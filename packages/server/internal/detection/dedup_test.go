package detection

import (
	"testing"
	"time"
)

func TestDeduplicator_Basic(t *testing.T) {
	d := NewDeduplicator(100 * time.Millisecond)

	t.Run("first event is not duplicate", func(t *testing.T) {
		if d.IsDuplicate("event-1") {
			t.Error("first event should not be duplicate")
		}
	})

	t.Run("same event within window is duplicate", func(t *testing.T) {
		if !d.IsDuplicate("event-1") {
			t.Error("same event should be duplicate within window")
		}
	})

	t.Run("different event is not duplicate", func(t *testing.T) {
		if d.IsDuplicate("event-2") {
			t.Error("different event should not be duplicate")
		}
	})
}

func TestDeduplicator_WindowExpiry(t *testing.T) {
	d := NewDeduplicator(50 * time.Millisecond)

	if d.IsDuplicate("event-1") {
		t.Error("first should not be duplicate")
	}

	time.Sleep(60 * time.Millisecond)

	if d.IsDuplicate("event-1") {
		t.Error("should not be duplicate after window expiry")
	}
}

func TestDeduplicator_Reset(t *testing.T) {
	d := NewDeduplicator(1 * time.Second)

	d.IsDuplicate("a")
	d.IsDuplicate("b")

	if d.Size() != 2 {
		t.Errorf("expected size 2, got %d", d.Size())
	}

	d.Reset()
	if d.Size() != 0 {
		t.Errorf("expected size 0 after reset, got %d", d.Size())
	}

	// After reset, same key is not duplicate
	if d.IsDuplicate("a") {
		t.Error("should not be duplicate after reset")
	}
}

func TestDeduplicator_Size(t *testing.T) {
	d := NewDeduplicator(1 * time.Second)

	d.IsDuplicate("a")
	d.IsDuplicate("b")
	d.IsDuplicate("c")
	d.IsDuplicate("a") // duplicate, doesn't add

	if d.Size() != 3 {
		t.Errorf("expected 3, got %d", d.Size())
	}
}
