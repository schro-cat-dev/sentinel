package notify

import (
	"context"
	"sync"
	"testing"
)

func TestMultiNotifier_RegisterAndSend(t *testing.T) {
	multi := NewMultiNotifier()
	slack := NewMockNotifier("slack")
	gmail := NewMockNotifier("gmail")
	multi.Register(slack)
	multi.Register(gmail)

	n := Notification{
		Channel:   "#security",
		Subject:   "Security Alert",
		Body:      "Intrusion detected",
		Severity:  "high",
		TraceID:   "trace-001",
		EventName: "SECURITY_INTRUSION_DETECTED",
	}

	err := multi.Send(context.Background(), n)
	if err != nil {
		t.Fatalf("error: %v", err)
	}

	// Without routing, all notifiers receive the notification
	if slack.SentCount() != 1 {
		t.Errorf("slack: expected 1, got %d", slack.SentCount())
	}
	if gmail.SentCount() != 1 {
		t.Errorf("gmail: expected 1, got %d", gmail.SentCount())
	}
}

func TestMultiNotifier_Routing(t *testing.T) {
	multi := NewMultiNotifier()
	slack := NewMockNotifier("slack")
	gmail := NewMockNotifier("gmail")
	webhook := NewMockNotifier("webhook")
	multi.Register(slack)
	multi.Register(gmail)
	multi.Register(webhook)

	multi.SetRouting("#", []string{"slack"})
	multi.SetRouting("@", []string{"gmail"})
	multi.SetRouting("https://", []string{"webhook"})

	t.Run("# routes to slack", func(t *testing.T) {
		slack.Reset()
		gmail.Reset()
		multi.Send(context.Background(), Notification{Channel: "#security"})
		if slack.SentCount() != 1 {
			t.Errorf("expected slack, got count %d", slack.SentCount())
		}
		if gmail.SentCount() != 0 {
			t.Error("gmail should not receive # channel")
		}
	})

	t.Run("@ routes to gmail", func(t *testing.T) {
		slack.Reset()
		gmail.Reset()
		multi.Send(context.Background(), Notification{Channel: "@admin@company.com"})
		if gmail.SentCount() != 1 {
			t.Errorf("expected gmail, got count %d", gmail.SentCount())
		}
		if slack.SentCount() != 0 {
			t.Error("slack should not receive @ channel")
		}
	})

	t.Run("https:// routes to webhook", func(t *testing.T) {
		webhook.Reset()
		multi.Send(context.Background(), Notification{Channel: "https://hooks.example.com/abc"})
		if webhook.SentCount() != 1 {
			t.Errorf("expected webhook, got count %d", webhook.SentCount())
		}
	})

	t.Run("unmatched prefix falls back to all", func(t *testing.T) {
		slack.Reset()
		gmail.Reset()
		webhook.Reset()
		multi.Send(context.Background(), Notification{Channel: "unknown-channel"})
		// All notifiers should receive it
		total := slack.SentCount() + gmail.SentCount() + webhook.SentCount()
		if total != 3 {
			t.Errorf("expected 3 (all notifiers), got %d", total)
		}
	})
}

func TestMultiNotifier_PartialFailure(t *testing.T) {
	multi := NewMultiNotifier()
	slack := NewMockNotifier("slack")
	gmail := NewMockNotifier("gmail")
	slack.SetShouldFail(true)
	multi.Register(slack)
	multi.Register(gmail)

	err := multi.Send(context.Background(), Notification{Channel: "test"})
	// Gmail succeeds, so overall no error
	if err != nil {
		t.Errorf("partial failure should not return error when one succeeds: %v", err)
	}
	if gmail.SentCount() != 1 {
		t.Error("gmail should still receive")
	}
}

func TestMultiNotifier_AllFail(t *testing.T) {
	multi := NewMultiNotifier()
	slack := NewMockNotifier("slack")
	gmail := NewMockNotifier("gmail")
	slack.SetShouldFail(true)
	gmail.SetShouldFail(true)
	multi.Register(slack)
	multi.Register(gmail)

	err := multi.Send(context.Background(), Notification{Channel: "test"})
	if err == nil {
		t.Error("expected error when all notifiers fail")
	}
}

func TestMultiNotifier_SendAll(t *testing.T) {
	multi := NewMultiNotifier()
	slack := NewMockNotifier("slack")
	gmail := NewMockNotifier("gmail")
	multi.Register(slack)
	multi.Register(gmail)

	multi.SetRouting("#", []string{"slack"}) // routing exists

	// SendAll ignores routing
	errs := multi.SendAll(context.Background(), Notification{Channel: "#security"})
	if len(errs) != 0 {
		t.Errorf("unexpected errors: %v", errs)
	}
	if slack.SentCount() != 1 {
		t.Error("slack should receive")
	}
	if gmail.SentCount() != 1 {
		t.Error("gmail should also receive via SendAll")
	}
}

func TestMultiNotifier_HasType(t *testing.T) {
	multi := NewMultiNotifier()
	multi.Register(NewMockNotifier("slack"))

	if !multi.HasType("slack") {
		t.Error("should have slack")
	}
	if multi.HasType("gmail") {
		t.Error("should not have gmail")
	}
}

func TestMultiNotifier_RegisteredTypes(t *testing.T) {
	multi := NewMultiNotifier()
	multi.Register(NewMockNotifier("slack"))
	multi.Register(NewMockNotifier("gmail"))
	multi.Register(NewMockNotifier("discord"))

	types := multi.RegisteredTypes()
	if len(types) != 3 {
		t.Errorf("expected 3 types, got %d", len(types))
	}
}

func TestMultiNotifier_ConcurrentSafety(t *testing.T) {
	multi := NewMultiNotifier()
	slack := NewMockNotifier("slack")
	multi.Register(slack)

	var wg sync.WaitGroup
	for i := 0; i < 100; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			multi.Send(context.Background(), Notification{
				Channel: "#test", Subject: "concurrent",
			})
		}()
	}
	wg.Wait()

	if slack.SentCount() != 100 {
		t.Errorf("expected 100, got %d", slack.SentCount())
	}
}

func TestMockNotifier_LastSent(t *testing.T) {
	mock := NewMockNotifier("test")

	_, ok := mock.LastSent()
	if ok {
		t.Error("should have no sent before sending")
	}

	mock.Send(context.Background(), Notification{Subject: "first"})
	mock.Send(context.Background(), Notification{Subject: "second"})

	last, ok := mock.LastSent()
	if !ok {
		t.Fatal("should have last")
	}
	if last.Subject != "second" {
		t.Errorf("expected 'second', got %s", last.Subject)
	}
}

func TestMockNotifier_Reset(t *testing.T) {
	mock := NewMockNotifier("test")
	mock.Send(context.Background(), Notification{Subject: "test"})
	if mock.SentCount() != 1 {
		t.Error("should have 1")
	}
	mock.Reset()
	if mock.SentCount() != 0 {
		t.Error("should be 0 after reset")
	}
}

func TestLogNotifier(t *testing.T) {
	log := NewLogNotifier()
	if log.Type() != "log" {
		t.Errorf("expected 'log', got %s", log.Type())
	}
	err := log.Send(context.Background(), Notification{
		Subject: "test", Body: "test body", Severity: "high",
	})
	if err != nil {
		t.Errorf("log notifier should not fail: %v", err)
	}
}

func TestNotification_Fields(t *testing.T) {
	n := Notification{
		Channel:   "#security",
		Subject:   "Alert",
		Body:      "Details here",
		Severity:  "critical",
		EventName: "SECURITY_INTRUSION_DETECTED",
		TraceID:   "trace-123",
		Fields: map[string]string{
			"ip":       "10.0.0.1",
			"action":   "block_ip",
			"risk":     "high",
		},
	}
	if len(n.Fields) != 3 {
		t.Errorf("expected 3 fields, got %d", len(n.Fields))
	}
	if n.Fields["ip"] != "10.0.0.1" {
		t.Error("wrong ip field")
	}
}

func TestSlackColor(t *testing.T) {
	tests := []struct{ severity, expected string }{
		{"critical", "#FF0000"},
		{"high", "#FF6600"},
		{"medium", "#FFCC00"},
		{"low", "#36A64F"},
		{"info", "#439FE0"},
		{"unknown", "#439FE0"},
	}
	for _, tt := range tests {
		got := slackColor(tt.severity)
		if got != tt.expected {
			t.Errorf("slackColor(%s) = %s, want %s", tt.severity, got, tt.expected)
		}
	}
}

func TestDiscordColor(t *testing.T) {
	if discordColor("critical") != 0xFF0000 {
		t.Error("wrong critical color")
	}
	if discordColor("low") != 0x36A64F {
		t.Error("wrong low color")
	}
}
