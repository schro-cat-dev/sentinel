package security

import (
	"regexp"
	"strings"
	"testing"

	"github.com/schro-cat-dev/sentinel-server/internal/domain"
)

func TestMaskingService_MaskString(t *testing.T) {
	t.Run("masks email via PII_TYPE rule", func(t *testing.T) {
		svc := NewMaskingService([]MaskingRule{
			{Type: "PII_TYPE", Category: "EMAIL"},
		}, nil)
		result := svc.maskString("Contact admin@example.com for help")
		if strings.Contains(result, "admin@example.com") {
			t.Error("email should be masked")
		}
		if !strings.Contains(result, "[MASKED_EMAIL]") {
			t.Errorf("expected [MASKED_EMAIL], got %q", result)
		}
	})

	t.Run("masks credit card", func(t *testing.T) {
		svc := NewMaskingService([]MaskingRule{
			{Type: "PII_TYPE", Category: "CREDIT_CARD"},
		}, nil)
		result := svc.maskString("Card: 4111 1111 1111 1111")
		if strings.Contains(result, "4111") {
			t.Errorf("credit card should be masked, got %q", result)
		}
	})

	t.Run("masks phone (Japan)", func(t *testing.T) {
		svc := NewMaskingService([]MaskingRule{
			{Type: "PII_TYPE", Category: "PHONE"},
		}, nil)
		result := svc.maskString("Call 090-1234-5678")
		if strings.Contains(result, "090-1234-5678") {
			t.Error("phone should be masked")
		}
	})

	t.Run("masks government ID", func(t *testing.T) {
		svc := NewMaskingService([]MaskingRule{
			{Type: "PII_TYPE", Category: "GOVERNMENT_ID"},
		}, nil)
		result := svc.maskString("ID: 123456789012")
		if strings.Contains(result, "123456789012") {
			t.Error("government ID should be masked")
		}
	})

	t.Run("masks via REGEX rule", func(t *testing.T) {
		svc := NewMaskingService([]MaskingRule{
			{Type: "REGEX", Pattern: regexp.MustCompile(`secret-\d+`), Replacement: "[REDACTED]"},
		}, nil)
		result := svc.maskString("Found secret-123 and secret-456")
		if strings.Contains(result, "secret-") {
			t.Errorf("regex should mask, got %q", result)
		}
		if !strings.Contains(result, "[REDACTED]") {
			t.Errorf("expected [REDACTED], got %q", result)
		}
	})

	t.Run("empty string returns empty", func(t *testing.T) {
		svc := NewMaskingService(nil, nil)
		if result := svc.maskString(""); result != "" {
			t.Errorf("expected empty, got %q", result)
		}
	})

	t.Run("multiple rules apply in order", func(t *testing.T) {
		svc := NewMaskingService([]MaskingRule{
			{Type: "PII_TYPE", Category: "EMAIL"},
			{Type: "REGEX", Pattern: regexp.MustCompile(`\[MASKED_EMAIL\]`), Replacement: "[DOUBLE]"},
		}, nil)
		result := svc.maskString("user@test.com")
		if result != "[DOUBLE]" {
			t.Errorf("expected [DOUBLE], got %q", result)
		}
	})
}

func TestMaskingService_MaskLog(t *testing.T) {
	t.Run("masks message field", func(t *testing.T) {
		svc := NewMaskingService([]MaskingRule{
			{Type: "PII_TYPE", Category: "EMAIL"},
		}, []string{"traceId"})
		log := domain.Log{Message: "Contact admin@example.com"}
		svc.MaskLog(&log)
		if strings.Contains(log.Message, "admin@example.com") {
			t.Error("message should be masked")
		}
	})

	t.Run("masks actorID", func(t *testing.T) {
		svc := NewMaskingService([]MaskingRule{
			{Type: "PII_TYPE", Category: "EMAIL"},
		}, nil)
		log := domain.Log{Message: "test", ActorID: "user@company.com"}
		svc.MaskLog(&log)
		if strings.Contains(log.ActorID, "@") {
			t.Errorf("actorID should be masked, got %q", log.ActorID)
		}
	})

	t.Run("preserves actorId when in preserveFields", func(t *testing.T) {
		svc := NewMaskingService([]MaskingRule{
			{Type: "PII_TYPE", Category: "EMAIL"},
		}, []string{"actorId"})
		log := domain.Log{Message: "test", ActorID: "user@company.com"}
		svc.MaskLog(&log)
		if log.ActorID != "user@company.com" {
			t.Errorf("actorID should be preserved, got %q", log.ActorID)
		}
	})

	t.Run("masks tag categories", func(t *testing.T) {
		svc := NewMaskingService([]MaskingRule{
			{Type: "PII_TYPE", Category: "EMAIL"},
		}, nil)
		log := domain.Log{
			Message: "test",
			Tags:    []domain.LogTag{{Key: "contact", Category: "user@test.com"}},
		}
		svc.MaskLog(&log)
		if strings.Contains(log.Tags[0].Category, "@") {
			t.Errorf("tag category should be masked, got %q", log.Tags[0].Category)
		}
	})

	t.Run("preserves specified tag keys", func(t *testing.T) {
		svc := NewMaskingService([]MaskingRule{
			{Type: "PII_TYPE", Category: "EMAIL"},
		}, []string{"ip"})
		log := domain.Log{
			Message: "test",
			Tags:    []domain.LogTag{{Key: "ip", Category: "user@test.com"}},
		}
		svc.MaskLog(&log)
		if log.Tags[0].Category != "user@test.com" {
			t.Error("preserved tag should not be masked")
		}
	})
}

func TestContainsPII(t *testing.T) {
	if !ContainsPII("email: admin@test.com") {
		t.Error("should detect email PII")
	}
	if ContainsPII("no pii here") {
		t.Error("should not detect PII in clean text")
	}
}
