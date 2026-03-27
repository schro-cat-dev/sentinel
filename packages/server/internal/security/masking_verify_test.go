package security

import (
	"testing"

	"github.com/schro-cat-dev/sentinel-server/internal/domain"
)

func TestMaskingVerifier_CleanLog(t *testing.T) {
	v := NewMaskingVerifier()

	log := domain.Log{
		Message: "Normal log message without PII",
		ActorID: "system",
	}
	result := v.VerifyLog(log)
	if !result.Clean {
		t.Errorf("expected clean, got leaks: %+v", result.Leaks)
	}
}

func TestMaskingVerifier_DetectsEmailLeak(t *testing.T) {
	v := NewMaskingVerifier()

	log := domain.Log{
		Message: "Contact admin@example.com for help",
	}
	result := v.VerifyLog(log)
	if result.Clean {
		t.Error("expected leak detection")
	}
	if len(result.Leaks) == 0 {
		t.Fatal("expected at least one leak")
	}

	found := false
	for _, leak := range result.Leaks {
		if leak.PIIType == "EMAIL" && leak.FieldName == "message" {
			found = true
		}
	}
	if !found {
		t.Errorf("expected EMAIL leak in message field, got %+v", result.Leaks)
	}
}

func TestMaskingVerifier_DetectsPhoneLeak(t *testing.T) {
	v := NewMaskingVerifier()

	log := domain.Log{
		Message: "Call 090-1234-5678",
	}
	result := v.VerifyLog(log)
	if result.Clean {
		t.Error("expected phone leak detection")
	}
}

func TestMaskingVerifier_DetectsLeakInTags(t *testing.T) {
	v := NewMaskingVerifier()

	log := domain.Log{
		Message: "test",
		Tags: []domain.LogTag{
			{Key: "contact", Category: "user@test.com"},
		},
	}
	result := v.VerifyLog(log)
	if result.Clean {
		t.Error("expected leak in tags")
	}
	if result.Leaks[0].FieldName != "tags[contact]" {
		t.Errorf("expected field tags[contact], got %s", result.Leaks[0].FieldName)
	}
}

func TestMaskingVerifier_DetectsLeakInDetails(t *testing.T) {
	v := NewMaskingVerifier()

	log := domain.Log{
		Message: "test",
		Details: map[string]string{
			"email": "admin@corp.com",
		},
	}
	result := v.VerifyLog(log)
	if result.Clean {
		t.Error("expected leak in details")
	}
}

func TestMaskingVerifier_DetectsLeakInAIContext(t *testing.T) {
	v := NewMaskingVerifier()

	log := domain.Log{
		Message: "test",
		AIContext: &domain.AIContext{
			ReasoningTrace: "User admin@secret.com requested analysis",
		},
	}
	result := v.VerifyLog(log)
	if result.Clean {
		t.Error("expected leak in AI context")
	}
}

func TestMaskingVerifier_DetectsLeakInAgentBackLog(t *testing.T) {
	v := NewMaskingVerifier()

	log := domain.Log{
		Message: "test",
		AgentBackLog: []domain.AgentBackLogEntry{
			{Result: "Found user@leak.com in data"},
		},
	}
	result := v.VerifyLog(log)
	if result.Clean {
		t.Error("expected leak in agent back log")
	}
}

func TestMaskingVerifier_FilterByCategory(t *testing.T) {
	v := NewMaskingVerifier("PHONE") // Only check for phone

	log := domain.Log{
		Message: "Contact admin@example.com or call 090-1234-5678",
	}
	result := v.VerifyLog(log)
	if result.Clean {
		t.Error("expected phone leak")
	}

	// Should only have PHONE leaks, not EMAIL
	for _, leak := range result.Leaks {
		if leak.PIIType == "EMAIL" {
			t.Error("should not detect EMAIL when filtering for PHONE only")
		}
	}
}

func TestMaskingVerifier_ActorIDLeak(t *testing.T) {
	v := NewMaskingVerifier()

	log := domain.Log{
		Message: "test",
		ActorID: "user@company.com",
	}
	result := v.VerifyLog(log)
	if result.Clean {
		t.Error("expected leak in actorId")
	}

	found := false
	for _, leak := range result.Leaks {
		if leak.FieldName == "actorId" {
			found = true
		}
	}
	if !found {
		t.Error("expected actorId field in leaks")
	}
}

func TestMaskingVerifier_InputFieldLeak(t *testing.T) {
	v := NewMaskingVerifier()

	log := domain.Log{
		Message: "test",
		Input:   "Please analyze user@private.com data",
	}
	result := v.VerifyLog(log)
	if result.Clean {
		t.Error("expected leak in input")
	}
}

func TestMaskingVerifier_EmptyFields(t *testing.T) {
	v := NewMaskingVerifier()

	log := domain.Log{}
	result := v.VerifyLog(log)
	if !result.Clean {
		t.Errorf("empty log should be clean, got leaks: %+v", result.Leaks)
	}
}

func TestMaskingVerifier_MaskedLogIsClean(t *testing.T) {
	// Mask first, then verify
	svc := NewMaskingService([]MaskingRule{
		{Type: "PII_TYPE", Category: "EMAIL"},
		{Type: "PII_TYPE", Category: "PHONE"},
	}, nil)

	log := domain.Log{
		Message: "Contact admin@example.com or call 090-1234-5678",
		ActorID: "user@test.com",
	}
	svc.MaskLog(&log)

	v := NewMaskingVerifier("EMAIL", "PHONE")
	result := v.VerifyLog(log)
	if !result.Clean {
		t.Errorf("masked log should be clean, got leaks: %+v", result.Leaks)
	}
}
