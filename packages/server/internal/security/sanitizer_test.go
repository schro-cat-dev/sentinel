package security

import (
	"strings"
	"testing"
)

func TestValidateString(t *testing.T) {
	t.Run("rejects oversized string", func(t *testing.T) {
		err := ValidateString("test", strings.Repeat("x", MaxFieldLength+1), MaxFieldLength)
		if err == nil {
			t.Error("expected error")
		}
	})

	t.Run("rejects invalid UTF-8", func(t *testing.T) {
		err := ValidateString("test", string([]byte{0xff, 0xfe}), 100)
		if err == nil {
			t.Error("expected error for invalid UTF-8")
		}
	})

	t.Run("rejects null bytes", func(t *testing.T) {
		err := ValidateString("test", "hello\x00world", 100)
		if err == nil {
			t.Error("expected error for null bytes")
		}
	})

	t.Run("accepts valid string", func(t *testing.T) {
		err := ValidateString("test", "hello world", 100)
		if err != nil {
			t.Errorf("unexpected error: %v", err)
		}
	})

	t.Run("accepts unicode", func(t *testing.T) {
		err := ValidateString("test", "こんにちは世界 🌍", 100)
		if err != nil {
			t.Errorf("unexpected error: %v", err)
		}
	})
}

func TestSanitizeString(t *testing.T) {
	t.Run("removes control characters", func(t *testing.T) {
		result := SanitizeString("hello\x01\x02world")
		if result != "helloworld" {
			t.Errorf("expected helloworld, got %q", result)
		}
	})

	t.Run("preserves tab and newline", func(t *testing.T) {
		result := SanitizeString("line1\nline2\ttab")
		if result != "line1\nline2\ttab" {
			t.Errorf("tab/newline should be preserved, got %q", result)
		}
	})

	t.Run("preserves normal text", func(t *testing.T) {
		result := SanitizeString("normal text 123")
		if result != "normal text 123" {
			t.Errorf("got %q", result)
		}
	})
}

func TestValidateRegexSafety(t *testing.T) {
	t.Run("accepts simple patterns", func(t *testing.T) {
		if err := ValidateRegexSafety(`[a-zA-Z]+@[a-zA-Z]+\.com`); err != nil {
			t.Errorf("should accept simple pattern: %v", err)
		}
	})

	t.Run("rejects oversized pattern", func(t *testing.T) {
		long := strings.Repeat("a", MaxRegexLength+1)
		if err := ValidateRegexSafety(long); err == nil {
			t.Error("should reject oversized pattern")
		}
	})

	t.Run("rejects invalid regex", func(t *testing.T) {
		if err := ValidateRegexSafety(`[unclosed`); err == nil {
			t.Error("should reject invalid regex")
		}
	})

	t.Run("rejects nested quantifiers", func(t *testing.T) {
		if err := ValidateRegexSafety(`((a+)+)b`); err == nil {
			t.Error("should reject nested quantifiers")
		}
	})

	t.Run("rejects excessive repetition", func(t *testing.T) {
		if err := ValidateRegexSafety(`a{10000}`); err == nil {
			t.Error("should reject excessive repetition")
		}
	})

	t.Run("accepts moderate repetition", func(t *testing.T) {
		if err := ValidateRegexSafety(`\d{3}-\d{4}`); err != nil {
			t.Errorf("should accept moderate repetition: %v", err)
		}
	})
}

func TestValidateLogType(t *testing.T) {
	valid := []string{"SYSTEM", "SECURITY", "COMPLIANCE", "INFRA", "SLA", "DEBUG", "BUSINESS-AUDIT"}
	for _, v := range valid {
		if !ValidateLogType(v) {
			t.Errorf("%s should be valid", v)
		}
	}
	invalid := []string{"", "UNKNOWN", "system", "SQL_INJECTION", "<script>"}
	for _, v := range invalid {
		if ValidateLogType(v) {
			t.Errorf("%s should be invalid", v)
		}
	}
}
