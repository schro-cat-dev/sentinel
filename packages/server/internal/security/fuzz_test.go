package security

import (
	"testing"

	"github.com/schro-cat-dev/sentinel-server/internal/domain"
)

func FuzzValidateString(f *testing.F) {
	f.Add("hello world")
	f.Add("")
	f.Add("hello\x00world")
	f.Add(string([]byte{0xff, 0xfe}))
	f.Add("こんにちは")
	f.Add("a{10000}")
	f.Add("'; DROP TABLE logs; --")

	f.Fuzz(func(t *testing.T, input string) {
		// Should not panic
		_ = ValidateString("fuzz", input, MaxFieldLength)
	})
}

func FuzzSanitizeString(f *testing.F) {
	f.Add("normal text")
	f.Add("hello\x01\x02world")
	f.Add("line1\nline2\ttab")
	f.Add("<script>alert('xss')</script>")

	f.Fuzz(func(t *testing.T, input string) {
		// Should not panic
		result := SanitizeString(input)
		// Result should not contain control chars (except tab/newline)
		for _, r := range result {
			if r != '\t' && r != '\n' && r < 0x20 && r != -1 {
				t.Errorf("control char %d in sanitized output", r)
			}
		}
	})
}

func FuzzValidateRegexSafety(f *testing.F) {
	f.Add(`[a-zA-Z]+@[a-zA-Z]+\.com`)
	f.Add(`((a+)+)b`)
	f.Add(`a{10000}`)
	f.Add(`[unclosed`)
	f.Add(`(?i)brute\s*force`)

	f.Fuzz(func(t *testing.T, pattern string) {
		// Should not panic
		_ = ValidateRegexSafety(pattern)
	})
}

func FuzzMaskString(f *testing.F) {
	svc := NewMaskingService([]MaskingRule{
		{Type: "PII_TYPE", Category: "EMAIL"},
		{Type: "PII_TYPE", Category: "PHONE"},
	}, nil)

	f.Add("Contact admin@example.com for help")
	f.Add("Call 090-1234-5678")
	f.Add("No PII here")
	f.Add("")

	f.Fuzz(func(t *testing.T, input string) {
		log := domain.Log{Message: input}
		// Should not panic
		svc.MaskLog(&log)
	})
}

func FuzzContainsPII(f *testing.F) {
	f.Add("admin@test.com")
	f.Add("no pii")
	f.Add("4111-1111-1111-1111")

	f.Fuzz(func(t *testing.T, input string) {
		// Should not panic
		_ = ContainsPII(input)
	})
}
