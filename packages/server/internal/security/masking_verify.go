package security

import (
	"github.com/schro-cat-dev/sentinel-server/internal/domain"
)

// PIILeakField はPII漏洩が検出されたフィールドの情報
type PIILeakField struct {
	FieldName  string // 漏洩が検出されたフィールド名
	PIIType    string // 検出されたPII種別
	Snippet    string // 検出箇所の部分文字列（最大50文字）
}

// VerificationResult はマスク後の検証結果
type VerificationResult struct {
	Clean  bool           // PIIが残留していない場合true
	Leaks  []PIILeakField // 漏洩検出リスト
}

// MaskingVerifier はマスク後のPII残留を検証する
type MaskingVerifier struct {
	patterns map[string]bool // 検証対象のPIIカテゴリ（空=全パターン）
}

// NewMaskingVerifier はMaskingVerifierを生成する
func NewMaskingVerifier(categories ...string) *MaskingVerifier {
	cats := make(map[string]bool, len(categories))
	for _, c := range categories {
		cats[c] = true
	}
	return &MaskingVerifier{patterns: cats}
}

// VerifyLog はマスク済みログにPIIが残留していないか検証する
func (v *MaskingVerifier) VerifyLog(log domain.Log) VerificationResult {
	var leaks []PIILeakField

	leaks = append(leaks, v.checkField("message", log.Message)...)
	leaks = append(leaks, v.checkField("actorId", log.ActorID)...)
	leaks = append(leaks, v.checkField("input", log.Input)...)

	for _, tag := range log.Tags {
		leaks = append(leaks, v.checkField("tags["+tag.Key+"]", tag.Category)...)
	}

	for k, val := range log.Details {
		leaks = append(leaks, v.checkField("details["+k+"]", val)...)
	}

	if log.AIContext != nil {
		leaks = append(leaks, v.checkField("aiContext.reasoningTrace", log.AIContext.ReasoningTrace)...)
	}

	for i, entry := range log.AgentBackLog {
		leaks = append(leaks, v.checkField("agentBackLog["+itoa(i)+"].result", entry.Result)...)
	}

	return VerificationResult{
		Clean: len(leaks) == 0,
		Leaks: leaks,
	}
}

func (v *MaskingVerifier) checkField(fieldName, value string) []PIILeakField {
	if value == "" {
		return nil
	}

	var leaks []PIILeakField
	for category, pattern := range piiPatterns {
		if len(v.patterns) > 0 && !v.patterns[category] {
			continue
		}
		locs := pattern.FindStringIndex(value)
		if locs == nil {
			continue
		}

		snippet := value[locs[0]:locs[1]]
		if len(snippet) > 50 {
			snippet = snippet[:50] + "..."
		}

		leaks = append(leaks, PIILeakField{
			FieldName: fieldName,
			PIIType:   category,
			Snippet:   snippet,
		})
	}
	return leaks
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	result := ""
	for n > 0 {
		result = string(rune('0'+n%10)) + result
		n /= 10
	}
	return result
}
