package security

import (
	"fmt"
	"regexp"
	"strings"
	"unicode"
	"unicode/utf8"
)

// --- Input Sanitization ---
// ReDoS攻撃防止、インジェクション防止、入力値の安全性検証

const (
	MaxFieldLength   = 65536
	MaxTagCount      = 100
	MaxTagKeyLength  = 128
	MaxTagValueLength = 1024
	MaxDetailsCount  = 50
	MaxResourceIDs   = 100
	MaxRegexLength   = 256 // ユーザー定義正規表現の最大長
)

// 危険な正規表現パターン（ReDoS脆弱性を持つ構造）
var dangerousRegexPatterns = []string{
	`(a+)+`,        // Nested quantifiers
	`(a|a)+`,       // Alternation with overlap
	`(.*a){10,}`,   // Greedy with backreference-like
}

// ホワイトリスト: 許可されるLogType
var allowedLogTypes = map[string]bool{
	"SYSTEM": true, "SECURITY": true, "COMPLIANCE": true,
	"INFRA": true, "SLA": true, "DEBUG": true, "BUSINESS-AUDIT": true,
}

// ホワイトリスト: 許可されるOrigin
var allowedOrigins = map[string]bool{
	"SYSTEM": true, "AI_AGENT": true,
}

// ホワイトリスト: 許可されるActionType
var allowedActionTypes = map[string]bool{
	"AI_ANALYZE": true, "AUTOMATED_REMEDIATE": true, "SYSTEM_NOTIFICATION": true,
	"EXTERNAL_WEBHOOK": true, "KILL_SWITCH": true, "ESCALATE": true,
}

// SanitizeError はサニタイズ違反エラー
type SanitizeError struct {
	Field   string
	Message string
}

func (e *SanitizeError) Error() string {
	return fmt.Sprintf("sanitize(%s): %s", e.Field, e.Message)
}

// ValidateString は文字列フィールドを検証する
func ValidateString(field, value string, maxLen int) error {
	if len(value) > maxLen {
		return &SanitizeError{Field: field, Message: fmt.Sprintf("exceeds max length %d", maxLen)}
	}
	if !utf8.ValidString(value) {
		return &SanitizeError{Field: field, Message: "invalid UTF-8"}
	}
	if strings.ContainsRune(value, '\x00') {
		return &SanitizeError{Field: field, Message: "contains null bytes"}
	}
	return nil
}

// SanitizeString は文字列から制御文字を除去する（タブ・改行は許可）
func SanitizeString(s string) string {
	return strings.Map(func(r rune) rune {
		if r == '\t' || r == '\n' {
			return r
		}
		if unicode.IsControl(r) {
			return -1
		}
		return r
	}, s)
}

// ValidateLogType はLogTypeがホワイトリストに含まれるか検証する
func ValidateLogType(t string) bool {
	return allowedLogTypes[t]
}

// ValidateOrigin はOriginがホワイトリストに含まれるか検証する
func ValidateOrigin(o string) bool {
	return o == "" || allowedOrigins[o]
}

// ValidateActionType はActionTypeがホワイトリストに含まれるか検証する
func ValidateActionType(a string) bool {
	return allowedActionTypes[a]
}

// ValidateRegexSafety はユーザー定義正規表現のReDoS脆弱性をチェックする
func ValidateRegexSafety(pattern string) error {
	if len(pattern) > MaxRegexLength {
		return &SanitizeError{Field: "regex", Message: fmt.Sprintf("pattern too long (%d > %d)", len(pattern), MaxRegexLength)}
	}

	// コンパイル可能か確認
	_, err := regexp.Compile(pattern)
	if err != nil {
		return &SanitizeError{Field: "regex", Message: fmt.Sprintf("invalid regex: %v", err)}
	}

	// 危険なパターンの検出（簡易ヒューリスティック）
	// ネストされた量指定子の検出
	nestCount := 0
	for _, ch := range pattern {
		switch ch {
		case '(':
			nestCount++
		case ')':
			nestCount--
		case '+', '*':
			if nestCount > 1 {
				return &SanitizeError{Field: "regex", Message: "nested quantifiers detected (ReDoS risk)"}
			}
		}
	}

	// 過度な繰り返し回数の検出
	if strings.Contains(pattern, "{") {
		re := regexp.MustCompile(`\{(\d+),?(\d*)\}`)
		matches := re.FindAllStringSubmatch(pattern, -1)
		for _, m := range matches {
			if len(m) > 1 {
				// 1000以上の繰り返しは拒否
				var n int
				fmt.Sscanf(m[1], "%d", &n)
				if n > 1000 {
					return &SanitizeError{Field: "regex", Message: fmt.Sprintf("repetition count too high (%d > 1000)", n)}
				}
			}
		}
	}

	return nil
}

// ValidateTags はタグ配列を検証する
func ValidateTags(tags []struct{ Key, Category string }) error {
	if len(tags) > MaxTagCount {
		return &SanitizeError{Field: "tags", Message: fmt.Sprintf("too many tags (%d > %d)", len(tags), MaxTagCount)}
	}
	for i, tag := range tags {
		if err := ValidateString(fmt.Sprintf("tags[%d].key", i), tag.Key, MaxTagKeyLength); err != nil {
			return err
		}
		if err := ValidateString(fmt.Sprintf("tags[%d].category", i), tag.Category, MaxTagValueLength); err != nil {
			return err
		}
	}
	return nil
}
