package security

import (
	"regexp"
	"strings"

	"github.com/schro-cat-dev/sentinel-server/internal/domain"
)

// MaskingRule マスキングルール
type MaskingRule struct {
	Type        string         // "REGEX", "PII_TYPE", "KEY_MATCH"
	Pattern     *regexp.Regexp // REGEX用
	Replacement string         // REGEX用
	Category    string         // PII_TYPE用
	Keys        []string       // KEY_MATCH用
}

// PIIパターンレジストリ（init()で拡張可能）
var piiPatterns = map[string]*regexp.Regexp{
	"EMAIL":         regexp.MustCompile(`[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}`),
	"CREDIT_CARD":   regexp.MustCompile(`\b(?:\d[ \-]*?){13,19}\b`),
	"PHONE":         regexp.MustCompile(`(\+81|0)\d{1,4}[\- ]?\d{1,4}[\- ]?\d{4}`),
	"GOVERNMENT_ID": regexp.MustCompile(`\b\d{12}\b`),
}

// RegisterPIIPattern はPIIパターンを登録する（init()から呼ばれる）
func RegisterPIIPattern(name string, pattern *regexp.Regexp) {
	piiPatterns[name] = pattern
}

// MaskingService PIIマスキングサービス
type MaskingService struct {
	rules          []MaskingRule
	preserveFields map[string]bool
	maxDepth       int
}

func NewMaskingService(rules []MaskingRule, preserveFields []string) *MaskingService {
	pf := make(map[string]bool, len(preserveFields))
	for _, f := range preserveFields {
		pf[f] = true
	}
	return &MaskingService{rules: rules, preserveFields: pf, maxDepth: 32}
}

// SetMaxDepth は再帰マスキングの最大深度を設定する
func (m *MaskingService) SetMaxDepth(depth int) {
	m.maxDepth = depth
}

// MaskLog はログ全体のPIIをマスクする（全フィールド対象）
func (m *MaskingService) MaskLog(log *domain.Log) {
	log.Message = m.maskString(log.Message)

	if !m.preserveFields["actorId"] && log.ActorID != "" {
		log.ActorID = m.maskString(log.ActorID)
	}

	for i := range log.Tags {
		if !m.preserveFields[log.Tags[i].Key] {
			log.Tags[i].Category = m.maskString(log.Tags[i].Category)
		}
	}

	// v2: 追加フィールドのマスキング
	if log.Input != "" {
		log.Input = m.maskString(log.Input)
	}

	if log.Details != nil {
		for k, v := range log.Details {
			if !m.preserveFields[k] {
				log.Details[k] = m.maskString(v)
			}
		}
	}

	if log.AIContext != nil {
		log.AIContext.ReasoningTrace = m.maskString(log.AIContext.ReasoningTrace)
	}

	for i := range log.AgentBackLog {
		log.AgentBackLog[i].Result = m.maskString(log.AgentBackLog[i].Result)
	}
}

// MaskValue は任意の値を再帰的にマスクする（深いオブジェクト/配列対応）
func (m *MaskingService) MaskValue(v interface{}, depth int) interface{} {
	if depth >= m.maxDepth {
		return "[MAX_DEPTH_EXCEEDED]"
	}

	switch val := v.(type) {
	case string:
		return m.maskString(val)
	case map[string]interface{}:
		result := make(map[string]interface{}, len(val))
		for k, item := range val {
			if m.preserveFields[k] {
				result[k] = item
			} else {
				result[k] = m.MaskValue(item, depth+1)
			}
		}
		return result
	case []interface{}:
		result := make([]interface{}, len(val))
		for i, item := range val {
			result[i] = m.MaskValue(item, depth+1)
		}
		return result
	default:
		return v
	}
}

func (m *MaskingService) maskString(text string) string {
	if text == "" {
		return text
	}
	result := text
	for _, rule := range m.rules {
		switch rule.Type {
		case "REGEX":
			if rule.Pattern != nil {
				result = rule.Pattern.ReplaceAllString(result, rule.Replacement)
			}
		case "PII_TYPE":
			if p, ok := piiPatterns[rule.Category]; ok {
				result = p.ReplaceAllString(result, "[MASKED_"+rule.Category+"]")
			}
		case "KEY_MATCH":
			// KEY_MATCH is handled at object level in MaskLog/MaskValue
		}
	}
	return result
}

// CompilePattern はパターン文字列をRegexpにコンパイルする（設定ファイル用）
func CompilePattern(pattern string) *regexp.Regexp {
	re, err := regexp.Compile(pattern)
	if err != nil {
		return nil
	}
	return re
}

// ContainsPII は文字列にPIIが含まれるか検査する
func ContainsPII(text string) bool {
	for _, p := range piiPatterns {
		if p.MatchString(text) {
			return true
		}
	}
	return false
}

// MaskAllPII は全PIIパターンをマスクする
func MaskAllPII(text string) string {
	result := text
	for category, p := range piiPatterns {
		result = p.ReplaceAllString(result, "[MASKED_"+strings.ToUpper(category)+"]")
	}
	return result
}
