package security

import (
	"strings"
	"testing"

	"github.com/schro-cat-dev/sentinel-server/internal/domain"
)

func TestMaskLog_V2Fields(t *testing.T) {
	svc := NewMaskingService([]MaskingRule{
		{Type: "PII_TYPE", Category: "EMAIL"},
	}, []string{"traceId"})

	t.Run("masks Input field", func(t *testing.T) {
		log := domain.Log{Message: "test", Input: "contact admin@example.com"}
		svc.MaskLog(&log)
		if strings.Contains(log.Input, "admin@example.com") {
			t.Errorf("Input should be masked, got %q", log.Input)
		}
	})

	t.Run("masks Details values", func(t *testing.T) {
		log := domain.Log{
			Message: "test",
			Details: map[string]string{"email": "user@test.com", "name": "John"},
		}
		svc.MaskLog(&log)
		if strings.Contains(log.Details["email"], "@") {
			t.Errorf("Details email should be masked, got %q", log.Details["email"])
		}
		if log.Details["name"] != "John" {
			t.Errorf("Details name should not be masked, got %q", log.Details["name"])
		}
	})

	t.Run("masks AIContext.ReasoningTrace", func(t *testing.T) {
		log := domain.Log{
			Message:  "test",
			AIContext: &domain.AIContext{ReasoningTrace: "analyzed user@test.com patterns"},
		}
		svc.MaskLog(&log)
		if strings.Contains(log.AIContext.ReasoningTrace, "@") {
			t.Errorf("ReasoningTrace should be masked, got %q", log.AIContext.ReasoningTrace)
		}
	})

	t.Run("masks AgentBackLog results", func(t *testing.T) {
		log := domain.Log{
			Message: "test",
			AgentBackLog: []domain.AgentBackLogEntry{
				{AgentID: "a1", Result: "found user@test.com"},
			},
		}
		svc.MaskLog(&log)
		if strings.Contains(log.AgentBackLog[0].Result, "@") {
			t.Errorf("AgentBackLog result should be masked, got %q", log.AgentBackLog[0].Result)
		}
	})

	t.Run("preserves Details keys in preserveFields", func(t *testing.T) {
		svc2 := NewMaskingService([]MaskingRule{
			{Type: "PII_TYPE", Category: "EMAIL"},
		}, []string{"contact"})

		log := domain.Log{
			Message: "test",
			Details: map[string]string{"contact": "admin@test.com"},
		}
		svc2.MaskLog(&log)
		if log.Details["contact"] != "admin@test.com" {
			t.Error("preserved key should not be masked")
		}
	})
}

func TestMaskValue_Deep(t *testing.T) {
	svc := NewMaskingService([]MaskingRule{
		{Type: "PII_TYPE", Category: "EMAIL"},
	}, nil)

	t.Run("masks nested map values", func(t *testing.T) {
		data := map[string]interface{}{
			"level1": map[string]interface{}{
				"level2": map[string]interface{}{
					"email": "deep@nested.com",
				},
			},
		}
		result := svc.MaskValue(data, 0).(map[string]interface{})
		l1 := result["level1"].(map[string]interface{})
		l2 := l1["level2"].(map[string]interface{})
		if strings.Contains(l2["email"].(string), "@") {
			t.Errorf("nested email should be masked, got %v", l2["email"])
		}
	})

	t.Run("masks array elements", func(t *testing.T) {
		data := []interface{}{"normal", "user@test.com", "also normal"}
		result := svc.MaskValue(data, 0).([]interface{})
		if strings.Contains(result[1].(string), "@") {
			t.Errorf("array element should be masked, got %v", result[1])
		}
		if result[0] != "normal" {
			t.Error("non-PII should be untouched")
		}
	})

	t.Run("respects maxDepth", func(t *testing.T) {
		svc2 := NewMaskingService(nil, nil)
		svc2.SetMaxDepth(2)

		data := map[string]interface{}{
			"l1": map[string]interface{}{
				"l2": map[string]interface{}{
					"l3": "too deep",
				},
			},
		}
		result := svc2.MaskValue(data, 0).(map[string]interface{})
		l1 := result["l1"].(map[string]interface{})
		l2 := l1["l2"]
		if l2 != "[MAX_DEPTH_EXCEEDED]" {
			t.Errorf("expected MAX_DEPTH_EXCEEDED at depth 2, got %v", l2)
		}
	})

	t.Run("preserves non-string types", func(t *testing.T) {
		data := map[string]interface{}{
			"count": 42,
			"flag":  true,
			"nil":   nil,
		}
		result := svc.MaskValue(data, 0).(map[string]interface{})
		if result["count"] != 42 {
			t.Errorf("int should be preserved, got %v", result["count"])
		}
		if result["flag"] != true {
			t.Error("bool should be preserved")
		}
		if result["nil"] != nil {
			t.Error("nil should be preserved")
		}
	})
}

func TestJapanPIIPatterns(t *testing.T) {
	svc := NewMaskingService([]MaskingRule{
		{Type: "PII_TYPE", Category: "JAPAN_ACCOUNT"},
		{Type: "PII_TYPE", Category: "POSTAL_CODE"},
	}, nil)

	t.Run("masks Japan bank account", func(t *testing.T) {
		result := svc.maskString("口座: 0001-001-1234567")
		if strings.Contains(result, "0001-001-1234567") {
			t.Errorf("bank account should be masked, got %q", result)
		}
	})

	t.Run("masks postal code", func(t *testing.T) {
		result := svc.maskString("〒100-0001")
		if strings.Contains(result, "100-0001") {
			t.Errorf("postal code should be masked, got %q", result)
		}
	})

	t.Run("masks postal code without 〒", func(t *testing.T) {
		result := svc.maskString("住所: 150-0002")
		if strings.Contains(result, "150-0002") {
			t.Errorf("postal code without 〒 should be masked, got %q", result)
		}
	})
}
