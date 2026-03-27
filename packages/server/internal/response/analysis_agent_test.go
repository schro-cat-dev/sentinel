package response

import (
	"context"
	"testing"

	"github.com/schro-cat-dev/sentinel-server/internal/domain"
	"github.com/schro-cat-dev/sentinel-server/testutil"
)

func TestMockAnalysisAgent_Success(t *testing.T) {
	agent := NewMockAnalysisAgent()
	det := &domain.DetectionResult{
		EventName: domain.EventSecurityIntrusion,
		Priority:  domain.PriorityHigh,
		Payload:   domain.SecurityIntrusionPayload{IP: "10.0.0.1", Severity: 5},
	}
	log := testutil.NewSecurityLog()

	result, err := agent.Analyze(context.Background(), det, log, "Analyze this threat")
	if err != nil {
		t.Fatalf("error: %v", err)
	}
	if result.Summary == "" {
		t.Error("expected summary")
	}
	if result.RiskLevel != "high" {
		t.Errorf("expected high, got %s", result.RiskLevel)
	}
	if result.Confidence < 0.9 {
		t.Errorf("expected high confidence, got %f", result.Confidence)
	}
	if len(result.Indicators) == 0 {
		t.Error("expected indicators")
	}
	if result.Recommended == "" {
		t.Error("expected recommendation")
	}
	if result.Model == "" {
		t.Error("expected model name")
	}
}

func TestMockAnalysisAgent_Failure(t *testing.T) {
	agent := NewMockAnalysisAgent()
	agent.SetShouldFail(true)

	det := &domain.DetectionResult{
		EventName: domain.EventSecurityIntrusion,
		Payload:   domain.SecurityIntrusionPayload{},
	}

	result, err := agent.Analyze(context.Background(), det, testutil.NewSecurityLog(), "prompt")
	if err == nil {
		t.Error("expected error")
	}
	if result.Error == "" {
		t.Error("expected error in result")
	}
}

func TestMockAnalysisAgent_CancelledContext(t *testing.T) {
	agent := NewMockAnalysisAgent()
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	det := &domain.DetectionResult{
		EventName: domain.EventSecurityIntrusion,
		Payload:   domain.SecurityIntrusionPayload{},
	}

	_, err := agent.Analyze(ctx, det, testutil.NewSecurityLog(), "prompt")
	if err == nil {
		t.Error("expected error for cancelled context")
	}
}

func TestMockAnalysisAgent_CustomResponse(t *testing.T) {
	agent := NewMockAnalysisAgent()
	agent.SetResponse(&AnalysisResult{
		Summary:   "Custom analysis",
		RiskLevel: "critical",
		Confidence: 0.99,
	})

	det := &domain.DetectionResult{
		EventName: domain.EventSecurityIntrusion,
		Payload:   domain.SecurityIntrusionPayload{},
	}

	result, _ := agent.Analyze(context.Background(), det, testutil.NewSecurityLog(), "prompt")
	if result.Summary != "Custom analysis" {
		t.Errorf("expected custom summary, got %s", result.Summary)
	}
	if result.RiskLevel != "critical" {
		t.Errorf("expected critical, got %s", result.RiskLevel)
	}
}

func TestAIAnalysisAgent_NilFunc(t *testing.T) {
	agent := NewAIAnalysisAgent("test", nil)
	det := &domain.DetectionResult{
		EventName: domain.EventSecurityIntrusion,
		Payload:   domain.SecurityIntrusionPayload{},
	}
	_, err := agent.Analyze(context.Background(), det, testutil.NewSecurityLog(), "prompt")
	if err == nil {
		t.Error("expected error for nil function")
	}
}

func TestAIAnalysisAgent_WithFunc(t *testing.T) {
	agent := NewAIAnalysisAgent("test-provider", func(ctx context.Context, prompt string, analysisCtx map[string]interface{}) (*AnalysisResult, error) {
		return &AnalysisResult{
			Summary:    "Analyzed: " + prompt,
			RiskLevel:  "medium",
			Confidence: 0.75,
		}, nil
	})

	det := &domain.DetectionResult{
		EventName: domain.EventSecurityIntrusion,
		Priority:  domain.PriorityHigh,
		Payload:   domain.SecurityIntrusionPayload{IP: "1.2.3.4"},
		Score:     0.9,
	}

	result, err := agent.Analyze(context.Background(), det, testutil.NewSecurityLog(), "Check this")
	if err != nil {
		t.Fatalf("error: %v", err)
	}
	if result.Summary != "Analyzed: Check this" {
		t.Errorf("unexpected summary: %s", result.Summary)
	}
}
