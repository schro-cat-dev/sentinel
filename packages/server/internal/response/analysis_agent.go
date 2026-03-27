package response

import (
	"context"
	"fmt"
	"time"

	"github.com/schro-cat-dev/sentinel-server/internal/domain"
)

// AnalysisAgent は検知結果をAI分析するエージェント
type AnalysisAgent interface {
	Analyze(ctx context.Context, det *domain.DetectionResult, log domain.Log, prompt string) (*AnalysisResult, error)
}

// AIAnalysisAgent はAIプロバイダを使った分析エージェント
type AIAnalysisAgent struct {
	providerName string
	analyzeFunc  func(ctx context.Context, prompt string, context map[string]interface{}) (*AnalysisResult, error)
}

// NewAIAnalysisAgent はAIAnalysisAgentを生成する
func NewAIAnalysisAgent(providerName string, fn func(ctx context.Context, prompt string, context map[string]interface{}) (*AnalysisResult, error)) *AIAnalysisAgent {
	return &AIAnalysisAgent{providerName: providerName, analyzeFunc: fn}
}

func (a *AIAnalysisAgent) Analyze(ctx context.Context, det *domain.DetectionResult, log domain.Log, prompt string) (*AnalysisResult, error) {
	if a.analyzeFunc == nil {
		return nil, fmt.Errorf("no analyze function configured")
	}

	analysisCtx := map[string]interface{}{
		"event_name": string(det.EventName),
		"priority":   string(det.Priority),
		"score":      det.Score,
		"message":    log.Message,
		"boundary":   log.Boundary,
		"level":      int(log.Level),
		"type":       string(log.Type),
	}

	return a.analyzeFunc(ctx, prompt, analysisCtx)
}

// MockAnalysisAgent はテスト/開発用のモック分析エージェント
type MockAnalysisAgent struct {
	shouldFail bool
	response   *AnalysisResult
}

func NewMockAnalysisAgent() *MockAnalysisAgent {
	return &MockAnalysisAgent{
		response: &AnalysisResult{
			Summary:     "Detected anomalous pattern consistent with brute-force attack",
			RiskLevel:   "high",
			Confidence:  0.92,
			Indicators:  []string{"rapid_login_attempts", "ip_reputation_low", "geo_anomaly"},
			Recommended: "Block source IP and notify security team",
			Model:       "mock-analyzer-v1",
			TokensUsed:  200,
			AnalyzedAt:  time.Now().UTC(),
		},
	}
}

func (m *MockAnalysisAgent) SetShouldFail(fail bool)         { m.shouldFail = fail }
func (m *MockAnalysisAgent) SetResponse(r *AnalysisResult)    { m.response = r }

func (m *MockAnalysisAgent) Analyze(ctx context.Context, det *domain.DetectionResult, log domain.Log, prompt string) (*AnalysisResult, error) {
	select {
	case <-ctx.Done():
		return nil, fmt.Errorf("analysis cancelled: %w", ctx.Err())
	default:
	}

	if m.shouldFail {
		return &AnalysisResult{
			Error:      "mock analysis failed",
			AnalyzedAt: time.Now().UTC(),
		}, fmt.Errorf("mock analysis failed")
	}

	result := *m.response
	result.AnalyzedAt = time.Now().UTC()
	return &result, nil
}
