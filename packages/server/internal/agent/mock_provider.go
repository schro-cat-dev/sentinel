package agent

import (
	"context"
	"fmt"

	"github.com/schro-cat-dev/sentinel-server/internal/domain"
)

// MockProvider はテスト・開発用のモックAIプロバイダ
type MockProvider struct {
	name       string
	shouldFail bool
	response   *InferenceResult
}

func NewMockProvider(name string) *MockProvider {
	return &MockProvider{
		name: name,
		response: &InferenceResult{
			Thought:    "Analyzed the security event pattern",
			Action:     "block_ip",
			Confidence: 0.85,
			Model:      "mock-model-v1",
			TokensUsed: 150,
		},
	}
}

func (m *MockProvider) SetShouldFail(fail bool) {
	m.shouldFail = fail
}

func (m *MockProvider) SetResponse(r *InferenceResult) {
	m.response = r
}

func (m *MockProvider) Execute(ctx context.Context, task domain.GeneratedTask, log domain.Log) (*InferenceResult, error) {
	select {
	case <-ctx.Done():
		return nil, fmt.Errorf("execution cancelled: %w", ctx.Err())
	default:
	}

	if m.shouldFail {
		return nil, fmt.Errorf("mock provider error: simulated failure")
	}

	return m.response, nil
}

func (m *MockProvider) Name() string {
	return m.name
}
