package detection

import (
	"strings"

	"github.com/schro-cat-dev/sentinel-server/internal/domain"
)

// CriticalRule は isCritical フラグが立ったログを検知する
type CriticalRule struct{}

func (r *CriticalRule) Match(log domain.Log) *domain.DetectionResult {
	if !log.IsCritical {
		return nil
	}
	return &domain.DetectionResult{
		EventName: domain.EventSystemCriticalFailure,
		Priority:  domain.PriorityHigh,
		Payload: domain.SystemCriticalPayload{
			Component:    log.Boundary,
			ErrorDetails: log.Message,
		},
	}
}

// SecurityIntrusionRule はSECURITYタイプかつlevel >= 5のログを検知する
type SecurityIntrusionRule struct{}

func (r *SecurityIntrusionRule) Match(log domain.Log) *domain.DetectionResult {
	if log.Type != domain.LogTypeSecurity || log.Level < domain.LogLevelError {
		return nil
	}
	return &domain.DetectionResult{
		EventName: domain.EventSecurityIntrusion,
		Priority:  domain.PriorityHigh,
		Payload: domain.SecurityIntrusionPayload{
			IP:       log.IP("0.0.0.0"),
			Severity: int(log.Level),
		},
	}
}

// ComplianceViolationRule はCOMPLIANCEタイプで"violation"を含むログを検知する
type ComplianceViolationRule struct{}

func (r *ComplianceViolationRule) Match(log domain.Log) *domain.DetectionResult {
	if log.Type != domain.LogTypeCompliance {
		return nil
	}
	if !strings.Contains(strings.ToLower(log.Message), "violation") {
		return nil
	}
	return &domain.DetectionResult{
		EventName: domain.EventComplianceViolation,
		Priority:  domain.PriorityHigh,
		Payload: domain.ComplianceViolationPayload{
			RuleID:     "AUTO-DETECT-001",
			DocumentID: log.FirstResourceID("unknown"),
			UserID:     log.ActorOrDefault("system"),
		},
	}
}

// SLAViolationRule はSLAタイプかつlevel >= 4のログを検知する
type SLAViolationRule struct{}

func (r *SLAViolationRule) Match(log domain.Log) *domain.DetectionResult {
	if log.Type != domain.LogTypeSLA || log.Level < domain.LogLevelWarn {
		return nil
	}
	return &domain.DetectionResult{
		EventName: domain.EventSystemCriticalFailure,
		Priority:  domain.PriorityMedium,
		Payload: domain.SystemCriticalPayload{
			Component:    log.Boundary,
			ErrorDetails: "SLA violation: " + log.Message,
		},
	}
}
