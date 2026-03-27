package task

import (
	"sort"
	"time"

	"github.com/google/uuid"
	"github.com/schro-cat-dev/sentinel-server/internal/domain"
)

// TaskGenerator はルールベースのタスク自動生成エンジン
type TaskGenerator struct {
	ruleIndex map[string][]domain.TaskRule
}

func NewTaskGenerator(rules []domain.TaskRule) *TaskGenerator {
	idx := make(map[string][]domain.TaskRule)
	for _, r := range rules {
		idx[r.EventName] = append(idx[r.EventName], r)
	}
	return &TaskGenerator{ruleIndex: idx}
}

// Generate は検知結果とログからタスクを生成する
func (g *TaskGenerator) Generate(detection *domain.DetectionResult, log domain.Log) []domain.GeneratedTask {
	if detection == nil {
		return nil
	}

	rules, ok := g.ruleIndex[string(detection.EventName)]
	if !ok || len(rules) == 0 {
		return nil
	}

	severity := classifySeverity(detection, log)

	// フィルタ+ソート
	var matched []domain.TaskRule
	for _, r := range rules {
		if domain.SeverityGTE(severity, r.Severity) {
			matched = append(matched, r)
		}
	}
	sort.Slice(matched, func(i, j int) bool {
		return matched[i].Priority < matched[j].Priority
	})

	tasks := make([]domain.GeneratedTask, 0, len(matched))
	for _, r := range matched {
		tasks = append(tasks, domain.GeneratedTask{
			TaskID:         uuid.New().String(),
			RuleID:         r.RuleID,
			EventName:      string(detection.EventName),
			Severity:       severity,
			ActionType:     r.ActionType,
			ExecutionLevel: r.ExecutionLevel,
			Priority:       r.Priority,
			Description:    r.Description,
			ExecParams:     r.ExecParams,
			Guardrails:     r.Guardrails,
			SourceLog: domain.SourceLogInfo{
				TraceID:   log.TraceID,
				Message:   log.Message,
				Boundary:  log.Boundary,
				Level:     log.Level,
				Timestamp: log.Timestamp,
			},
			CreatedAt: time.Now().UTC(),
		})
	}
	return tasks
}

func (g *TaskGenerator) RuleCount() int {
	count := 0
	for _, rules := range g.ruleIndex {
		count += len(rules)
	}
	return count
}

func classifySeverity(det *domain.DetectionResult, log domain.Log) domain.TaskSeverity {
	if log.IsCritical {
		return domain.SeverityCritical
	}
	switch det.EventName {
	case domain.EventSecurityIntrusion:
		if log.Level >= domain.LogLevelCritical {
			return domain.SeverityCritical
		}
		return domain.SeverityHigh
	case domain.EventSystemCriticalFailure:
		if det.Priority == domain.PriorityHigh {
			return domain.SeverityCritical
		}
		return domain.SeverityHigh
	case domain.EventComplianceViolation:
		return domain.SeverityHigh
	case domain.EventAIActionRequired:
		return domain.SeverityMedium
	default:
		return fromLogLevel(log.Level)
	}
}

func fromLogLevel(level domain.LogLevel) domain.TaskSeverity {
	switch {
	case level >= 6:
		return domain.SeverityCritical
	case level >= 5:
		return domain.SeverityHigh
	case level >= 4:
		return domain.SeverityMedium
	case level >= 3:
		return domain.SeverityLow
	default:
		return domain.SeverityInfo
	}
}
