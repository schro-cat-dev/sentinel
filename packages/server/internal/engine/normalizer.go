package engine

import (
	"errors"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/schro-cat-dev/sentinel-server/internal/domain"
	"github.com/schro-cat-dev/sentinel-server/internal/security"
)

// LogNormalizer はPartial Logを完全なLogに正規化する
type LogNormalizer struct {
	serviceID string
}

func NewLogNormalizer(serviceID string) *LogNormalizer {
	return &LogNormalizer{serviceID: serviceID}
}

func (n *LogNormalizer) Normalize(raw domain.Log) (domain.Log, error) {
	// Message validation (必須、長さ、UTF-8、null bytes)
	msg := strings.TrimSpace(raw.Message)
	if msg == "" {
		return domain.Log{}, errors.New("log message is required and cannot be empty")
	}
	if err := security.ValidateString("message", msg, security.MaxFieldLength); err != nil {
		return domain.Log{}, err
	}
	msg = security.SanitizeString(msg)

	log := raw
	log.Message = msg
	log.ServiceID = n.serviceID

	if log.TraceID == "" {
		log.TraceID = uuid.New().String()
	}
	if !domain.IsValidLogType(log.Type) {
		log.Type = domain.LogTypeSystem
	}
	if !domain.IsValidLogLevel(log.Level) {
		log.Level = domain.LogLevelInfo
	}
	if !domain.IsValidOrigin(log.Origin) {
		log.Origin = domain.OriginSystem
	}
	if log.Timestamp.IsZero() {
		log.Timestamp = time.Now().UTC()
	}
	if log.LogicalClock == 0 {
		log.LogicalClock = time.Now().UnixMilli()
	}
	if log.Boundary == "" {
		log.Boundary = "unknown"
	}
	if log.Tags == nil {
		log.Tags = []domain.LogTag{}
	}

	// Tags数制限
	if len(log.Tags) > security.MaxTagCount {
		log.Tags = log.Tags[:security.MaxTagCount]
	}
	// ResourceIDs数制限
	if len(log.ResourceIDs) > security.MaxResourceIDs {
		log.ResourceIDs = log.ResourceIDs[:security.MaxResourceIDs]
	}
	// Details数制限 + 値の長さ検証
	if log.Details != nil {
		if len(log.Details) > security.MaxDetailsCount {
			trimmed := make(map[string]string, security.MaxDetailsCount)
			count := 0
			for k, v := range log.Details {
				if count >= security.MaxDetailsCount {
					break
				}
				trimmed[k] = v
				count++
			}
			log.Details = trimmed
		}
		for k, v := range log.Details {
			if err := security.ValidateString("details.key", k, security.MaxTagKeyLength); err != nil {
				return domain.Log{}, err
			}
			if len(v) > security.MaxFieldLength {
				log.Details[k] = v[:security.MaxFieldLength]
			}
			log.Details[k] = security.SanitizeString(log.Details[k])
		}
	}

	// Input sanitize
	if log.Input != "" {
		log.Input = security.SanitizeString(log.Input)
	}

	return log, nil
}
