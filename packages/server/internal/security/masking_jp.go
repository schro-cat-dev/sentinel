package security

import "regexp"

// Japan-specific PII patterns
func init() {
	RegisterPIIPattern("JAPAN_ACCOUNT", regexp.MustCompile(`\b\d{4}[\-]\d{3}[\-]\d{7}\b`))
	RegisterPIIPattern("POSTAL_CODE", regexp.MustCompile(`〒?\d{3}[\-]\d{4}`))
	RegisterPIIPattern("DRIVER_LICENSE", regexp.MustCompile(`\b\d{2}\d{2}\d{6}\d{2}\b`)) // 都道府県(2)+年(2)+連番(6)+チェック(2)
	RegisterPIIPattern("HEALTH_INSURANCE", regexp.MustCompile(`\b\d{2}\d{6}\b`))          // 保険者番号(8桁)
}
