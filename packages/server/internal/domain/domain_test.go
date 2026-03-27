package domain

import "testing"

func TestIsValidLogType(t *testing.T) {
	tests := []struct {
		name string
		typ  LogType
		want bool
	}{
		{"SYSTEM is valid", LogTypeSystem, true},
		{"SECURITY is valid", LogTypeSecurity, true},
		{"COMPLIANCE is valid", LogTypeCompliance, true},
		{"BUSINESS-AUDIT is valid", LogTypeBusinessAudit, true},
		{"INFRA is valid", LogTypeInfra, true},
		{"SLA is valid", LogTypeSLA, true},
		{"DEBUG is valid", LogTypeDebug, true},
		{"empty is invalid", LogType(""), false},
		{"arbitrary string is invalid", LogType("UNKNOWN"), false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := IsValidLogType(tt.typ); got != tt.want {
				t.Errorf("IsValidLogType(%q) = %v, want %v", tt.typ, got, tt.want)
			}
		})
	}
}

func TestIsValidLogLevel(t *testing.T) {
	tests := []struct {
		name  string
		level LogLevel
		want  bool
	}{
		{"level 1 valid", 1, true},
		{"level 6 valid", 6, true},
		{"level 3 valid", 3, true},
		{"level 0 invalid", 0, false},
		{"level 7 invalid", 7, false},
		{"level -1 invalid", -1, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := IsValidLogLevel(tt.level); got != tt.want {
				t.Errorf("IsValidLogLevel(%d) = %v, want %v", tt.level, got, tt.want)
			}
		})
	}
}

func TestIsValidOrigin(t *testing.T) {
	tests := []struct {
		name   string
		origin Origin
		want   bool
	}{
		{"SYSTEM valid", OriginSystem, true},
		{"AI_AGENT valid", OriginAIAgent, true},
		{"empty invalid", Origin(""), false},
		{"UNKNOWN invalid", Origin("UNKNOWN"), false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := IsValidOrigin(tt.origin); got != tt.want {
				t.Errorf("IsValidOrigin(%q) = %v, want %v", tt.origin, got, tt.want)
			}
		})
	}
}

func TestSeverityGTE(t *testing.T) {
	tests := []struct {
		name      string
		actual    TaskSeverity
		threshold TaskSeverity
		want      bool
	}{
		{"CRITICAL >= CRITICAL", SeverityCritical, SeverityCritical, true},
		{"CRITICAL >= HIGH", SeverityCritical, SeverityHigh, true},
		{"HIGH >= MEDIUM", SeverityHigh, SeverityMedium, true},
		{"MEDIUM >= LOW", SeverityMedium, SeverityLow, true},
		{"LOW >= INFO", SeverityLow, SeverityInfo, true},
		{"INFO >= INFO", SeverityInfo, SeverityInfo, true},
		{"HIGH < CRITICAL", SeverityHigh, SeverityCritical, false},
		{"LOW < HIGH", SeverityLow, SeverityHigh, false},
		{"INFO < CRITICAL", SeverityInfo, SeverityCritical, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := SeverityGTE(tt.actual, tt.threshold); got != tt.want {
				t.Errorf("SeverityGTE(%q, %q) = %v, want %v", tt.actual, tt.threshold, got, tt.want)
			}
		})
	}
}
