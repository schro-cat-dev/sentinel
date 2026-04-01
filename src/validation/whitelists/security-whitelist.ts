import type { WhitelistDefinition } from "../whitelist-types";

const VALID_EVENT_NAMES: readonly string[] = [
    "SECURITY_INTRUSION_DETECTED",
    "COMPLIANCE_VIOLATION",
    "SYSTEM_CRITICAL_FAILURE",
    "AI_ACTION_REQUIRED",
];

const VALID_DETECTION_PRIORITIES: readonly string[] = ["HIGH", "MEDIUM", "LOW"];

const VALID_LOG_TYPES: readonly string[] = [
    "BUSINESS-AUDIT", "SECURITY", "COMPLIANCE", "INFRA", "SYSTEM", "SLA", "DEBUG",
];

const VALID_ORIGINS: readonly string[] = ["SYSTEM", "AI_AGENT"];

const VALID_ERROR_ROUTING_SEVERITIES: readonly string[] = ["CRITICAL", "WARNING", "INFO"];

const VALID_ERROR_ROUTING_DESTINATIONS: readonly string[] = [
    "task", "ai_agent", "notification", "audit_sink", "dead_letter", "log",
];

const VALID_ERROR_ROUTING_ACTIONS: readonly string[] = [
    "escalate", "auto_remediate", "block", "record", "retry",
];

export const SECURITY_WHITELIST: WhitelistDefinition = {
    domain: "security",
    fields: {
        eventName: VALID_EVENT_NAMES,
        detectionPriority: VALID_DETECTION_PRIORITIES,
        logType: VALID_LOG_TYPES,
        origin: VALID_ORIGINS,
        errorRoutingSeverity: VALID_ERROR_ROUTING_SEVERITIES,
        errorRoutingDestination: VALID_ERROR_ROUTING_DESTINATIONS,
        errorRoutingAction: VALID_ERROR_ROUTING_ACTIONS,
    },
};
