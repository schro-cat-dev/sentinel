import type { WhitelistDefinition } from "../whitelist-types";

const VALID_EVENT_NAMES: readonly string[] = [
    "SECURITY_INTRUSION_DETECTED",
    "COMPLIANCE_VIOLATION",
    "SYSTEM_CRITICAL_FAILURE",
    "AI_ACTION_REQUIRED",
];

const VALID_DETECTION_PRIORITIES: readonly string[] = ["HIGH", "MEDIUM", "LOW"];

export const SECURITY_WHITELIST: WhitelistDefinition = {
    domain: "security",
    fields: {
        eventName: VALID_EVENT_NAMES,
        detectionPriority: VALID_DETECTION_PRIORITIES,
    },
};
