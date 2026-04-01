import type { ClassifiedError, RoutingDecision, RoutingRule } from "./types";

const DEFAULT_RULES: RoutingRule[] = [
    {
        match: { severity: "CRITICAL" },
        decisions: [
            { destination: "task", action: "escalate", priority: 1 },
            { destination: "notification", action: "escalate", priority: 1 },
            { destination: "audit_sink", action: "record", priority: 1 },
        ],
    },
    {
        match: { severity: "WARNING", kindPattern: /^Transport/ },
        decisions: [
            { destination: "dead_letter", action: "retry", priority: 3 },
            { destination: "audit_sink", action: "record", priority: 3 },
        ],
    },
    {
        match: { severity: "WARNING", kindPattern: /^Handler/ },
        decisions: [
            { destination: "ai_agent", action: "auto_remediate", priority: 2 },
            { destination: "audit_sink", action: "record", priority: 3 },
        ],
    },
    {
        match: { severity: "WARNING" },
        decisions: [
            { destination: "audit_sink", action: "record", priority: 3 },
        ],
    },
    {
        match: { severity: "INFO" },
        decisions: [
            { destination: "log", action: "record", priority: 5 },
        ],
    },
];

const DEFAULT_FALLBACK: RoutingDecision[] = [
    { destination: "log", action: "record", priority: 5 },
];

export class RoutingEngine {
    private readonly rules: RoutingRule[];

    constructor(customRules?: RoutingRule[]) {
        this.rules = customRules ?? DEFAULT_RULES;
    }

    evaluate(error: ClassifiedError): RoutingDecision[] {
        for (const rule of this.rules) {
            if (this.matches(error, rule)) {
                return rule.decisions;
            }
        }
        return DEFAULT_FALLBACK;
    }

    private matches(error: ClassifiedError, rule: RoutingRule): boolean {
        if (rule.match.severity !== error.severity) return false;
        if (rule.match.kindPattern && !rule.match.kindPattern.test(error.kind)) return false;
        return true;
    }
}
