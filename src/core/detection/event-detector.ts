import { Log } from "../../types/log";
import { DetectionResult, DetectionRule, SystemEventName } from "../../types/event";

/**
 * ログからシステムイベントを検知するルールベースの検出器。
 * 組込みルール（最優先）→ カスタムルール（設定順）の順で評価。
 */
export class EventDetector {
    private readonly customRules: DetectionRule[];

    constructor(customRules?: DetectionRule[]) {
        this.customRules = customRules ?? [];
        this.validateCustomRules();
    }

    /**
     * カスタムルールのランタイム整合性を検証する。
     * TypeScriptの型チェックでは防げないケース（JSON parse由来のstring等）を検出。
     */
    private validateCustomRules(): void {
        for (const rule of this.customRules) {
            const mp = rule.conditions.messagePattern;
            if (mp !== undefined) {
                if (!(mp instanceof RegExp)) {
                    throw new Error(
                        `detectionRules[${rule.ruleId}].conditions.messagePattern must be a RegExp instance, ` +
                        `got ${typeof mp}. ` +
                        `If loading from JSON/YAML, convert the string to RegExp: new RegExp("pattern", "flags")`,
                    );
                }
                if (mp.global || mp.sticky) {
                    throw new Error(
                        `detectionRules[${rule.ruleId}].conditions.messagePattern must not have global (g) or sticky (y) flag. ` +
                        `These flags make .test() stateful and cause non-deterministic detection.`,
                    );
                }
            }
        }
    }

    /**
     * ログを評価し、該当するシステムイベントを返す。
     * 該当なしの場合はnull。
     */
    public detect(log: Log): DetectionResult<SystemEventName> | null {
        // AI_AGENTからのログは再帰検知を防ぐためスキップ
        if (log.origin === "AI_AGENT" && !log.isCritical) {
            return null;
        }

        // === 組込みルール（最優先） ===

        // 1. クリティカルフラグ（最優先）
        if (log.isCritical) {
            return {
                eventName: "SYSTEM_CRITICAL_FAILURE",
                priority: "HIGH",
                payload: {
                    component: log.boundary,
                    errorDetails: log.message,
                },
            };
        }

        // 2. セキュリティ侵入検知（level >= 5）
        if (log.type === "SECURITY" && log.level >= 5) {
            return {
                eventName: "SECURITY_INTRUSION_DETECTED",
                priority: "HIGH",
                payload: {
                    ip: EventDetector.extractIp(log),
                    severity: log.level,
                    rawLog: {
                        traceId: log.traceId,
                        type: log.type,
                        level: log.level,
                        timestamp: log.timestamp,
                        boundary: log.boundary,
                        serviceId: log.serviceId,
                        message: log.message,
                        isCritical: log.isCritical,
                    },
                },
            };
        }

        // 3. コンプライアンス違反
        if (log.type === "COMPLIANCE" && log.message.toLowerCase().includes("violation")) {
            return {
                eventName: "COMPLIANCE_VIOLATION",
                priority: "HIGH",
                payload: {
                    ruleId: "AUTO-DETECT-001",
                    documentId: log.resourceIds?.[0] || "unknown",
                    userId: log.actorId || "system",
                },
            };
        }

        // 4. AIエージェントアクション要求
        if (log.triggerAgent && log.level >= 4) {
            return {
                eventName: "AI_ACTION_REQUIRED",
                priority: log.level >= 5 ? "HIGH" : "MEDIUM",
                payload: {
                    reason: log.message,
                    suggestedTask: log.type === "SECURITY" ? "AI_ANALYZE" : "SYSTEM_NOTIFICATION",
                    context: log.aiContext ?? null,
                },
            };
        }

        // 5. SLA違反
        if (log.type === "SLA" && log.level >= 4) {
            return {
                eventName: "SYSTEM_CRITICAL_FAILURE",
                priority: "MEDIUM",
                payload: {
                    component: log.boundary,
                    errorDetails: `SLA violation: ${log.message}`,
                },
            };
        }

        // === カスタムルール（設定順、最初にマッチしたものが勝つ） ===
        for (const rule of this.customRules) {
            if (this.matchesCustomRule(log, rule)) {
                return this.buildCustomResult(log, rule);
            }
        }

        return null;
    }

    /** REDOS-004: messagePattern実行時の入力長上限 */
    private static readonly MAX_REGEX_INPUT_LENGTH = 65536;

    /**
     * カスタムルールの条件を全てAND評価する
     */
    private matchesCustomRule(log: Log, rule: DetectionRule): boolean {
        const { conditions } = rule;

        if (conditions.logTypes && !conditions.logTypes.includes(log.type)) {
            return false;
        }

        if (conditions.minLevel !== undefined && log.level < conditions.minLevel) {
            return false;
        }

        if (conditions.maxLevel !== undefined && log.level > conditions.maxLevel) {
            return false;
        }

        // REDOS-004: 入力長ガード — 巨大メッセージへのregex実行を回避
        if (conditions.messagePattern) {
            if (log.message.length > EventDetector.MAX_REGEX_INPUT_LENGTH) {
                return false;
            }
            if (!conditions.messagePattern.test(log.message)) {
                return false;
            }
        }

        if (conditions.tagMatch) {
            const { key, value } = conditions.tagMatch;
            const found = log.tags.some(
                (t) => t.key === key && (value === undefined || t.category === value),
            );
            if (!found) return false;
        }

        if (conditions.origin !== undefined && log.origin !== conditions.origin) {
            return false;
        }

        if (conditions.isCritical !== undefined && log.isCritical !== conditions.isCritical) {
            return false;
        }

        return true;
    }

    /**
     * カスタムルールマッチ時のDetectionResult生成
     */
    private buildCustomResult(log: Log, rule: DetectionRule): DetectionResult<SystemEventName> {
        // eventName に応じた型安全なpayloadを構築
        switch (rule.eventName) {
            case "SECURITY_INTRUSION_DETECTED":
                return {
                    eventName: rule.eventName,
                    priority: rule.priority,
                    payload: {
                        ip: EventDetector.extractIp(log),
                        severity: log.level,
                        rawLog: {
                            traceId: log.traceId,
                            type: log.type,
                            level: log.level,
                            timestamp: log.timestamp,
                            boundary: log.boundary,
                            serviceId: log.serviceId,
                            message: log.message,
                            isCritical: log.isCritical,
                        },
                    },
                };
            case "COMPLIANCE_VIOLATION":
                return {
                    eventName: rule.eventName,
                    priority: rule.priority,
                    payload: {
                        ruleId: rule.ruleId,
                        documentId: log.resourceIds?.[0] || "unknown",
                        userId: log.actorId || "system",
                    },
                };
            case "SYSTEM_CRITICAL_FAILURE":
                return {
                    eventName: rule.eventName,
                    priority: rule.priority,
                    payload: {
                        component: log.boundary,
                        errorDetails: log.message,
                    },
                };
            case "AI_ACTION_REQUIRED":
                return {
                    eventName: rule.eventName,
                    priority: rule.priority,
                    payload: {
                        reason: log.message,
                        suggestedTask: "SYSTEM_NOTIFICATION",
                        context: log.aiContext ?? null,
                    },
                };
            /* v8 ignore start -- exhaustive check: unreachable at runtime, compile-time guard */
            default: {
                const _exhaustive: never = rule.eventName;
                throw new Error(`Unknown eventName: ${_exhaustive}`);
            }
            /* v8 ignore stop */
        }
    }

    private static extractIp(log: Log): string {
        return log.tags.find((t) => t.key === "ip")?.category || "0.0.0.0";
    }
}
