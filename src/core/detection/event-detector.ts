import { Log } from "../../types/log";
import { DetectionResult, SystemEventName } from "../../types/event";

/**
 * ログからシステムイベントを検知するルールベースの検出器
 */
export class EventDetector {
    /**
     * ログを評価し、該当するシステムイベントを返す。
     * 該当なしの場合はnull。
     */
    public detect(log: Log): DetectionResult<SystemEventName> | null {
        // AI_AGENTからのログは再帰検知を防ぐためスキップ
        if (log.origin === "AI_AGENT" && !log.isCritical) {
            return null;
        }

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
                    rawLog: log,
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

        // 4. SLA違反
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

        return null;
    }

    private static extractIp(log: Log): string {
        return log.tags.find((t) => t.key === "ip")?.category || "0.0.0.0";
    }
}
