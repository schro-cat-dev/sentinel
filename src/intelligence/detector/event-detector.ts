import { Log } from "../../types/log";
import { DetectionResult, SystemEventName } from "../../types/event";

export class EventDetector {
    /**
     * ログからシステムイベントを検知する。
     * DetectionResult に <SystemEventName> を渡すことで、
     * SystemEventMap に定義されたいずれかのイベントであることを保証します。
     */
    public static detect(log: Log): DetectionResult<SystemEventName> | null {
        // 1. クリティカルフラグによる検知
        if (log.isCritical) {
            return {
                eventName: "SYSTEM_CRITICAL_FAILURE", // SystemEventMap にある名前を使用
                priority: "HIGH",
                payload: {
                    component: log.boundary,
                    errorDetails: log.message,
                },
            };
        }

        // 2. セキュリティログかつ高レベルの検知
        if (log.type === "SECURITY" && log.level >= 5) {
            return {
                eventName: "SECURITY_INTRUSION_DETECTED",
                priority: "HIGH",
                payload: {
                    ip: this.extractIp(log), // 補助関数でIPを抽出
                    severity: log.level,
                    rawLog: log,
                },
            };
        }

        // 3. コンプライアンス違反の兆候
        if (log.type === "COMPLIANCE" && log.message.includes("violation")) {
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

        return null;
    }

    /**
     * ログのタグからIPアドレスを安全に抽出する
     */
    private static extractIp(log: Log): string {
        return log.tags.find((t) => t.key === "ip")?.category || "0.0.0.0";
    }
}
