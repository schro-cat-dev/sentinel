import { Log } from "../../types/log";
import { TaskSeverity } from "../../types/task";
import { DetectionResult, SystemEventName } from "../../types/event";

/**
 * ログとイベント検知結果から重大度を分類する
 */
export class SeverityClassifier {
    /**
     * 検知結果とログコンテキストから最終的な重大度を決定
     */
    public classify(
        detection: DetectionResult<SystemEventName>,
        log: Log,
    ): TaskSeverity {
        // isCritical フラグは常にCRITICAL
        if (log.isCritical) {
            return "CRITICAL";
        }

        // イベント種別ベースの分類
        switch (detection.eventName) {
            case "SECURITY_INTRUSION_DETECTED":
                return log.level >= 6 ? "CRITICAL" : "HIGH";

            case "SYSTEM_CRITICAL_FAILURE":
                return detection.priority === "HIGH" ? "CRITICAL" : "HIGH";

            case "COMPLIANCE_VIOLATION":
                return "HIGH";

            case "AI_ACTION_REQUIRED":
                return "MEDIUM";

            default:
                return SeverityClassifier.fromLogLevel(log.level);
        }
    }

    /**
     * ログレベルからの基本的な重大度マッピング
     */
    private static fromLogLevel(level: number): TaskSeverity {
        if (level >= 6) return "CRITICAL";
        if (level >= 5) return "HIGH";
        if (level >= 4) return "MEDIUM";
        if (level >= 3) return "LOW";
        return "INFO";
    }
}
