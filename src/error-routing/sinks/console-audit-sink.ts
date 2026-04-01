import type { AuditSink, ClassifiedError } from "../types";
import { maskPiiContext } from "../../shared/utils/error-utils";

/**
 * デフォルトのAuditSink実装。
 * serializeForAudit相当の構造化JSONをconsole.errorに出力する。
 * PII除去済み。
 */
export class ConsoleAuditSink implements AuditSink {
    async send(payload: ClassifiedError): Promise<void> {
        const safeContext = maskPiiContext(
            payload.meta.context as Record<string, string | number | boolean | null>,
        );

        const auditData = {
            timestamp: new Date().toISOString(),
            traceId: payload.meta.traceId ?? "unknown",
            kind: payload.kind,
            code: payload.code,
            severity: payload.severity,
            message: payload.message,
            layer: payload.meta.layer ?? "Unknown",
            context: safeContext,
        };

        console.error(JSON.stringify(auditData, undefined, 2));
    }
}
