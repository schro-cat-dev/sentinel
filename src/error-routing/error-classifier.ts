import type { ClassificationInput, ClassifiedError } from "./types";

interface SeverityConfig {
    CRITICAL: readonly string[];
    WARNING: readonly string[];
}

const DEFAULT_SEVERITY: SeverityConfig = {
    CRITICAL: ["TransportConnectionRefused", "EngineInternalError"],
    WARNING: ["TransportTimeout", "HandlerTimeout", "HandlerException", "CallbackException", "Unknown"],
};

const KIND_PATTERNS: { pattern: RegExp; context?: RegExp; kind: string }[] = [
    { pattern: /timeout/i, context: /transport/i, kind: "TransportTimeout" },
    { pattern: /timeout/i, context: /task/i, kind: "HandlerTimeout" },
    { pattern: /connection refused/i, kind: "TransportConnectionRefused" },
    { pattern: /ECONNRESET/i, kind: "TransportConnectionReset" },
    { pattern: /^validation\(/i, kind: "ValidationFailure" },
    { pattern: /shutdown/i, kind: "ShutdownViolation" },
];

export class ErrorClassifier {
    private readonly severityConfig: SeverityConfig;

    constructor(severityConfig?: Partial<SeverityConfig>) {
        this.severityConfig = {
            CRITICAL: severityConfig?.CRITICAL ?? DEFAULT_SEVERITY.CRITICAL,
            WARNING: severityConfig?.WARNING ?? DEFAULT_SEVERITY.WARNING,
        };
    }

    classify(input: ClassificationInput): ClassifiedError {
        try {
            const message = this.safeMessage(input.error);
            const kind = this.deriveKind(message, input.context);
            const severity = this.classifySeverity(kind);
            const code = kind.replace(/([A-Z])/g, "_$1").toUpperCase().replace(/^_/, "");

            return {
                kind,
                detailKind: input.context,
                code,
                message,
                severity,
                meta: {
                    traceId: input.traceId,
                    layer: input.layer,
                    operation: input.operation,
                    context: { originalContext: input.context },
                },
            };
        } catch {
            return {
                kind: "ClassificationError",
                detailKind: "internal",
                code: "CLASSIFICATION_ERROR",
                message: "Error classification itself failed",
                severity: "WARNING",
                meta: { context: {} },
            };
        }
    }

    private safeMessage(error: unknown): string {
        try {
            if (typeof error === "object" && error !== null && "message" in error) {
                const msg = (error as { message: unknown }).message;
                return typeof msg === "string" ? msg : String(msg);
            }
            return String(error);
        } catch {
            return "unknown error";
        }
    }

    private deriveKind(message: string, context: string): string {
        if (context.startsWith("task.dispatch") && !message.toLowerCase().includes("timeout")) {
            return "HandlerException";
        }

        for (const { pattern, context: ctxPattern, kind } of KIND_PATTERNS) {
            if (pattern.test(message)) {
                if (ctxPattern && !ctxPattern.test(context)) continue;
                return kind;
            }
        }

        if (message.toLowerCase().includes("validation")) return "ValidationFailure";

        return "Unknown";
    }

    private classifySeverity(kind: string): "CRITICAL" | "WARNING" | "INFO" {
        if (this.severityConfig.CRITICAL.includes(kind)) return "CRITICAL";
        if (this.severityConfig.WARNING.includes(kind)) return "WARNING";
        if (kind === "ValidationFailure" || kind === "ShutdownViolation") return "INFO";
        return "WARNING";
    }
}
