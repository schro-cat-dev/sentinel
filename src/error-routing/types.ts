/**
 * エラールーティング型定義
 */

export interface ClassificationInput {
    error: Error;
    context: string;
    traceId?: string;
    layer?: string;
    operation?: string;
}

export interface ClassifiedError {
    kind: string;
    detailKind: string;
    code: string;
    message: string;
    severity: "CRITICAL" | "WARNING" | "INFO";
    meta: {
        traceId?: string;
        layer?: string;
        operation?: string;
        context: Record<string, string | number | boolean | null>;
    };
}

export interface RoutingRule {
    match: {
        severity: "CRITICAL" | "WARNING" | "INFO";
        kindPattern?: RegExp;
    };
    decisions: RoutingDecision[];
}

export interface RoutingDecision {
    destination: "task" | "ai_agent" | "notification" | "audit_sink" | "dead_letter" | "log";
    action: "escalate" | "auto_remediate" | "block" | "record" | "retry";
    priority: number;
    metadata?: Record<string, string>;
}

export interface AuditSink {
    send(payload: ClassifiedError): Promise<void>;
}

export interface DeadLetterQueue {
    enqueue(payload: ClassifiedError, metadata: Record<string, string>): Promise<void>;
}

export interface ErrorRoutingConfig {
    enabled: boolean;
    severityConfig?: {
        CRITICAL: readonly string[];
        WARNING: readonly string[];
    };
    rules?: RoutingRule[];
    sinks?: {
        audit?: AuditSink;
        deadLetter?: DeadLetterQueue;
    };
}
