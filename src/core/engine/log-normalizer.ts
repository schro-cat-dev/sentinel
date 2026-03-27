import { randomUUID } from "node:crypto";
import { Log, LogLevel, LogType } from "../../types/log";
import { ILogNormalizer } from "./i-interfaces";

const VALID_LOG_TYPES: readonly LogType[] = [
    "BUSINESS-AUDIT", "SECURITY", "COMPLIANCE", "INFRA", "SYSTEM", "SLA", "DEBUG",
];

const VALID_LOG_LEVELS: readonly LogLevel[] = [1, 2, 3, 4, 5, 6];

export class LogNormalizer implements ILogNormalizer {
    constructor(private readonly serviceId: string) {}

    normalize(raw: Partial<Log>): Log {
        this.validate(raw);

        return {
            traceId: raw.traceId || randomUUID(),
            type: raw.type && VALID_LOG_TYPES.includes(raw.type) ? raw.type : "SYSTEM",
            level: raw.level && VALID_LOG_LEVELS.includes(raw.level) ? raw.level : 3,
            timestamp: raw.timestamp || new Date().toISOString(),
            logicalClock: raw.logicalClock ?? Date.now(),
            boundary: raw.boundary || "unknown",
            serviceId: this.serviceId,
            isCritical: raw.isCritical ?? false,
            message: raw.message!.trim(),
            origin: raw.origin === "AI_AGENT" ? "AI_AGENT" : "SYSTEM",
            triggerAgent: raw.triggerAgent ?? false,
            tags: raw.tags ?? [],
            spanId: raw.spanId,
            parentSpanId: raw.parentSpanId,
            actorId: raw.actorId,
            aiContext: raw.aiContext,
            input: raw.input,
            details: raw.details,
            resourceIds: raw.resourceIds,
            previousHash: raw.previousHash,
            hash: raw.hash,
            signature: raw.signature,
        };
    }

    private validate(raw: Partial<Log>): void {
        if (!raw.message || !raw.message.trim()) {
            throw new Error("Log message is required and cannot be empty");
        }
        if (raw.message.length > 65536) {
            throw new Error("Log message exceeds maximum length of 65536 characters");
        }
    }
}
