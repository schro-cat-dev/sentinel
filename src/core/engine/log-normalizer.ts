import { randomUUID } from "node:crypto";
import { Log, LogLevel, LogType } from "../../types/log";
import { ILogNormalizer } from "./i-interfaces";

const VALID_LOG_TYPES = new Set<LogType>([
    "BUSINESS-AUDIT", "SECURITY", "COMPLIANCE", "INFRA", "SYSTEM", "SLA", "DEBUG",
]);

const VALID_LOG_LEVELS = new Set<LogLevel>([1, 2, 3, 4, 5, 6]);

/**
 * ログ正規化 — Partial<Log> にデフォルトを注入して完全な Log を返す。
 * 入力検証は validateLogInput() (SDK境界) の責務。ここでは防御的フォールバックのみ行う。
 */
export class LogNormalizer implements ILogNormalizer {
    constructor(
        private readonly serviceId: string,
        private readonly projectName?: string,
    ) {}

    normalize(raw: Partial<Log>): Log {
        const message = typeof raw.message === "string" ? raw.message.trim() : "";

        return {
            traceId: raw.traceId || randomUUID(),
            type: raw.type && VALID_LOG_TYPES.has(raw.type) ? raw.type : "SYSTEM",
            level: raw.level && VALID_LOG_LEVELS.has(raw.level) ? raw.level : 3,
            timestamp: raw.timestamp || new Date().toISOString(),
            logicalClock: raw.logicalClock ?? Date.now(),
            boundary: raw.boundary || "unknown",
            serviceId: this.serviceId,
            projectName: this.projectName,
            isCritical: raw.isCritical ?? false,
            message,
            origin: raw.origin === "AI_AGENT" ? "AI_AGENT" : "SYSTEM",
            triggerAgent: raw.triggerAgent ?? false,
            tags: raw.tags ?? [],
            spanId: raw.spanId,
            parentSpanId: raw.parentSpanId,
            actorId: raw.actorId,
            aiContext: raw.aiContext,
            input: raw.input,
            traceInfo: raw.traceInfo,
            agentBackLog: raw.agentBackLog,
            details: raw.details,
            resourceIds: raw.resourceIds,
        };
    }
}
