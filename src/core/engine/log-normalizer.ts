import { randomUUID } from "node:crypto";
import { GlobalConfig } from "../../configs/global-config";
import { Log } from "../../types/log";
import { ILoggerNormalizer } from "./i-interfaces";

export class LogNormalizer implements ILoggerNormalizer {
    private readonly serviceId: string;

    constructor(gConfig: GlobalConfig) {
        this.serviceId = gConfig.serviceId;
    }

    normalize(raw: Partial<Log>): Log {
        if (!raw.message?.trim()) {
            throw new Error("Log message cannot be empty"); // TODO ValidationErrorがあれば使用
        }

        return {
            traceId: raw.traceId || randomUUID(),
            type: raw.type || "SYSTEM",
            level: raw.level || 3,
            timestamp: new Date().toISOString(),
            logicalClock: Date.now(),
            boundary: raw.boundary || "unknown",
            serviceId: this.serviceId,
            isCritical: raw.isCritical || false,
            message: raw.message,
            origin: raw.origin || "SYSTEM",
            triggerAgent: raw.triggerAgent || false,
            tags: raw.tags || [],
            ...raw,
        } as Log;
    }
}
