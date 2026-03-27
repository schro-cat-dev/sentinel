/**
 * SDK入力バリデータ — zodなし、zero-dep
 *
 * SDK公開API境界（ingest()）でランタイム検証を行う。
 * TypeScript型はコンパイル時のみ。このモジュールはランタイムで不正入力を弾く。
 */

import type { Log, LogType, LogLevel } from "../types/log";

const VALID_LOG_TYPES: readonly string[] = [
    "BUSINESS-AUDIT", "SECURITY", "COMPLIANCE", "INFRA", "SYSTEM", "SLA", "DEBUG",
];
const VALID_ORIGINS: readonly string[] = ["SYSTEM", "AI_AGENT"];
const MAX_MESSAGE_LENGTH = 65536;
const MAX_TAG_COUNT = 100;
const MAX_TAG_KEY_LENGTH = 128;
const MAX_TAG_VALUE_LENGTH = 1024;
const MAX_RESOURCE_IDS = 100;

export class ValidationError extends Error {
    public readonly field: string;
    constructor(field: string, message: string) {
        super(`validation(${field}): ${message}`);
        this.name = "ValidationError";
        this.field = field;
    }
}

/**
 * ログ入力を検証する。不正な場合はValidationErrorをthrowする。
 */
export function validateLogInput(input: Partial<Log>): void {
    // message: 必須、非空、最大長
    if (input.message !== undefined && input.message !== null) {
        if (typeof input.message !== "string") {
            throw new ValidationError("message", "must be a string");
        }
        if (input.message.trim().length === 0) {
            throw new ValidationError("message", "cannot be empty");
        }
        if (input.message.length > MAX_MESSAGE_LENGTH) {
            throw new ValidationError("message", `exceeds max length ${MAX_MESSAGE_LENGTH}`);
        }
        if (input.message.includes("\x00")) {
            throw new ValidationError("message", "contains null bytes");
        }
    }

    // type
    if (input.type !== undefined && !VALID_LOG_TYPES.includes(input.type)) {
        throw new ValidationError("type", `invalid log type: ${input.type}`);
    }

    // level
    if (input.level !== undefined) {
        if (typeof input.level !== "number" || !Number.isInteger(input.level) || input.level < 1 || input.level > 6) {
            throw new ValidationError("level", "must be integer 1-6");
        }
    }

    // origin
    if (input.origin !== undefined && !VALID_ORIGINS.includes(input.origin)) {
        throw new ValidationError("origin", `invalid origin: ${input.origin}`);
    }

    // isCritical
    if (input.isCritical !== undefined && typeof input.isCritical !== "boolean") {
        throw new ValidationError("isCritical", "must be boolean");
    }

    // tags
    if (input.tags !== undefined) {
        if (!Array.isArray(input.tags)) {
            throw new ValidationError("tags", "must be array");
        }
        if (input.tags.length > MAX_TAG_COUNT) {
            throw new ValidationError("tags", `exceeds max count ${MAX_TAG_COUNT}`);
        }
        for (let i = 0; i < input.tags.length; i++) {
            const tag = input.tags[i];
            if (typeof tag.key !== "string" || tag.key.length > MAX_TAG_KEY_LENGTH) {
                throw new ValidationError(`tags[${i}].key`, `invalid or too long`);
            }
            if (typeof tag.category !== "string" || tag.category.length > MAX_TAG_VALUE_LENGTH) {
                throw new ValidationError(`tags[${i}].category`, `invalid or too long`);
            }
        }
    }

    // resourceIds
    if (input.resourceIds !== undefined) {
        if (!Array.isArray(input.resourceIds)) {
            throw new ValidationError("resourceIds", "must be array");
        }
        if (input.resourceIds.length > MAX_RESOURCE_IDS) {
            throw new ValidationError("resourceIds", `exceeds max count ${MAX_RESOURCE_IDS}`);
        }
    }

    // details (string in SDK, map in Go — validate length)
    if (input.details !== undefined && input.details !== null) {
        if (typeof input.details === "string" && input.details.length > MAX_MESSAGE_LENGTH) {
            throw new ValidationError("details", `exceeds max length ${MAX_MESSAGE_LENGTH}`);
        }
    }

    // agentBackLog
    if (input.agentBackLog !== undefined && input.agentBackLog !== null) {
        if (!Array.isArray(input.agentBackLog)) {
            throw new ValidationError("agentBackLog", "must be array");
        }
        if (input.agentBackLog.length > MAX_TAG_COUNT) {
            throw new ValidationError("agentBackLog", `exceeds max count ${MAX_TAG_COUNT}`);
        }
    }

    // aiContext
    if (input.aiContext !== undefined && input.aiContext !== null) {
        const ai = input.aiContext;
        if (ai.loopDepth !== undefined && (typeof ai.loopDepth !== "number" || ai.loopDepth < 0)) {
            throw new ValidationError("aiContext.loopDepth", "must be non-negative number");
        }
    }
}
