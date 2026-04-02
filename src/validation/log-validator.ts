/**
 * SDK入力バリデータ — zodなし、zero-dep
 *
 * SDK公開API境界（ingest()）でランタイム検証を行う。
 * TypeScript型はコンパイル時のみ。このモジュールはランタイムで不正入力を弾く。
 *
 * 全フィールドにサイズ制限あり。デフォルト値はValidationLimitsで定義。
 * 利用者はcreateDefaultConfigまたはvalidateLogInput第2引数でオーバーライド可能。
 */

import type { Log, LogType, LogLevel } from "../types/log";

const VALID_LOG_TYPES: readonly string[] = [
    "BUSINESS-AUDIT", "SECURITY", "COMPLIANCE", "INFRA", "SYSTEM", "SLA", "DEBUG",
];
const VALID_ORIGINS: readonly string[] = ["SYSTEM", "AI_AGENT"];

/**
 * バリデーション制限値。利用者がオーバーライド可能。
 * デフォルト値はGoサーバのnormalizer/config制限と整合。
 */
export interface ValidationLimits {
    /** message最大長（デフォルト: 65536） */
    maxMessageLength: number;
    /** details最大長（デフォルト: 65536） */
    maxDetailsLength: number;
    /** tags最大数（デフォルト: 100） */
    maxTagCount: number;
    /** tag.key最大長（デフォルト: 128） */
    maxTagKeyLength: number;
    /** tag.category最大長（デフォルト: 1024） */
    maxTagValueLength: number;
    /** resourceIds最大数（デフォルト: 100） */
    maxResourceIds: number;
    /** resourceIds各要素の最大長（デフォルト: 512） */
    maxResourceIdLength: number;
    /** 文字列フィールドの汎用最大長: actorId, traceId, spanId, parentSpanId, boundary, traceInfo（デフォルト: 512） */
    maxStringFieldLength: number;
    /** input フィールドのJSON概算最大バイト数（デフォルト: 1MB = 1048576） */
    maxInputSize: number;
    /** ログ全体の概算最大バイト数（デフォルト: 2MB = 2097152） */
    maxTotalLogSize: number;
}

export const DEFAULT_VALIDATION_LIMITS: Readonly<ValidationLimits> = {
    maxMessageLength: 65536,
    maxDetailsLength: 65536,
    maxTagCount: 100,
    maxTagKeyLength: 128,
    maxTagValueLength: 1024,
    maxResourceIds: 100,
    maxResourceIdLength: 512,
    maxStringFieldLength: 512,
    maxInputSize: 1_048_576,
    maxTotalLogSize: 2_097_152,
};

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
 * @param input 検証対象
 * @param limits カスタム制限値（省略時はDEFAULT_VALIDATION_LIMITS）
 */
export function validateLogInput(
    input: Partial<Log>,
    limits: Partial<ValidationLimits> = {},
): void {
    const L = { ...DEFAULT_VALIDATION_LIMITS, ...limits };

    // message: 必須、非空、最大長、null byte、lone surrogate
    if (input.message === undefined || input.message === null) {
        throw new ValidationError("message", "is required");
    }
    {
        if (typeof input.message !== "string") {
            throw new ValidationError("message", "must be a string");
        }
        if (input.message.trim().length === 0) {
            throw new ValidationError("message", "cannot be empty");
        }
        if (input.message.length > L.maxMessageLength) {
            throw new ValidationError("message", `exceeds max length ${L.maxMessageLength}`);
        }
        if (input.message.includes("\x00")) {
            throw new ValidationError("message", "contains null bytes");
        }
        if (containsLoneSurrogate(input.message)) {
            throw new ValidationError("message", "contains invalid UTF-16 lone surrogate");
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

    // timestamp (A-03: must be ISO8601 string if provided)
    if (input.timestamp !== undefined) {
        if (typeof input.timestamp !== "string") {
            throw new ValidationError("timestamp", "must be a string");
        }
        if (!isISO8601(input.timestamp)) {
            throw new ValidationError("timestamp", "must be a valid ISO8601 date string");
        }
    }

    // logicalClock (A-03: must be finite non-negative number if provided)
    if (input.logicalClock !== undefined) {
        if (typeof input.logicalClock !== "number" || !Number.isFinite(input.logicalClock) || input.logicalClock < 0) {
            throw new ValidationError("logicalClock", "must be a finite non-negative number");
        }
    }

    // triggerAgent (A-03: must be boolean if provided)
    if (input.triggerAgent !== undefined && typeof input.triggerAgent !== "boolean") {
        throw new ValidationError("triggerAgent", "must be boolean");
    }

    // string fields with length limit
    validateStringField(input.actorId, "actorId", L.maxStringFieldLength);
    validateStringField(input.traceId, "traceId", L.maxStringFieldLength);
    validateStringField(input.spanId, "spanId", L.maxStringFieldLength);
    validateStringField(input.parentSpanId, "parentSpanId", L.maxStringFieldLength);
    validateStringField(input.boundary, "boundary", L.maxStringFieldLength);
    validateStringField(input.traceInfo, "traceInfo", L.maxStringFieldLength);

    // tags
    if (input.tags !== undefined) {
        if (!Array.isArray(input.tags)) {
            throw new ValidationError("tags", "must be array");
        }
        if (input.tags.length > L.maxTagCount) {
            throw new ValidationError("tags", `exceeds max count ${L.maxTagCount}`);
        }
        for (let i = 0; i < input.tags.length; i++) {
            const tag = input.tags[i];
            if (typeof tag.key !== "string" || tag.key.length > L.maxTagKeyLength) {
                throw new ValidationError(`tags[${i}].key`, `invalid or too long`);
            }
            if (tag.key.includes("\x00")) {
                throw new ValidationError(`tags[${i}].key`, "contains null bytes");
            }
            if (containsLoneSurrogate(tag.key)) {
                throw new ValidationError(`tags[${i}].key`, "contains invalid UTF-16 lone surrogate");
            }
            if (typeof tag.category !== "string" || tag.category.length > L.maxTagValueLength) {
                throw new ValidationError(`tags[${i}].category`, `invalid or too long`);
            }
            if (tag.category.includes("\x00")) {
                throw new ValidationError(`tags[${i}].category`, "contains null bytes");
            }
            if (containsLoneSurrogate(tag.category)) {
                throw new ValidationError(`tags[${i}].category`, "contains invalid UTF-16 lone surrogate");
            }
        }
    }

    // resourceIds
    if (input.resourceIds !== undefined) {
        if (!Array.isArray(input.resourceIds)) {
            throw new ValidationError("resourceIds", "must be array");
        }
        if (input.resourceIds.length > L.maxResourceIds) {
            throw new ValidationError("resourceIds", `exceeds max count ${L.maxResourceIds}`);
        }
        for (let i = 0; i < input.resourceIds.length; i++) {
            if (typeof input.resourceIds[i] !== "string") {
                throw new ValidationError(`resourceIds[${i}]`, "must be a string");
            }
            if (input.resourceIds[i].length > L.maxResourceIdLength) {
                throw new ValidationError(`resourceIds[${i}]`, `exceeds max length ${L.maxResourceIdLength}`);
            }
            if (input.resourceIds[i].includes("\x00")) {
                throw new ValidationError(`resourceIds[${i}]`, "contains null bytes");
            }
            if (containsLoneSurrogate(input.resourceIds[i])) {
                throw new ValidationError(`resourceIds[${i}]`, "contains invalid UTF-16 lone surrogate");
            }
        }
    }

    // details (Record<string, string> — Proto map<string,string> 互換)
    if (input.details !== undefined && input.details !== null) {
        if (typeof input.details !== "object" || Array.isArray(input.details)) {
            throw new ValidationError("details", "must be an object (Record<string, string>)");
        }
        const entries = Object.entries(input.details);
        if (entries.length > 50) {
            throw new ValidationError("details", `exceeds max entry count 50 (got ${entries.length})`);
        }
        for (const [k, v] of entries) {
            if (typeof v !== "string") {
                throw new ValidationError(`details.${k}`, "value must be a string");
            }
            if (v.length > L.maxDetailsLength) {
                throw new ValidationError(`details.${k}`, `exceeds max length ${L.maxDetailsLength}`);
            }
            if (v.includes("\x00")) {
                throw new ValidationError(`details.${k}`, "contains null bytes");
            }
            if (containsLoneSurrogate(v)) {
                throw new ValidationError(`details.${k}`, "contains invalid UTF-16 lone surrogate");
            }
        }
    }

    // input (JSONValue) — approximate size check
    if (input.input !== undefined && input.input !== null) {
        const approxSize = estimateJsonSize(input.input);
        if (approxSize > L.maxInputSize) {
            throw new ValidationError("input", `exceeds max size ~${L.maxInputSize} bytes (estimated ${approxSize})`);
        }
    }

    // agentBackLog
    if (input.agentBackLog !== undefined && input.agentBackLog !== null) {
        if (typeof input.agentBackLog !== "object" || Array.isArray(input.agentBackLog)) {
            throw new ValidationError("agentBackLog", "must be an object");
        }
        // GAP-02: エントリ数制限（DoS防止）
        const backLogKeys = Object.keys(input.agentBackLog as object);
        if (backLogKeys.length > 100) {
            throw new ValidationError("agentBackLog", `too many entries (${backLogKeys.length} > 100)`);
        }
        const backLogSize = estimateJsonSize(input.agentBackLog);
        if (backLogSize > L.maxInputSize) {
            throw new ValidationError("agentBackLog", `exceeds max size ~${L.maxInputSize} bytes (estimated ${backLogSize})`);
        }
    }

    // aiContext
    if (input.aiContext !== undefined && input.aiContext !== null) {
        const ai = input.aiContext;
        // プロトタイプ汚染防御
        if (Object.prototype.hasOwnProperty.call(ai, "__proto__") || Object.prototype.hasOwnProperty.call(ai, "constructor")) {
            throw new ValidationError("aiContext", "contains prohibited keys (__proto__ or constructor)");
        }
        if (ai.loopDepth !== undefined && (typeof ai.loopDepth !== "number" || ai.loopDepth < 0)) {
            throw new ValidationError("aiContext.loopDepth", "must be non-negative number");
        }
    }

    // total log size estimate
    const totalSize = estimateLogSize(input);
    if (totalSize > L.maxTotalLogSize) {
        throw new ValidationError("_total", `log exceeds max total size ~${L.maxTotalLogSize} bytes (estimated ${totalSize})`);
    }
}

/**
 * ISO8601日時文字列の簡易検証。
 * Date.parse()のみに頼ると "1234567890" 等の数値文字列も通過するため、
 * パターンマッチ + Date.parse の二重検証で安全性を確保する。
 */
const ISO8601_PATTERN = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d+)?(Z|[+-]\d{2}:\d{2})$/;

function isISO8601(value: string): boolean {
    if (!ISO8601_PATTERN.test(value)) return false;
    return !isNaN(Date.parse(value));
}

function validateStringField(value: string | undefined | null, field: string, maxLength: number): void {
    if (value === undefined || value === null) return;
    if (typeof value !== "string") {
        throw new ValidationError(field, "must be a string");
    }
    if (value.length > maxLength) {
        throw new ValidationError(field, `exceeds max length ${maxLength}`);
    }
    if (value.includes("\x00")) {
        throw new ValidationError(field, "contains null bytes");
    }
    if (containsLoneSurrogate(value)) {
        throw new ValidationError(field, "contains invalid UTF-16 lone surrogate");
    }
}

/**
 * 不正なUTF-16 lone surrogate を検出する。
 * JavaScriptの文字列はUTF-16エンコードされているため、
 * ペアになっていないサロゲートを検出してgRPC/protobuf互換性を保証する。
 */
function containsLoneSurrogate(s: string): boolean {
    for (let i = 0; i < s.length; i++) {
        const code = s.charCodeAt(i);
        if (code >= 0xD800 && code <= 0xDBFF) {
            // High surrogate — 次の文字がlow surrogateでなければlone
            const next = s.charCodeAt(i + 1);
            if (isNaN(next) || next < 0xDC00 || next > 0xDFFF) return true;
            i++; // skip paired low surrogate
        } else if (code >= 0xDC00 && code <= 0xDFFF) {
            // Lone low surrogate
            return true;
        }
    }
    return false;
}

function estimateJsonSize(value: unknown, depth = 0, seen?: WeakSet<object>): number {
    if (depth > 20) return 0;
    if (value === null || value === undefined) return 4;
    if (typeof value === "string") return value.length + 2;
    if (typeof value === "number" || typeof value === "boolean") return 8;
    if (typeof value === "object") {
        const visited = seen ?? new WeakSet<object>();
        if (visited.has(value as object)) return 0; // 循環参照防御
        visited.add(value as object);
        try {
            if (Array.isArray(value)) {
                let size = 2;
                for (const item of value) size += estimateJsonSize(item, depth + 1, visited) + 1;
                return size;
            }
            let size = 2;
            for (const [k, v] of Object.entries(value as Record<string, unknown>)) {
                size += k.length + 3 + estimateJsonSize(v, depth + 1, visited) + 1;
            }
            return size;
        } finally {
            visited.delete(value as object);
        }
    }
    return 8;
}

function estimateLogSize(input: Partial<Log>): number {
    // validateLogInput で message は必須・非空が検証済み
    let size = input.message!.length;
    if (input.details) size += estimateJsonSize(input.details);
    if (input.traceInfo) size += input.traceInfo.length;
    if (input.actorId) size += input.actorId.length;
    if (input.boundary) size += input.boundary.length;
    if (input.traceId) size += input.traceId.length;
    if (input.tags) {
        for (const tag of input.tags) {
            size += tag.key.length + tag.category.length;
        }
    }
    if (input.resourceIds) {
        for (const id of input.resourceIds) {
            size += id.length;
        }
    }
    if (input.input !== undefined && input.input !== null) {
        size += estimateJsonSize(input.input);
    }
    if (input.agentBackLog !== undefined && input.agentBackLog !== null) {
        size += estimateJsonSize(input.agentBackLog);
    }
    if (input.aiContext !== undefined && input.aiContext !== null) {
        size += estimateJsonSize(input.aiContext);
    }
    return size;
}
