import {
    WalEntryRaw,
    LogTag,
    LogType,
    LogLevel,
    AIAgentEventBacklog,
    AIAgentProcessorInfo,
    ResourceInfo,
    AllocatedHardwareResourceInfo,
    ServiceInfo,
    JSONValue,
} from "../../types/log";
import { err, ok, Result, tryCatch } from "../functional/result";

// 1. バリデーションヘルパー

/** 必須項目の検証 */
const req = <T>(
    val: unknown,
    name: string,
    check: (v: unknown) => v is T,
): Result<T, Error> => {
    if (check(val)) return ok(val);
    return err(new Error(`Field '${name}' is invalid or missing`));
};

/** オプショナル項目の検証 (undefined/null は OK) */
const opt = <T>(
    val: unknown,
    name: string,
    check: (v: unknown) => v is T,
): Result<T | undefined, Error> => {
    if (val === undefined || val === null) return ok(undefined);
    if (check(val)) return ok(val);
    return err(new Error(`Field '${name}' is invalid type`));
};

// --- 型ガード (プリミティブ) ---
const isStr = (v: unknown): v is string => typeof v === "string";
const isNum = (v: unknown): v is number => typeof v === "number";
const isBigInt = (v: unknown): v is bigint => typeof v === "bigint"; // ★ 追加
const isBool = (v: unknown): v is boolean => typeof v === "boolean";
const isObj = (v: unknown): v is Record<string, unknown> =>
    typeof v === "object" && v !== null && !Array.isArray(v);

// --- 型ガード (Enum / 特殊) ---
const isLogLevel = (v: unknown): v is LogLevel => {
    return typeof v === "number" && Number.isInteger(v) && v >= 1 && v <= 6;
};

const validLogTypes = new Set([
    "BUSINESS-AUDIT",
    "SECURITY",
    "COMPLIANCE",
    "INFRA",
    "SYSTEM",
    "SLA",
    "DEBUG",
]);
const isLogType = (v: unknown): v is LogType =>
    isStr(v) && validLogTypes.has(v);

const isOrigin = (v: unknown): v is "SYSTEM" | "AI_AGENT" =>
    v === "SYSTEM" || v === "AI_AGENT";

const isAgentStatus = (v: unknown): v is "pending" | "success" | "failed" =>
    v === "pending" || v === "success" || v === "failed";

/**
 * JSONValueのチェック
 * 最適化: Protobuf/Mapper層で JSON.parse に成功している時点で
 * 基本的な構造は担保されているため、過度な再帰チェックは省略し、
 * 「プリミティブ または オブジェクト/配列」であることを確認する。
 */
const isJSONValue = (v: unknown): v is JSONValue => {
    const t = typeof v;
    return (
        t === "string" ||
        t === "number" ||
        t === "boolean" ||
        v === null ||
        t === "object"
    );
};

// 2. サブバリデータ (ネストしたオブジェクト用)

// tryCatch内の ensure 用ヘルパー (Result -> Value or Throw)
// この throw は tryCatch で捕捉され、最終的に Result.error に変換されます
const ensure = <T>(r: Result<T, Error>): T => {
    if (!r.success) throw r.error;
    return r.value;
};

/** HardwareResourceInfo (Strip Unknown Fields) */
const validateHardware = (
    obj: unknown,
    path: string,
): AllocatedHardwareResourceInfo => {
    if (!isObj(obj)) throw new Error(`${path} must be object`);
    return {
        quantity: ensure(req(obj.quantity, `${path}.quantity`, isNum)),
        unit: ensure(req(obj.unit, `${path}.unit`, isStr)),
    };
};

/** ServiceInfo (Strip Unknown Fields) */
const validateServiceInfo = (obj: unknown, path: string): ServiceInfo => {
    if (!isObj(obj)) throw new Error(`${path} must be object`);
    return {
        serviceId: ensure(req(obj.serviceId, `${path}.serviceId`, isStr)),
        instanceId: ensure(req(obj.instanceId, `${path}.instanceId`, isStr)),
        version: ensure(req(obj.version, `${path}.version`, isStr)),
        deployment: ensure(req(obj.deployment, `${path}.deployment`, isStr)),
        DIContainerRuntime: ensure(
            opt(obj.DIContainerRuntime, `${path}.DIContainerRuntime`, isStr),
        ),
    };
};

/** ResourceInfo (Strip Unknown Fields) */
const validateResourceInfo = (obj: unknown, path: string): ResourceInfo => {
    if (!isObj(obj)) throw new Error(`${path} must be object`);
    return {
        cpu: validateHardware(obj.cpu, `${path}.cpu`),
        memory: validateHardware(obj.memory, `${path}.memory`),
        outerStorage: validateHardware(
            obj.outerStorage,
            `${path}.outerStorage`,
        ),
        serviceInfo: validateServiceInfo(
            obj.serviceInfo,
            `${path}.serviceInfo`,
        ),
    };
};

/** ProcessorInfo (Strip Unknown Fields) */
const validateProcessorInfo = (
    obj: unknown,
    path: string,
): AIAgentProcessorInfo => {
    if (!isObj(obj)) throw new Error(`${path} must be object`);
    return {
        resourceInfo: validateResourceInfo(
            obj.resourceInfo,
            `${path}.resourceInfo`,
        ),
    };
};

/** LogTag (Strip Unknown Fields) */
const validateLogTag = (obj: unknown, index: number): LogTag => {
    if (!isObj(obj)) throw new Error(`tags[${index}] must be object`);
    return {
        key: ensure(req(obj.key, `tags[${index}].key`, isStr)),
        category: ensure(req(obj.category, `tags[${index}].category`, isStr)),
    };
};

/** AgentBackLog (Strip Unknown Fields) */
const validateAgentBackLog = (obj: unknown): AIAgentEventBacklog => {
    if (!isObj(obj)) throw new Error("agentBackLog must be object");

    if (!isObj(obj.processorInfo))
        throw new Error("backlog.processorInfo must be object");

    return {
        agentId: ensure(req(obj.agentId, "backlog.agentId", isStr)),
        taskId: ensure(req(obj.taskId, "backlog.taskId", isStr)),
        actionType: ensure(req(obj.actionType, "backlog.actionType", isStr)),
        model: ensure(req(obj.model, "backlog.model", isStr)),
        inputHash: ensure(req(obj.inputHash, "backlog.inputHash", isStr)),
        isAsynchronous: ensure(
            req(obj.isAsynchronous, "backlog.isAsynchronous", isBool),
        ),
        generatedAt: ensure(req(obj.generatedAt, "backlog.generatedAt", isStr)),
        status: ensure(req(obj.status, "backlog.status", isAgentStatus)),

        processorInfo: validateProcessorInfo(
            obj.processorInfo,
            "backlog.processorInfo",
        ),

        output: obj.output, // unknown (JSONValue)
        triggeredAt: ensure(opt(obj.triggeredAt, "backlog.triggeredAt", isStr)),
        confidence: ensure(opt(obj.confidence, "backlog.confidence", isNum)),
        error: ensure(opt(obj.error, "backlog.error", isStr)),
    };
};

// メインバリデータ (集約・Strict Mode)

export const validateWalEntry = (obj: unknown): Result<WalEntryRaw, Error> => {
    if (!isObj(obj)) return err(new Error("Input is not an object"));

    return tryCatch(() => {
        // --- 1. バリデーションと値の抽出 ---

        // WAL Meta
        // ★ 修正: sequenceId は bigint なので isBigInt でチェック
        const sequenceId = ensure(req(obj.sequenceId, "sequenceId", isBigInt));
        const prevHash = ensure(req(obj.prevHash, "prevHash", isStr));

        // Log Core
        const traceId = ensure(req(obj.traceId, "traceId", isStr));
        const spanId = ensure(opt(obj.spanId, "spanId", isStr));
        const parentSpanId = ensure(
            opt(obj.parentSpanId, "parentSpanId", isStr),
        );
        const actorId = ensure(opt(obj.actorId, "actorId", isStr));

        // Type & Level & Time
        const type = ensure(req(obj.type, "type", isLogType));
        const level = ensure(req(obj.level, "level", isLogLevel));

        const timestamp = ensure(req(obj.timestamp, "timestamp", isStr));
        const logicalClock = ensure(
            req(obj.logicalClock, "logicalClock", isNum),
        );

        // Source & Control
        const boundary = ensure(req(obj.boundary, "boundary", isStr));
        const serviceId = ensure(req(obj.serviceId, "serviceId", isStr));
        const origin = ensure(req(obj.origin, "origin", isOrigin));
        const isCritical = ensure(req(obj.isCritical, "isCritical", isBool));

        // AI Context
        let aiContext: WalEntryRaw["aiContext"] = undefined;
        if (obj.aiContext !== undefined) {
            if (!isObj(obj.aiContext))
                throw new Error("aiContext must be object");
            aiContext = {
                agentId: ensure(
                    req(obj.aiContext.agentId, "aiContext.agentId", isStr),
                ),
                taskId: ensure(
                    req(obj.aiContext.taskId, "aiContext.taskId", isStr),
                ),
                loopDepth: ensure(
                    req(obj.aiContext.loopDepth, "aiContext.loopDepth", isNum),
                ),
            };
        }

        // Content
        const message = ensure(req(obj.message, "message", isStr));
        const input = ensure(opt(obj.input, "input", isJSONValue));
        const traceInfo = ensure(opt(obj.traceInfo, "traceInfo", isStr));
        const triggerAgent = ensure(
            req(obj.triggerAgent, "triggerAgent", isBool),
        );
        const details = ensure(opt(obj.details, "details", isStr));

        // AgentBackLog (Nested)
        let agentBackLog: AIAgentEventBacklog | undefined = undefined;
        if (obj.agentBackLog !== undefined) {
            agentBackLog = validateAgentBackLog(obj.agentBackLog);
        }

        // Tags (Array)
        if (!Array.isArray(obj.tags)) throw new Error("tags must be an array");
        const tags: LogTag[] = obj.tags.map((t, i) => validateLogTag(t, i));

        // Resource Ids (Array Optional)
        let resourceIds: string[] | undefined = undefined;
        if (obj.resourceIds !== undefined) {
            if (!Array.isArray(obj.resourceIds))
                throw new Error("resourceIds must be array");
            resourceIds = obj.resourceIds.map((r, i) => {
                if (!isStr(r))
                    throw new Error(`resourceIds[${i}] must be string`);
                return r;
            });
        }

        // Integrity
        const previousHash = ensure(
            opt(obj.previousHash, "previousHash", isStr),
        );
        const hash = ensure(opt(obj.hash, "hash", isStr));
        const signature = ensure(opt(obj.signature, "signature", isStr));

        // --- 2. オブジェクトの再構築 (Strip Unknown Fields) ---
        // 余剰プロパティを排除したクリーンなオブジェクトを作成
        const cleanEntry: WalEntryRaw = {
            sequenceId,
            prevHash,
            traceId,
            spanId,
            parentSpanId,
            actorId,
            type,
            level,
            timestamp,
            logicalClock,
            boundary,
            serviceId,
            origin,
            isCritical,
            aiContext,
            message,
            input,
            traceInfo,
            triggerAgent,
            agentBackLog,
            details,
            tags,
            resourceIds,
            previousHash,
            hash,
            signature,
        };

        return cleanEntry;
    });
};
