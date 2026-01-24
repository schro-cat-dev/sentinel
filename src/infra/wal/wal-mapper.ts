import {
    WalEntryRaw,
    AIAgentEventBacklog,
    AIAgentProcessorInfo,
    ResourceInfo,
    AllocatedHardwareResourceInfo,
    ServiceInfo,
    LogType,
    LogLevel,
} from "../../types/log"; // 'Domain' here.

import {
    WalEntry as ProtoWalEntry,
    AgentBacklog as ProtoAgentBacklog,
    ProcessorInfo as ProtoProcessorInfo,
    ResourceInfo as ProtoResourceInfo,
    HardwareInfo as ProtoHardwareInfo,
    ServiceInfo as ProtoServiceInfo,
} from "../../generated/src/proto/wal"; // Proto here.

/*
 * NOTE:
 * 命名規則: Domain(PascalCase) → Proto(camelCase)
 * DIContainerRuntime → diContainerRuntime
 */

// --- Domain → Proto (Encode) ---

const toProtoHardware = (
    h: AllocatedHardwareResourceInfo,
): ProtoHardwareInfo => ({
    quantity: h.quantity,
    unit: h.unit,
});

const toProtoService = (s: ServiceInfo): ProtoServiceInfo => ({
    serviceId: s.serviceId,
    instanceId: s.instanceId,
    version: s.version,
    deployment: s.deployment,
    diContainerRuntime: s.DIContainerRuntime,
});

const toProtoResource = (r: ResourceInfo): ProtoResourceInfo => ({
    cpu: toProtoHardware(r.cpu),
    memory: toProtoHardware(r.memory),
    outerStorage: toProtoHardware(r.outerStorage),
    serviceInfo: toProtoService(r.serviceInfo),
});

const toProtoProcessor = (p: AIAgentProcessorInfo): ProtoProcessorInfo => ({
    resourceInfo: toProtoResource(p.resourceInfo),
});

const toProtoBacklog = (b: AIAgentEventBacklog): ProtoAgentBacklog => ({
    agentId: b.agentId,
    taskId: b.taskId,
    actionType: b.actionType,
    model: b.model,
    inputHash: b.inputHash,
    outputJson: b.output !== undefined ? JSON.stringify(b.output) : undefined,
    isAsynchronous: b.isAsynchronous,
    generatedAt: b.generatedAt,
    triggeredAt: b.triggeredAt,
    confidence: b.confidence,
    status: b.status,
    error: b.error,
    processorInfo: toProtoProcessor(b.processorInfo),
});

const toLogType = (s: string): LogType => s as LogType;
const toLogLevel = (n: number): LogLevel => n as LogLevel;
const toOrigin = (s: string): WalEntryRaw["origin"] =>
    s as WalEntryRaw["origin"];

/**
 * 'Domain' Object -> Protobuf Object
 */
export const toProto = (entry: WalEntryRaw): ProtoWalEntry => {
    return {
        sequenceId: entry.sequenceId,
        prevHash: entry.prevHash,

        traceId: entry.traceId,
        spanId: entry.spanId,
        parentSpanId: entry.parentSpanId,
        actorId: entry.actorId,
        type: entry.type,
        level: entry.level,
        timestamp: entry.timestamp,
        logicalClock: entry.logicalClock,
        boundary: entry.boundary,
        serviceId: entry.serviceId,
        origin: entry.origin,
        isCritical: entry.isCritical,

        aiContext: entry.aiContext,
        message: entry.message,
        inputJson:
            entry.input !== undefined ? JSON.stringify(entry.input) : undefined,
        traceInfo: entry.traceInfo,
        triggerAgent: entry.triggerAgent,

        agentBackLog: entry.agentBackLog
            ? toProtoBacklog(entry.agentBackLog)
            : undefined,

        details: entry.details,

        tags: entry.tags.map((t) => ({ key: t.key, category: t.category })),
        resourceIds: entry.resourceIds ?? [],

        previousHash: entry.previousHash,
        hash: entry.hash,
        signature: entry.signature,
    };
};

// --- Proto → Domain (Decode) ---
// Proto → 構造復元オブジェクト（Validatorで型保証）

const fromProtoHardware = (
    h: ProtoHardwareInfo | undefined,
): AllocatedHardwareResourceInfo | undefined => {
    if (!h) return undefined;
    return {
        quantity: h.quantity,
        unit: h.unit,
    };
};

const fromProtoService = (s: ProtoServiceInfo | undefined) => {
    if (!s) return undefined;
    return {
        serviceId: s.serviceId,
        instanceId: s.instanceId,
        version: s.version,
        deployment: s.deployment,
        DIContainerRuntime: s.diContainerRuntime,
    };
};

const fromProtoResource = (r: ProtoResourceInfo | undefined) => {
    if (!r) return undefined;
    return {
        cpu: fromProtoHardware(r.cpu),
        memory: fromProtoHardware(r.memory),
        outerStorage: fromProtoHardware(r.outerStorage),
        serviceInfo: fromProtoService(r.serviceInfo),
    } as ResourceInfo;
};

const fromProtoProcessor = (
    p: ProtoProcessorInfo | undefined,
): Partial<AIAgentProcessorInfo> | undefined => {
    if (!p) return undefined;
    return {
        resourceInfo: fromProtoResource(p.resourceInfo),
    };
};

const toStatus = (s: string): AIAgentEventBacklog["status"] =>
    s as AIAgentEventBacklog["status"];

const fromProtoBacklog = (
    b: ProtoAgentBacklog,
): Partial<AIAgentEventBacklog> => {
    return {
        agentId: b.agentId,
        taskId: b.taskId,
        actionType: b.actionType,
        model: b.model,
        inputHash: b.inputHash,
        output: b.outputJson ? JSON.parse(b.outputJson) : undefined,
        isAsynchronous: b.isAsynchronous,
        generatedAt: b.generatedAt,
        triggeredAt: b.triggeredAt,
        confidence: b.confidence,
        status: toStatus(b.status),
        error: b.error,
        processorInfo: fromProtoProcessor(
            b.processorInfo,
        ) as AIAgentProcessorInfo,
    };
};

/**
 * Protobuf Object -> Domain Object (Unknown / Raw Structure)
 * 復元時は一度構造を整えた Plain Object に戻し、その後 validateWalEntry に渡す
 */
export const fromProto = (proto: ProtoWalEntry): Partial<WalEntryRaw> => {
    return {
        sequenceId: proto.sequenceId,
        prevHash: proto.prevHash,

        traceId: proto.traceId,
        spanId: proto.spanId,
        parentSpanId: proto.parentSpanId,
        actorId: proto.actorId,
        type: toLogType(proto.type),
        level: toLogLevel(proto.level),
        timestamp: proto.timestamp,
        logicalClock: proto.logicalClock,
        boundary: proto.boundary,
        serviceId: proto.serviceId,
        origin: toOrigin(proto.origin),
        isCritical: proto.isCritical,

        aiContext: proto.aiContext,

        message: proto.message,
        input: proto.inputJson ? JSON.parse(proto.inputJson) : undefined,
        traceInfo: proto.traceInfo,
        triggerAgent: proto.triggerAgent,

        agentBackLog: proto.agentBackLog
            ? (fromProtoBacklog(proto.agentBackLog) as AIAgentEventBacklog)
            : undefined,
        details: proto.details,

        tags: proto.tags,
        resourceIds: proto.resourceIds ?? [],

        previousHash: proto.previousHash,
        hash: proto.hash,
        signature: proto.signature,
    };
};
