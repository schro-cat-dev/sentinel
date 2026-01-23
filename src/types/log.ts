export type JSONValue =
    | string
    | number
    | boolean
    | null
    | JSONValue[]
    | { [key: string]: JSONValue };

export type LogType =
    | "BUSINESS-AUDIT"
    | "SECURITY"
    | "COMPLIANCE" // 法令、ガイドライン、等
    | "INFRA"
    | "SYSTEM"
    | "SLA"
    | "DEBUG";
export type LogLevel = 1 | 2 | 3 | 4 | 5 | 6;

export type LogTag = {
    key: string;
    // value: string; // key = value として扱う
    category: string;
};

export interface Log {
    // 識別子・追跡（基本情報）
    traceId: string;
    spanId?: string;
    parentSpanId?: string;
    actorId?: string; // 実行者（UserID, System, or AgentID）

    type: LogType;
    level: LogLevel;
    timestamp: string; // ISO8601 with high precision
    logicalClock: number; // 分散システムでの順序保証用

    // 発生源（トレーサビリティ責務）
    boundary: string; // 発生箇所情報: サービス名やモジュール名
    serviceId: string; // どのインスタンスか（Configから自動注入）

    // 制御メタデータ（安全性責務）
    origin: "SYSTEM" | "AI_AGENT";
    isCritical: boolean;
    aiContext?: {
        agentId: string;
        taskId: string;
        loopDepth: number; // 無限ループ防止用の深度管理
    };

    // コンテンツ（情報責務）
    message: string; // ログ主メッセージ（PIIマスキング・整合性ハッシュ対象）
    input?: JSONValue;
    traceInfo?: string; // TODO 仮
    triggerAgent: boolean;
    agentBackLog?: AIAgentEventBacklog; // AI実行時のみ付与される詳細レコード
    details?: string; // TODO cooperate AI agent

    // 証跡・整合性（不変性責務）
    tags: LogTag[];
    resourceIds?: string[]; // TODO 影響がある口座などの関連情報
    previousHash?: string; // ハッシュチェーン（前のログのハッシュ）
    hash?: string; // このログ自体のハッシュ
    signature?: string; // デジタル署名（非改ざん証明）
}

export interface AIAgentEventBacklog {
    agentId: string; // "anomaly-detector-v2"
    taskId: string; // "task-uuid-123"
    actionType: string; // TODO "analyze", "alert", "remediate"
    model: string; // "gpt-4o", "llama3-70b"
    inputHash: string; // 入力データのハッシュ
    output?: unknown; // TODO AI出力
    isAsynchronous: boolean;
    generatedAt: string;
    triggeredAt?: string;
    processorInfo: AIAgentProcessorInfo;
    confidence?: number; // 信頼度スコア（0.0-1.0）
    status: "pending" | "success" | "failed"; // 実行状態
    error?: string; // エラー詳細
}

export interface AIAgentProcessorInfo {
    resourceInfo: ResourceInfo;
}

export interface ResourceInfo {
    cpu: AllocatedHardwareResourceInfo;
    memory: AllocatedHardwareResourceInfo;
    outerStorage: AllocatedHardwareResourceInfo;
    serviceInfo: ServiceInfo; // in which service the agent is processed.
}

export interface AllocatedHardwareResourceInfo {
    quantity: number;
    unit: string;
}

export interface ServiceInfo {
    serviceId: string; // "payment-service-v1.2.3"
    instanceId: string; // "pod-789-abc123"
    version: string; // "1.2.3"
    deployment: string; // "prod-ap-northeast-1"
    DIContainerRuntime?: string; // "docker", "di-containerd"
}
