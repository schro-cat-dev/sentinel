/**
 * ServerManagementTransport — Server 管理 RPC のSDK側抽象化 (Phase 3)
 *
 * タスク承認/状態管理/ブロック管理をSDKから実行するためのインターフェース。
 * 具体的な gRPC 実装はユーザーが注入する（ゼロ依存原則）。
 */

/** タスク承認結果 */
export interface ApproveTaskResult {
    taskId: string;
    status: string;
    dispatchedAt?: string;
    error?: string;
}

/** タスク拒否結果 */
export interface RejectTaskResult {
    taskId: string;
    status: string;
}

/** タスク状態 */
export interface TaskStatusResult {
    taskId: string;
    ruleId: string;
    eventName: string;
    status: string;
    actionType: string;
    severity: string;
    executionLevel: string;
    description: string;
    sourceTraceId: string;
    createdAt: string;
    updatedAt: string;
    errorMessage?: string;
}

/** タスクリストフィルタ */
export interface TaskListFilter {
    eventName?: string;
    status?: string;
    fromTime?: string;
    toTime?: string;
    limit?: number;
    offset?: number;
}

/** タスクリスト結果 */
export interface TaskListResult {
    tasks: TaskStatusResult[];
    totalCount: number;
}

/** 保留中ブロック情報 */
export interface PendingBlockInfo {
    blockId: string;
    actionType: string;
    targetIp: string;
    targetUserId: string;
    reason: string;
    status: string;
    createdAt: string;
}

/** ブロック承認結果 */
export interface ApproveBlockResult {
    blockId: string;
    success: boolean;
    target: string;
    error?: string;
}

/** ブロック拒否結果 */
export interface RejectBlockResult {
    blockId: string;
    status: string;
}

/**
 * Server 管理 RPC インターフェース
 *
 * 全メソッドは Proto の SentinelService RPC と1:1対応。
 * ユーザーが gRPC クライアントを使って実装し、SentinelOptions に注入する。
 */
export interface ServerManagementTransport {
    // --- Task Approval ---
    approveTask(taskId: string, approverId: string, reason: string): Promise<ApproveTaskResult>;
    rejectTask(taskId: string, rejectorId: string, reason: string): Promise<RejectTaskResult>;

    // --- Task Status ---
    getTaskStatus(taskId: string): Promise<TaskStatusResult>;
    listTasks(filter: TaskListFilter): Promise<TaskListResult>;

    // --- Block Management ---
    listPendingBlocks(): Promise<PendingBlockInfo[]>;
    approveBlock(blockId: string, approverId: string): Promise<ApproveBlockResult>;
    rejectBlock(blockId: string, rejectorId: string): Promise<RejectBlockResult>;

    // --- Lifecycle ---
    close?(): Promise<void>;
}
