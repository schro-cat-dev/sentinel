/**
 * タスク実行アクションの定数定義
 */
export const TASK_ACTION_TYPES = [
    "AI_ANALYZE",
    "AUTOMATED_REMEDIATE",
    "SYSTEM_NOTIFICATION",
    "EXTERNAL_WEBHOOK",
    "KILL_SWITCH",
    "ESCALATE",
] as const;

export type TaskActionType = (typeof TASK_ACTION_TYPES)[number];

/**
 * タスク優先度 (1: 最高/即時 - 5: 最低/バッチ)
 */
export type TaskPriority = 1 | 2 | 3 | 4 | 5;

/**
 * タスク実行レベル
 * AUTO: 自動実行
 * SEMI_AUTO: 確認後自動実行
 * MANUAL: 人間が実行
 * MONITOR: 監視のみ
 */
export type TaskExecutionLevel = "AUTO" | "SEMI_AUTO" | "MANUAL" | "MONITOR";

/**
 * タスクルール定義
 * EventDetectorが検知したイベント名に紐づくルール
 */
export interface TaskRule {
    ruleId: string;
    eventName: string;
    severity: TaskSeverity;
    actionType: TaskActionType;
    executionLevel: TaskExecutionLevel;
    priority: TaskPriority;
    description: string;
    executionParams: {
        targetEndpoint?: string;
        scriptIdentifier?: string;
        notificationChannel?: string;
        promptTemplate?: string;
    };
    guardrails: {
        requireHumanApproval: boolean;
        timeoutMs: number;
        maxRetries: number;
    };
}

/**
 * 重大度分類
 */
export const TASK_SEVERITIES = [
    "CRITICAL",
    "HIGH",
    "MEDIUM",
    "LOW",
    "INFO",
] as const;

export type TaskSeverity = (typeof TASK_SEVERITIES)[number];

/**
 * 生成されたタスク
 */
export interface GeneratedTask {
    taskId: string;
    ruleId: string;
    eventName: string;
    severity: TaskSeverity;
    actionType: TaskActionType;
    executionLevel: TaskExecutionLevel;
    priority: TaskPriority;
    description: string;
    executionParams: TaskRule["executionParams"];
    guardrails: TaskRule["guardrails"];
    sourceLog: {
        traceId: string;
        message: string;
        boundary: string;
        level: number;
        timestamp: string;
    };
    createdAt: string;
}

/**
 * タスク実行結果
 */
export type TaskDispatchStatus = "dispatched" | "blocked_approval" | "skipped" | "failed";

export interface TaskResult {
    taskId: string;
    ruleId: string;
    status: TaskDispatchStatus;
    dispatchedAt: string;
    error?: string;
}
