import { ITaskRepository } from "./i-task-repository";
import {
    TaskDefinition,
    TaskActionType,
    TaskPriority,
    TASK_ACTION_TYPES,
} from "../../types/task";

/**
 * DB接続設定の型定義（Record<string, unknown>を排除）
 */
export interface DBConnectionConfig {
    host: string;
    port: number;
    dbName: string;
    username: string;
    password?: string;
    cacheTtlMs?: number;
    ssl?: boolean;
}

export class SQLTaskRepository implements ITaskRepository {
    private cache = new Map<
        string,
        { data: TaskDefinition[]; expires: number }
    >();
    private readonly ttlMs: number;

    constructor(private config: DBConnectionConfig) {
        this.ttlMs = config.cacheTtlMs ?? 300000;
        this.initializeConnection();
    }

    private initializeConnection(): void {
        console.log(
            `[SQLTaskRepository] Connecting to ${this.config.host}:${this.config.port}/${this.config.dbName}`,
        );
    }

    public async getTasksByEvent(eventName: string): Promise<TaskDefinition[]> {
        const cached = this.cache.get(eventName);
        if (cached && cached.expires > Date.now()) {
            return cached.data;
        }

        try {
            const definitions = await this.queryDatabase(eventName);
            this.cache.set(eventName, {
                data: definitions,
                expires: Date.now() + this.ttlMs,
            });
            return definitions;
        } catch (error) {
            console.error(
                `[SQLTaskRepository] Critical: Failed to fetch tasks for ${eventName}`,
                error,
            );
            return [];
        }
    }

    private async queryDatabase(eventName: string): Promise<TaskDefinition[]> {
        // 1. 生データの取得（DBドライバの戻り値は通常 unknown[] として扱う）
        const rawRows: unknown[] = await this.executeRawQuery(eventName);

        // 2. フィルタリングと型安全なマッピング
        return rawRows
            .map((row) => this.validateAndMapRow(row))
            .filter((task): task is TaskDefinition => task !== null);
    }

    /**
     * DBの1行を型安全に検証・変換
     */
    private validateAndMapRow(row: unknown): TaskDefinition | null {
        if (!row || typeof row !== "object") return null;

        // 型の絞り込み（Type Narrowing）
        const r = row as Record<string, unknown>;

        // 必須フィールドの存在チェック
        if (
            typeof r.id !== "string" ||
            typeof r.event_name !== "string" ||
            typeof r.params !== "string" ||
            typeof r.require_approval !== "boolean"
        ) {
            return null;
        }

        // ActionType のバリデーション
        const actionType = String(r.action_type);
        if (!this.isTaskActionType(actionType)) {
            console.warn(
                `[SQLTaskRepository] Invalid ActionType found in DB: ${actionType}`,
            );
            return null;
        }

        // Priority のバリデーション
        const priority = Number(r.priority);
        if (!this.isTaskPriority(priority)) {
            return null;
        }

        // パラメータのパース（JSON.parse の戻り値を安全に扱う）
        const executionParams = this.parseParams(r.params);

        return {
            taskId: r.id,
            eventName: r.event_name,
            actionType: actionType,
            priority: priority,
            executionParams,
            guardrails: {
                requireHumanApproval: r.require_approval,
                timeoutMs: 30000,
                retryStrategy: {
                    maxAttempts: 3,
                    initialIntervalMs: 1000,
                    backoffFactor: 2,
                },
            },
            metadata: { originator: "SYSTEM", version: "1.0.0" },
        };
    }

    /**
     * Type Guards
     */
    private isTaskActionType(type: string): type is TaskActionType {
        return (TASK_ACTION_TYPES as readonly string[]).includes(type);
    }

    private isTaskPriority(p: number): p is TaskPriority {
        return [1, 2, 3, 4, 5].includes(p);
    }

    private parseParams(json: string): TaskDefinition["executionParams"] {
        try {
            const parsed = JSON.parse(json);
            if (typeof parsed !== "object" || parsed === null) return {};

            const p = parsed as Record<string, unknown>;
            return {
                promptTemplate:
                    typeof p.promptTemplate === "string"
                        ? p.promptTemplate
                        : undefined,
                targetEndpoint:
                    typeof p.targetEndpoint === "string"
                        ? p.targetEndpoint
                        : undefined,
                scriptIdentifier:
                    typeof p.scriptIdentifier === "string"
                        ? p.scriptIdentifier
                        : undefined,
            };
        } catch {
            return {};
        }
    }

    private async executeRawQuery(_eventName: string): Promise<unknown[]> {
        // 実際には pool.query(...) を実行
        return [
            {
                id: "task-001",
                event_name: _eventName,
                action_type: "AI_ANALYZE",
                priority: 1,
                params: '{"promptTemplate": "Analyze breach"}',
                require_approval: true,
            },
        ];
    }
}
