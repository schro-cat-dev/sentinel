import { ITaskRepository } from "./i-task-repository";
import { IAgentProvider } from "../ai/i-agent-provider";
import { DetectionResult, SystemEventName } from "../../types/event";
import {
    Log,
    AIAgentEventBacklog,
    AIAgentProcessorInfo,
} from "../../types/log";
import { TaskDefinition } from "../../types/task";
import { IngestionEngine } from "../../core/engine/ingestion-engine";

export class TaskManager {
    constructor(
        private readonly taskRepo: ITaskRepository,
        private readonly agentProvider: IAgentProvider,
        private readonly ingestionEngine: IngestionEngine,
        private readonly maxLoopDepth: number,
    ) {}

    /**
     * 検知イベントをトリガーに、DBからレシピを引き出し、AIタスク群を実行する
     */
    public async onEventDetected(
        detection: DetectionResult<SystemEventName>,
        originalLog: Log,
    ): Promise<void> {
        // 1. 無限ループ防御（AIが生成したログにAIが無限に反応するのを防ぐ）
        const currentDepth = originalLog.aiContext?.loopDepth ?? 0;
        if (currentDepth >= this.maxLoopDepth) {
            console.warn(
                `[TaskManager] Safety Trigger: Max loop depth reached (${this.maxLoopDepth}) for traceId: ${originalLog.traceId}`,
            );
            return;
        }

        // 2. イベントに対応する定義（レシピ）をリポジトリから取得
        const tasks = await this.taskRepo.getTasksByEvent(detection.eventName);
        if (tasks.length === 0) {
            return;
        }

        // 3. 各タスクを並列または順次実行（ここでは安全のため順次実行）
        for (const task of tasks) {
            await this.executeTask(task, originalLog, currentDepth + 1);
        }
    }

    /**
     * 個別の AI タスクを実行し、結果をシステムログに再投入する
     */
    private async executeTask(
        task: TaskDefinition,
        context: Log,
        nextDepth: number,
    ): Promise<void> {
        const startTime = new Date().toISOString();

        try {
            // 1. AI プロバイダーによる推論実行
            const response = await this.agentProvider.execute(task, context);

            // 2. 成功ログの構築（ServiceInfo を含む ProcessorInfo を付与）
            const successBacklog: AIAgentEventBacklog = {
                agentId: task.taskId,
                taskId: task.taskId,
                actionType: task.actionType,
                model: response.model,
                inputHash: context.hash ?? "no-hash",
                output: response.result,
                isAsynchronous: true,
                generatedAt: new Date().toISOString(),
                triggeredAt: startTime,
                status: "success", // AIAgentStatus 型に適合
                confidence: response.result.confidence,
                processorInfo: this.getProcessorInfo(),
            };

            await this.reIngestAgentLog(
                context,
                task,
                successBacklog,
                nextDepth,
                `AI Action Result: ${response.result.action}`,
            );
        } catch (error) {
            // 3. 失敗時も「失敗したという事実」を証跡として残す
            const errorBacklog: AIAgentEventBacklog = {
                agentId: task.taskId,
                taskId: task.taskId,
                actionType: task.actionType,
                model: "unknown",
                inputHash: context.hash ?? "no-hash",
                isAsynchronous: true,
                generatedAt: new Date().toISOString(),
                triggeredAt: startTime,
                status: "failed",
                error: error instanceof Error ? error.message : String(error),
                processorInfo: this.getProcessorInfo(),
            };

            await this.reIngestAgentLog(
                context,
                task,
                errorBacklog,
                nextDepth,
                `AI Action Failed: ${task.taskId}`,
            );
        }
    }

    /**
     * 実行コンテキスト（環境情報）を型安全に生成
     */
    private getProcessorInfo(): AIAgentProcessorInfo {
        return {
            resourceInfo: {
                cpu: { quantity: 1, unit: "vCPU" },
                memory: { quantity: 512, unit: "MB" },
                outerStorage: { quantity: 0, unit: "GB" },
                serviceInfo: {
                    serviceId: "ai-orchestrator-node",
                    instanceId: "instance-az-1-001",
                    version: "1.2.0",
                    deployment: "production-east",
                    DIContainerRuntime: "docker",
                },
            },
        };
    }

    /**
     * AI の思考結果を、新しいログとして IngestionEngine に戻す
     */
    private async reIngestAgentLog(
        parentContext: Log,
        task: TaskDefinition,
        backlog: AIAgentEventBacklog,
        depth: number,
        message: string,
    ): Promise<void> {
        await this.ingestionEngine.handle({
            traceId: parentContext.traceId, // 同一の traceId を保持して追跡を可能にする
            parentSpanId: parentContext.spanId,
            actorId: backlog.agentId,
            type: "SYSTEM",
            level: backlog.status === "failed" ? 5 : 3,
            origin: "AI_AGENT",
            aiContext: {
                agentId: task.taskId,
                taskId: task.taskId,
                loopDepth: depth,
            },
            message: message,
            agentBackLog: backlog,
            triggerAgent: false, // ループ防止：AIログで再度AIを起動させない
        });
    }
}
