import { Log } from "../../types/log";
import { MaskingService } from "../../security/masking-service";
import { IntegritySigner } from "../../security/integrity-signer";
import { EventDetector } from "../detection/event-detector";
import { TaskGenerator } from "../task/task-generator";
import { TaskExecutor } from "../task/task-executor";
import { IIngestionCoordinator, ILogNormalizer } from "./i-interfaces";
import { IngestionResult } from "./types";
import { SentinelConfig } from "../../configs/sentinel-config";
import { TaskResult } from "../../types/task";
import { ErrorRouter } from "../../error-routing/error-router";

export class IngestionEngine implements IIngestionCoordinator {
    private readonly normalizer: ILogNormalizer;
    private readonly signer: IntegritySigner;
    private readonly detector: EventDetector;
    private readonly taskGenerator: TaskGenerator;
    private readonly taskExecutor: TaskExecutor;
    private readonly config: SentinelConfig;

    // PERF-04: Narrow mutex — only serializes hash chain update, not entire pipeline
    private chainLock: Promise<void> = Promise.resolve();

    // RES-02: dual-mode reuse
    private lastProcessedLog: Log | null = null;

    // エラールーティング（optional）
    private readonly errorRouter?: ErrorRouter;

    // 動的コールバックオーバーライド（configはfrozen、こちらはmutable）
    private callbackOverrides: {
        onLogProcessed?: ((log: Log) => void) | null;
        onTaskGenerated?: ((task: import("../../types/task").GeneratedTask) => void) | null;
        onTaskDispatched?: ((result: TaskResult) => void) | null;
        onError?: ((error: Error, context: string) => void) | null;
    } = {};

    constructor(deps: {
        config: SentinelConfig;
        normalizer: ILogNormalizer;
        signer: IntegritySigner;
        detector: EventDetector;
        taskGenerator: TaskGenerator;
        taskExecutor: TaskExecutor;
        errorRouter?: ErrorRouter;
    }) {
        this.config = deps.config;
        this.normalizer = deps.normalizer;
        this.signer = deps.signer;
        this.detector = deps.detector;
        this.taskGenerator = deps.taskGenerator;
        this.taskExecutor = deps.taskExecutor;
        this.errorRouter = deps.errorRouter;
    }

    /**
     * コールバックを動的に更新する。nullで明示的にクリア。undefinedで変更なし。
     * 不正な型はエラー。
     */
    updateCallbacks(callbacks: typeof this.callbackOverrides): void {
        // 型安全な個別代入（Record<string, unknown>キャスト不要）
        this.applyCallback("onLogProcessed", callbacks);
        this.applyCallback("onTaskGenerated", callbacks);
        this.applyCallback("onTaskDispatched", callbacks);
        this.applyCallback("onError", callbacks);
    }

    private applyCallback<K extends keyof typeof this.callbackOverrides>(
        key: K,
        callbacks: typeof this.callbackOverrides,
    ): void {
        const value = callbacks[key];
        if (value === undefined) return;
        if (value !== null && typeof value !== "function") {
            throw new Error(`updateCallbacks: "${key}" must be a function or null, got ${typeof value}`);
        }
        this.callbackOverrides[key] = value;
    }

    /** コールバックを取得（オーバーライド優先、なければconfig） */
    private getCallback<K extends "onLogProcessed" | "onTaskGenerated" | "onTaskDispatched" | "onError">(
        key: K,
    ): SentinelConfig[K] | undefined {
        if (key in this.callbackOverrides) {
            return (this.callbackOverrides[key] ?? undefined) as SentinelConfig[K] | undefined;
        }
        return this.config[key];
    }

    /**
     * 内部状態をリセットする（shutdown時に呼ばれる）
     */
    resetState(): void {
        this.signer.resetChain();
        this.lastProcessedLog = null;
        this.callbackOverrides = {};
        this.errorRouter?.shutdown();
    }

    /** onErrorコールバックを取得（オーバーライド優先）。dual-mode transport等から利用。 */
    getOnError(): ((error: Error, context: string) => void) | undefined {
        return this.getCallback("onError");
    }

    getLastProcessedLog(): Log | null {
        if (!this.lastProcessedLog) return null;
        return { ...this.lastProcessedLog };
    }

    /**
     * 正規化 + マスキングのみ（リモート送信用）
     */
    normalizeOnly(raw: Partial<Log>): Log {
        const log = this.normalizer.normalize(raw);
        if (this.config.masking.enabled) {
            return MaskingService.mask(
                log,
                this.config.masking.rules,
                this.config.masking.preserveFields,
                { logger: this.config.logger },
            );
        }
        return log;
    }

    async handle(raw: Partial<Log>): Promise<IngestionResult> {
        const startTime = Date.now();
        // 1. Normalize (outside lock — stateless, parallelizable)
        let log = this.normalizer.normalize(raw);
        this.emitSafe(() => this.config.tracer?.onPipelineStart?.({ traceId: log.traceId, operation: "ingest" }));

        // 2. Mask PII
        let masked = false;
        if (this.config.masking.enabled) {
            log = MaskingService.mask(
                log,
                this.config.masking.rules,
                this.config.masking.preserveFields,
            );
            masked = true;
        }

        // 3. Detect events
        const detection = this.detector.detect(log);

        // 3.5 Metrics: detection
        if (detection) {
            this.emitSafe(() => this.config.metrics?.onDetection?.({
                eventName: detection.eventName,
                priority: detection.priority,
            }));
        }

        // 4. Generate + dispatch tasks (outside lock — user handlers may be slow)
        const tasksGenerated: TaskResult[] = [];
        if (detection) {
            const tasks = this.taskGenerator.generate(detection, log);
            for (const task of tasks) {
                this.emitSafe(() => this.getCallback("onTaskGenerated")?.(task));
                const result = await this.taskExecutor.dispatch(task);
                this.emitSafe(() => this.getCallback("onTaskDispatched")?.(result));
                this.emitSafe(() => this.config.metrics?.onTaskDispatch?.(result));
                tasksGenerated.push(result);
            }
        }

        // 5. Hash-chain (NARROW lock — only the read-compute-update section)
        let hashChainValid = false;
        if (this.config.security.enableHashChain) {
            await this.withChainLock(() => {
                const previousHash = this.signer.getPreviousHash();
                log.previousHash = previousHash;
                log.hash = IntegritySigner.calculateHash(log, previousHash);
                this.signer.updateChain(log.hash);
            });
            hashChainValid = true;
        }

        // 6. Callbacks + metrics + tracing（防御コピーで改竄防止）
        this.emitSafe(() => this.getCallback("onLogProcessed")?.({ ...log, tags: [...log.tags] }));
        this.emitSafe(() => this.config.metrics?.onIngest?.());
        this.emitSafe(() => this.config.tracer?.onPipelineEnd?.({
            traceId: log.traceId,
            operation: "ingest",
            durationMs: Date.now() - startTime,
            success: true,
        }));

        this.lastProcessedLog = log;

        return {
            traceId: log.traceId,
            hashChainValid,
            tasksGenerated,
            masked,
            detection: detection ? { eventName: detection.eventName, priority: detection.priority } : null,
        };
    }

    /**
     * Narrow async mutex — serializes only the critical section
     */
    private async withChainLock(fn: () => void): Promise<void> {
        let releaseLock: () => void;
        const acquired = new Promise<void>((resolve) => { releaseLock = resolve; });
        const previousLock = this.chainLock;
        this.chainLock = acquired;
        await previousLock;
        try {
            fn();
        } finally {
            releaseLock!();
        }
    }

    private emitSafe(fn: () => void, context = "callback"): void {
        try {
            fn();
        } catch (e) {
            const error = e instanceof Error ? e : new Error(String(e));

            // ErrorRouter有効時: 分類→ルーティング→アダプタ実行（非同期、non-blocking）
            if (this.errorRouter) {
                this.errorRouter.route(error, context).catch((routeErr) => {
                    console.error("[Sentinel] ErrorRouter.route failed:", routeErr);
                });
            }

            // 既存動作も維持: onErrorコールバック呼出し
            try {
                this.getCallback("onError")?.(error, context);
            } catch (onErrorErr) {
                console.error(`[Sentinel] onError handler threw: ${onErrorErr instanceof Error ? onErrorErr.message : String(onErrorErr)}`);
            }
        }
    }
}
