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

    constructor(deps: {
        config: SentinelConfig;
        normalizer: ILogNormalizer;
        signer: IntegritySigner;
        detector: EventDetector;
        taskGenerator: TaskGenerator;
        taskExecutor: TaskExecutor;
    }) {
        this.config = deps.config;
        this.normalizer = deps.normalizer;
        this.signer = deps.signer;
        this.detector = deps.detector;
        this.taskGenerator = deps.taskGenerator;
        this.taskExecutor = deps.taskExecutor;
    }

    /**
     * 内部状態をリセットする（shutdown時に呼ばれる）
     */
    resetState(): void {
        this.signer.resetChain();
        this.lastProcessedLog = null;
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
            ) as Log;
        }
        return log;
    }

    async handle(raw: Partial<Log>): Promise<IngestionResult> {
        // 1. Normalize (outside lock — stateless, parallelizable)
        let log = this.normalizer.normalize(raw);

        // 2. Mask PII
        let masked = false;
        if (this.config.masking.enabled) {
            log = MaskingService.mask(
                log,
                this.config.masking.rules,
                this.config.masking.preserveFields,
            ) as Log;
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
                this.emitSafe(() => this.config.onTaskGenerated?.(task));
                const result = await this.taskExecutor.dispatch(task);
                this.emitSafe(() => this.config.onTaskDispatched?.(result));
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

        // 6. Callbacks + metrics
        this.emitSafe(() => this.config.onLogProcessed?.(log));
        this.emitSafe(() => this.config.metrics?.onIngest?.());

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
            try {
                this.config.onError?.(error, context);
            } catch (onErrorErr) {
                // onError自体の例外をstderrにfallback出力（完全無視を防ぐ）
                console.error(`[Sentinel] onError handler threw:`, onErrorErr);
            }
        }
    }
}
