import { Log } from "../../types/log";
import { MaskingService } from "../../security/masking-service";
import { IntegritySigner } from "../../security/integrity-signer";
import { EventDetector } from "../detection/event-detector";
import { TaskGenerator } from "../task/task-generator";
import { TaskExecutor } from "../task/task-executor";
import { LogNormalizer } from "./log-normalizer";
import { IIngestionCoordinator } from "./i-interfaces";
import { IngestionResult } from "./types";
import { SentinelConfig } from "../../configs/sentinel-config";
import { TaskResult } from "../../types/task";

export class IngestionEngine implements IIngestionCoordinator {
    private readonly normalizer: LogNormalizer;
    private readonly masking: MaskingService;
    private readonly signer: IntegritySigner;
    private readonly detector: EventDetector;
    private readonly taskGenerator: TaskGenerator;
    private readonly taskExecutor: TaskExecutor;
    private readonly config: SentinelConfig;

    // Async mutex: serializes hash chain operations to prevent race conditions (NEW-02)
    private chainLock: Promise<void> = Promise.resolve();

    constructor(deps: {
        config: SentinelConfig;
        normalizer: LogNormalizer;
        masking: MaskingService;
        signer: IntegritySigner;
        detector: EventDetector;
        taskGenerator: TaskGenerator;
        taskExecutor: TaskExecutor;
    }) {
        this.config = deps.config;
        this.normalizer = deps.normalizer;
        this.masking = deps.masking;
        this.signer = deps.signer;
        this.detector = deps.detector;
        this.taskGenerator = deps.taskGenerator;
        this.taskExecutor = deps.taskExecutor;
    }

    /**
     * ログを正規化 + マスキングのみ行う（リモート送信用）
     * NEW-05: transport送信前にマスキングを適用
     */
    normalizeOnly(raw: Partial<Log>): Log {
        const log = this.normalizer.normalize(raw);
        if (this.config.masking.enabled) {
            return MaskingService.mask(
                log,
                this.config.masking.rules,
                this.config.masking.preserveFields,
            ) as Log;
        }
        return log;
    }

    async handle(raw: Partial<Log>): Promise<IngestionResult> {
        // NEW-02: Serialize hash chain operations via async mutex
        let releaseLock: () => void;
        const acquired = new Promise<void>((resolve) => {
            releaseLock = resolve;
        });
        const previousLock = this.chainLock;
        this.chainLock = acquired;
        await previousLock;

        try {
            return await this.handleInternal(raw);
        } finally {
            releaseLock!();
        }
    }

    private async handleInternal(raw: Partial<Log>): Promise<IngestionResult> {
        // 1. Normalize
        let log = this.normalizer.normalize(raw);

        // 2. Mask PII (if enabled) — NEW-03: ログ全体をマスク対象に
        let masked = false;
        if (this.config.masking.enabled) {
            log = MaskingService.mask(
                log,
                this.config.masking.rules,
                this.config.masking.preserveFields,
            ) as Log;
            masked = true;
        }

        // 3. Detect events (before hash chain, so detection uses masked data)
        const detection = this.detector.detect(log);

        // 4. Generate tasks (before hash chain to avoid ghost entries on failure)
        const tasksGenerated: TaskResult[] = [];
        if (detection) {
            const tasks = this.taskGenerator.generate(detection, log);
            for (const task of tasks) {
                const result = await this.taskExecutor.dispatch(task);
                tasksGenerated.push(result);
            }
        }

        // 5. Hash-chain (NEW-08: moved to AFTER side effects to prevent ghost entries)
        let hashChainValid = false;
        if (this.config.security.enableHashChain) {
            const previousHash = this.signer.getPreviousHash();
            log.previousHash = previousHash;
            log.hash = IntegritySigner.calculateHash(log, previousHash);
            this.signer.updateChain(log.hash);
            hashChainValid = true;
        }

        // 6. Emit to handlers (after hash chain, wrapped in try-catch for safety)
        try {
            this.config.onLogProcessed?.(log);
        } catch {
            // Callback errors must not propagate — hash chain is already committed
        }

        return {
            traceId: log.traceId,
            hashChainValid,
            tasksGenerated,
            masked,
        };
    }
}
