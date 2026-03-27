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

    async handle(raw: Partial<Log>): Promise<IngestionResult> {
        // 1. Normalize
        const log = this.normalizer.normalize(raw);

        // 2. Mask PII (if enabled)
        let masked = false;
        if (this.config.masking.enabled) {
            const maskedMessage = MaskingService.mask(
                log.message,
                this.config.masking.rules,
                this.config.masking.preserveFields,
            ) as string;
            log.message = maskedMessage;
            masked = true;
        }

        // 3. Hash-chain (if enabled)
        let hashChainValid = false;
        if (this.config.security.enableHashChain) {
            const previousHash = this.signer.getPreviousHash();
            log.previousHash = previousHash;
            log.hash = IntegritySigner.calculateHash(log, previousHash);
            this.signer.updateChain(log.hash);
            hashChainValid = true;
        }

        // 4. Detect events
        const detection = this.detector.detect(log);

        // 5. Generate + dispatch tasks
        const tasksGenerated: TaskResult[] = [];
        if (detection) {
            const tasks = this.taskGenerator.generate(detection, log);
            for (const task of tasks) {
                const result = await this.taskExecutor.dispatch(task);
                tasksGenerated.push(result);
            }
        }

        // 6. Emit to handlers
        this.config.onLogProcessed?.(log);

        return {
            traceId: log.traceId,
            hashChainValid,
            tasksGenerated,
            masked,
        };
    }
}
