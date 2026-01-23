import { DetailedConfig } from "../configs/detailed-config";
import { GlobalConfig } from "../configs/global-config";
import { IngestionEngine } from "../core/engine/ingestion-engine";
import { WALManager } from "../core/persistence/wal-manager";
import { ITaskRepository } from "../intelligence/task/i-task-repository";
import { SQLTaskRepository } from "../intelligence/task/sql-task-repository";
import { WorkerPool } from "./worker-pool";

type DependencyKey =
    | "WALManager"
    | "WorkerPool"
    | "TaskRepository"
    | "IngestionEngine";

export class DIContainer {
    private instances: Partial<Record<DependencyKey, unknown>> = {};

    constructor(
        private gConfig: GlobalConfig,
        private dConfig: DetailedConfig,
    ) {}

    public async init(): Promise<void> {
        const wal = new WALManager(this.gConfig);
        await wal.initialize();
        this.instances["WALManager"] = wal;

        const workerPool = new WorkerPool(this.gConfig, this.dConfig);
        await workerPool.boot();
        this.instances["WorkerPool"] = workerPool;

        const taskRepo = this.resolveTaskRepository();
        this.instances["TaskRepository"] = taskRepo;

        const engine = new IngestionEngine(
            this.gConfig,
            wal,
            workerPool,
            taskRepo,
        );
        this.instances["IngestionEngine"] = engine;
    }

    private resolveTaskRepository(): ITaskRepository {
        const repoConfig = this.dConfig.intelligence.taskRepository;
        switch (repoConfig.provider) {
            case "POSTGRES":
                return new SQLTaskRepository(repoConfig.connectionConfig);
            default:
                throw new Error(
                    `Unsupported TaskRepository provider: ${repoConfig.provider}`,
                );
        }
    }

    public resolve<T>(key: DependencyKey): T {
        const instance = this.instances[key];
        if (!instance) throw new Error(`Dependency not found: ${key}`);
        return instance as T;
    }
}
