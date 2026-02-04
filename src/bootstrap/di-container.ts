import { DetailedConfig } from "../configs/detailed-config";
import { GlobalConfig } from "../configs/global-config";
import { createIngestionEngine } from "../core/engine/ingestion-engine";
import { WALManager } from "../infrastructure/persistence/wal-manager";
// import { ITaskRepository } from "../intelligence/task/i-task-repository";
// import { SQLTaskRepository } from "../intelligence/task/sql-task-repository";
import { CloudWatchTransport, TransportManager } from "../transport";
import { WorkerPool } from "./worker-pool";

// TODO 仮 + 一旦ここに配置。要修正
interface CloudWatchConfig {
    groupName: string;
    streamName: string;
    region: string;
}

type DependencyKey =
    | "WALManager"
    | "WorkerPool"
    // | "TaskRepository"
    | "IngestionEngine"
    | "TransportManager";

export class DIContainer {
    private instances: Partial<Record<DependencyKey, unknown>> = {};

    constructor(
        private gConfig: GlobalConfig,
        private dConfig: DetailedConfig,
    ) {}

    public async init(): Promise<void> {
        const kmsKeyBuffer = Buffer.alloc(32, 0x01); // TODO: KMSキー生成（仮）してるので、実際のKMSキー取得するように

        // WAL
        const wal = new WALManager(this.gConfig, kmsKeyBuffer);
        await wal.initialize();
        this.instances["WALManager"] = wal;

        // WorkerPool
        const workerPool = new WorkerPool(this.gConfig, this.dConfig);
        await workerPool.boot();
        this.instances["WorkerPool"] = workerPool;

        // TODO TaskRepositoryを現状利用しない形式になっているため確認
        // const taskRepo = this.resolveTaskRepository();
        // this.instances["TaskRepository"] = taskRepo;

        // TransportManager
        const transportManager = new TransportManager();
        // TODO 仮なので疎結合化。DependencyKeyのtypeも含め。
        const cwConfig: CloudWatchConfig = {
            groupName: this.gConfig.serviceId,
            streamName: "sentinel-main",
            region: "ap-northeast-1",
        };
        transportManager.addTransport(new CloudWatchTransport(cwConfig));
        // TODO transportManager.addTransport(...); // → 設定に応じてさらに追加（というか必要分登録モジュールを作って宣言化したほうがよき）
        this.instances["TransportManager"] = transportManager;

        // 5. IngestionEngine（ファクトリ使用）
        this.instances["IngestionEngine"] = createIngestionEngine({
            gConfig: this.gConfig,
            wal,
            workerPool,
            // taskRepo: taskRepo, // 削除済み
        });

        // 6. WorkerPoolとTransportManager連携
        const wp = workerPool as WorkerPool;
        const tm = transportManager as TransportManager;
        wp.on("LOG_PROCESSED", (log) => tm.handleProcessedLog(log));
    }

    // private resolveTaskRepository(): ITaskRepository {
    //     const repoConfig = this.dConfig.intelligence.taskRepository;
    //     switch (repoConfig.provider) {
    //         case "POSTGRES":
    //             return new SQLTaskRepository(repoConfig.connectionConfig);
    //         default:
    //             throw new Error(
    //                 `Unsupported TaskRepository provider: ${repoConfig.provider}`,
    //             );
    //     }
    // }

    public resolve<T>(key: DependencyKey): T {
        const instance = this.instances[key];
        if (!instance) throw new Error(`Dependency not found: ${key}`);
        return instance as T;
    }
}
