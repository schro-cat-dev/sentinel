import { WalError } from "../../shared/errors/infra/wal-error";
import { Result } from "../../shared/functional/result";
import { Log } from "../../types/log";
import { WALManager } from "../../infrastructure/persistence/wal-manager";
import { IPersistenceLayer } from "./i-interfaces";

export class PersistenceLayer implements IPersistenceLayer {
    constructor(
        private wal: WALManager,
        private persistenceEnabled: boolean = true,
    ) {}

    async append(log: Log): Promise<void> {
        if (!this.persistenceEnabled) return;
        await this.wal.append(log);
    }

    async recover(): Promise<Result<Log[], WalError>> {
        return await this.wal.recover();
    }

    async truncate(): Promise<void> {
        await this.wal.truncate();
    }
}
