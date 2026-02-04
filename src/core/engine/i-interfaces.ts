import { Log } from "../../types/log";
import { Result } from "../../shared/functional/result";
import { RecoveryStatus, IngestionResult } from "./types";
import { WalError } from "../../shared/errors/infra/wal-error";

export interface IIngestionCoordinator {
    handle(raw: Partial<Log>): Promise<IngestionResult>;
}

export interface ILoggerNormalizer {
    normalize(raw: Partial<Log>): Log;
}

export interface IPersistenceLayer {
    append(log: Log): Promise<void>;
    recover(): Promise<Result<Log[], WalError>>;
    truncate(): Promise<void>;
}

export interface IQueueAdapter {
    enqueueWithBackpressure(log: Log): Promise<void>;
    isFull(): boolean;
}

export interface IRecoveryService {
    recoverUnsentLogs(): Promise<RecoveryStatus>;
}
