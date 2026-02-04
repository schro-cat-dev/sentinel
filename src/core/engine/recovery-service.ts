import { WalError } from "../../shared/errors/infra/wal-error";
import {
    IPersistenceLayer,
    IQueueAdapter,
    IRecoveryService,
} from "./i-interfaces";
import { RecoveryStatus } from "./types";

type WalResult<T> =
    | { success: true; value: T }
    | { success: false; error: WalError };

const isSuccess = <T>(
    result: WalResult<T>,
): result is { success: true; value: T } => result.success === true;

const toError = (walError: WalError): Error => {
    const error = new Error(walError.message || "Unknown WAL error");
    error.name = walError.code || "WalError";
    if ("stack" in walError) error.stack = walError.stack as string;
    return error;
};

/**
 * NOTE: 復旧責任のみ責務として担当
 */
export class RecoveryService implements IRecoveryService {
    constructor(
        private persistence: IPersistenceLayer,
        private queue: IQueueAdapter,
    ) {}

    async recoverUnsentLogs(): Promise<RecoveryStatus> {
        const recoverResult = await this.persistence.recover();

        if (!isSuccess(recoverResult)) {
            return {
                recoveredCount: 0,
                truncated: false,
                errors: [toError(recoverResult.error)],
            };
        }

        const pendingLogs = recoverResult.value;
        let recoveredCount = 0;
        const errors: Error[] = [];

        if (pendingLogs.length > 0) {
            for (const log of pendingLogs) {
                try {
                    await this.queue.enqueueWithBackpressure(log);
                    recoveredCount++;
                } catch (err) {
                    errors.push(err as Error);
                }
            }

            // truncateもResult処理が必要なら同様に
            if (
                pendingLogs.length > 0 &&
                recoveredCount === pendingLogs.length
            ) {
                await this.persistence.truncate();
            } else {
                throw new Error("Partial recovery - truncate aborted");
            }
        }

        return {
            recoveredCount,
            truncated:
                pendingLogs.length === 0 ||
                recoveredCount === pendingLogs.length,
            errors: errors.length > 0 ? errors : undefined,
        };
    }
}
