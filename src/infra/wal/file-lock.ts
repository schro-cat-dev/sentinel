import { open, unlink, FileHandle } from "fs/promises";
import { Result, safe, mapError, ok } from "../../shared/functional/result";
import { walLockError, WalError } from "../../shared/errors/infra/wal-error";
import { ErrorMeta } from "../../shared/errors/error-payload-protocol";

export class FileLock {
    private lockHandle: FileHandle | null = null;

    constructor(
        private readonly lockFilePath: string,
        private readonly walId: string,
    ) {}

    public async acquire(): Promise<Result<void, WalError>> {
        const result = await safe(async () => {
            this.lockHandle = await open(this.lockFilePath, "wx");
            await this.lockHandle.write(`${process.pid}:${Date.now()}`);
            await this.lockHandle.sync();
        }, {});
        return mapError(result, (e: unknown) =>
            walLockError("acquire", this.walId, this.lockFilePath, {
                originalError: e,
            } as ErrorMeta),
        );
    }

    public async release(): Promise<Result<void, WalError>> {
        if (!this.lockHandle) return ok(undefined);

        const result = await safe(async () => {
            await this.lockHandle!.close();
            await unlink(this.lockFilePath);
        }, {});

        this.lockHandle = null; // 常に状態リセット（finally相当）
        return mapError(result, (e: unknown) =>
            walLockError("release", this.walId, this.lockFilePath, {
                originalError: e,
            } as ErrorMeta),
        );
    }
}
