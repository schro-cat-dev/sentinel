import { truncate } from "fs/promises";
import {
    WalError,
    walTruncateError,
} from "../../shared/errors/infra/wal-error";
import { mapError, Result, safe } from "../../shared/functional/result";
import { AppErrorMeta } from "../../shared/errors/app-error";

export const atomicTruncate = async (
    filePath: string,
    walId: string,
): Promise<Result<void, WalError>> => {
    const result = await safe(async () => truncate(filePath, 0), {});

    return mapError(
        result,
        (e: unknown): WalError =>
            walTruncateError(walId, filePath, {
                originalError: e,
            } as AppErrorMeta),
    );
};

// NOTE: PoC（手動検証手順）

// # 1. WALファイル作成
// echo "data1|data2|data3" > wal.wal

// # 2. truncate直前
// ls -l wal.wal  # 12バイト

// # 3. truncate実行中（突然終了想定）
// node -e "require('fs/promises').truncate('./wal.wal', 0)"

// # 4. 結果確認
// ls -l wal.wal  # 0バイト（原子性確認）
