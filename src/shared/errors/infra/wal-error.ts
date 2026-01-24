// AppErrorMetaだけimport（共通メタデータ用）
import { createIsUnionMember } from "../../utils/seed-to-union-types";
import { AppErrorMeta } from "../app-error";

// NOTE: walで発生したエラー周りはアプリ層で検知・ハンドルするためこちらの層から明示的な変換処理の実装は不適切。実装しないように。

export const WAL_ERROR_KIND = [
    "WalInit",
    "WalWrite",
    "WalRead",
    "WalCrypto",
    "WalDiskFull",
    "WalLock",
    "WalTruncate",
    "WalCorrupted",
    "WalFsync",
] as const;

export type WalErrorKind = (typeof WAL_ERROR_KIND)[number];

// ガードは直接kindフィールドチェック。そもそも使うか不明
export const isWalErrorKind = createIsUnionMember(WAL_ERROR_KIND);

export const isWalError = (e: unknown): e is WalError => {
    return (
        typeof e === "object" &&
        e !== null &&
        "kind" in e &&
        typeof e.kind === "string" &&
        isWalErrorKind(e.kind)
    );
};

export interface WalError {
    readonly kind: WalErrorKind; // fsync失敗
    readonly operation: string;
    readonly walId: string;
    readonly code: string; // WAL専用
    readonly message: string; // WAL専用
    readonly meta: AppErrorMeta; // 共通メタデータのみ
}

// 本ブロック下のファクトリ関数群は wal-manager.ts で利用。
// --- Usage of the factory-funcs under this comment block ---
// ❌ 毎回WALManager内でこれを書く（重複・ミス多発）
// return err({
//   kind: "WalWrite",
//   operation: "append",
//   walId: this.walId,
//   code: "WAL_WRITE_FAILED",
//   message: `WAL[${this.walId}] write failed: append`,
//   meta: { layer: "Repository", context: { walId: this.walId, filePath: this.walFilePath } }
// });

// ✅ ファクトリ1行（構造保証・監査情報自動付与）
// return err(walWriteError("append", this.walId, this.walFilePath));

export const walInitError = (
    walId: string,
    filePath: string,
    meta: AppErrorMeta = { layer: "Repository", httpStatus: 500 },
): WalError => ({
    kind: "WalInit",
    operation: "initialize",
    walId,
    code: "WAL_INIT_FAILED",
    message: `WAL[${walId}] initialization failed`,
    meta: {
        ...meta,
        context: { walId, filePath },
    },
});

export const walWriteError = (
    operation: string,
    walId: string,
    filePath: string,
    meta: AppErrorMeta = { layer: "Repository", httpStatus: 500 },
): WalError => ({
    kind: "WalWrite",
    operation,
    walId,
    code: "WAL_WRITE_FAILED",
    message: `WAL[${walId}] write failed: ${operation}`,
    meta: {
        ...meta,
        operation,
        context: { walId, filePath },
    },
});

export const walReadError = (
    operation: string,
    walId: string,
    filePath: string,
    meta: AppErrorMeta = { layer: "Repository", httpStatus: 500 },
): WalError => ({
    kind: "WalRead",
    operation,
    walId,
    code: "WAL_READ_FAILED",
    message: `WAL[${walId}] read failed during ${operation}`,
    meta: {
        ...meta,
        context: { walId, filePath },
    },
});

export const walCryptoError = (
    operation: string,
    walId: string,
    filePath: string,
    meta: AppErrorMeta = { layer: "Repository", httpStatus: 500 },
): WalError => ({
    kind: "WalCrypto",
    operation,
    walId,
    code: "WAL_CRYPTO_FAILED",
    message: `WAL[${walId}] crypto failed: ${operation}`,
    meta: { ...meta, context: { walId, filePath } },
});

export const walDiskFullError = (
    operation: string,
    walId: string,
    filePath: string,
    meta: AppErrorMeta = { layer: "Repository", httpStatus: 503 },
): WalError => ({
    kind: "WalDiskFull",
    operation,
    walId,
    code: "WAL_DISK_FULL",
    message: `WAL[${walId}] disk full during ${operation}`,
    meta: { ...meta, context: { walId, filePath } },
});

export const walLockError = (
    operation: string,
    walId: string,
    filePath: string,
    meta: AppErrorMeta = { layer: "Repository", httpStatus: 503 },
): WalError => ({
    kind: "WalLock",
    operation,
    walId,
    code: "WAL_LOCK_FAILED",
    message: `WAL[${walId}] lock failed: ${operation}`,
    meta: { ...meta, context: { walId, filePath } },
});

export const walTruncateError = (
    walId: string,
    filePath: string,
    meta: AppErrorMeta = { layer: "Repository", httpStatus: 500 },
): WalError => ({
    kind: "WalTruncate",
    operation: "truncate",
    walId,
    code: "WAL_TRUNCATE_FAILED",
    message: `WAL[${walId}] truncate failed`,
    meta: { ...meta, context: { walId, filePath } },
});

export const walCorruptedError = (
    operation: string,
    walId: string,
    filePath: string,
    details: string,
    meta: AppErrorMeta = { layer: "Repository", httpStatus: 500 },
): WalError => ({
    kind: "WalCorrupted",
    operation,
    walId,
    code: "WAL_CORRUPTED",
    message: `WAL[${walId}] corrupted during ${operation}: ${details}`,
    meta: { ...meta, context: { walId, filePath, details } },
});

export const walFsyncError = (
    operation: string,
    walId: string,
    filePath: string,
    meta: AppErrorMeta = { layer: "Repository", httpStatus: 500 },
): WalError => ({
    kind: "WalFsync",
    operation,
    walId,
    code: "WAL_FSYNC_FAILED",
    message: `WAL[${walId}] fsync failed after ${operation}`,
    meta: { ...meta, context: { walId, filePath } },
});
