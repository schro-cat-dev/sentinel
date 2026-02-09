// TODO wal-manager, atomic-file, file-lockなどから移行。以下のコメントアウトはきちんとした実装に置き換え。i-wal-repository連携。

// import * as fs from "fs/promises";
// import * as crypto from "crypto";
// import path from "path";
// import { pipeline } from "stream/promise";
// import { ErrorMeta } from "../../shared/errors/app-error";
// import {
//     WalError,
//     walWriteError,
//     walInitError,
// } from "../../shared/errors/wal-error";
// import { safe, mapError, Result } from "../../shared/functional/result";
// import { logFinancialError } from "../../shared/utils/error-utils";
// import { WalWriteInput, WalRepository } from "./WalRepository";

// const WAL_FILE_PREFIX = "wal-";
// const WAL_MAX_SIZE = 100 * 1024 * 1024; // 100MB
// const WAL_SYNC_INTERVAL = 1000; // 1秒
// const MAX_WAL_FILES = 10;

// export class WalRepositoryImpl implements WalRepository {
//     private walDir: string;
//     private currentWalFile: string | null = null;
//     private writeBuffer = new Map<string, Buffer>();
//     private lastSync = 0;
//     private fileHandle: fs.FileHandle | null = null;

//     constructor(walDir: string) {
//         this.walDir = path.resolve(walDir);
//     }

//     private async ensureWalDir(): Promise<Result<void, WalError>> {
//         return safe(
//             async () => {
//                 await fs.mkdir(this.walDir, { recursive: true });
//             },
//             { retries: 1 },
//         ).then(
//             mapError((error) =>
//                 walInitError("WAL_DIR_CREATE_FAILED", {
//                     layer: "Repository",
//                     httpStatus: 500,
//                     context: { dirPathLength: this.walDir.length },
//                 }),
//             ),
//         );
//     }

//     private async getCurrentWalFile(): Promise<Result<string, WalError>> {
//         if (this.currentWalFile) {
//             return ok(this.currentWalFile);
//         }

//         return safe(
//             async () => {
//                 const timestamp = Date.now();
//                 const files = await fs.readdir(this.walDir);
//                 const walFiles = files
//                     .filter((f) => f.startsWith(WAL_FILE_PREFIX))
//                     .map((f) =>
//                         parseInt(f.replace(WAL_FILE_PREFIX, "").split(".")[0]),
//                     )
//                     .sort((a, b) => b - a);

//                 if (walFiles.length > 0) {
//                     this.currentWalFile = path.join(
//                         this.walDir,
//                         `${WAL_FILE_PREFIX}${walFiles[0]}.wal`,
//                     );
//                     return this.currentWalFile;
//                 }

//                 // 新規WALファイル作成
//                 const newWalFile = path.join(
//                     this.walDir,
//                     `${WAL_FILE_PREFIX}${timestamp}.wal`,
//                 );
//                 await fs.writeFile(newWalFile, Buffer.alloc(0));
//                 this.currentWalFile = newWalFile;
//                 return newWalFile;
//             },
//             { retries: 2 },
//         ).then(
//             mapError((error) =>
//                 walWriteError(
//                     "rotate",
//                     "WAL_FILE_INIT",
//                     0,
//                     "file_creation_failed",
//                     {
//                         layer: "Repository",
//                         httpStatus: 500,
//                         context: { walDirLength: this.walDir.length },
//                     },
//                 ),
//             ),
//         );
//     }

//     private async checkWalSize(
//         filePath: string,
//     ): Promise<Result<void, WalError>> {
//         return safe(
//             async () => {
//                 const stats = await fs.stat(filePath);
//                 if (stats.size > WAL_MAX_SIZE) {
//                     throw new Error("WAL_EXCEEDED_MAX_SIZE");
//                 }
//             },
//             { retries: 0 },
//         ).then(
//             mapError((error) =>
//                 walWriteError(
//                     "check_size",
//                     "WAL_SIZE_CHECK",
//                     0,
//                     "size_exceeded",
//                     {
//                         layer: "Repository",
//                         httpStatus: 503,
//                         context: { maxSize: WAL_MAX_SIZE },
//                     },
//                 ),
//             ),
//         );
//     }

//     private async rotateWal(): Promise<Result<string, WalError>> {
//         const oldFile = this.currentWalFile;
//         this.currentWalFile = null;
//         this.writeBuffer.clear();

//         // 古いファイル数チェック
//         return safe(
//             async () => {
//                 const files = await fs.readdir(this.walDir);
//                 const walFiles = files.filter((f) =>
//                     f.startsWith(WAL_FILE_PREFIX),
//                 );

//                 if (walFiles.length > MAX_WAL_FILES) {
//                     const sortedFiles = walFiles
//                         .map((f) => path.join(this.walDir, f))
//                         .sort(
//                             (a, b) =>
//                                 fs.statSync(a).mtime.getTime() -
//                                 fs.statSync(b).mtime.getTime(),
//                         );

//                     await fs.unlink(sortedFiles[0]);
//                 }
//             },
//             { retries: 1 },
//         )
//             .then(() => this.getCurrentWalFile())
//             .then(
//                 mapError((error) =>
//                     walWriteError(
//                         "rotate",
//                         "WAL_ROTATION",
//                         0,
//                         "rotation_failed",
//                         { layer: "Repository", httpStatus: 500 },
//                     ),
//                 ),
//             );
//     }

//     private async syncIfNeeded(): Promise<void> {
//         const now = Date.now();
//         if (now - this.lastSync < WAL_SYNC_INTERVAL) return;

//         if (this.fileHandle) {
//             await this.fileHandle.sync();
//             this.lastSync = now;
//         }
//     }

//     async write(input: WalWriteInput): Promise<Result<void, WalError>> {
//         const { transactionId, dataSize, cause } = input;

//         return this.ensureWalDir().flatMap(async () => {
//             const walFileResult = await this.getCurrentWalFile();
//             if (!walFileResult.success) return walFileResult;

//             const walFile = walFileResult.value;
//             return this.checkWalSize(walFile).flatMap(async () => {
//                 // トランザクションエントリ作成
//                 const entry = this.createWalEntry(transactionId, input);

//                 return safe(
//                     async () => {
//                         await this.syncIfNeeded();

//                         if (!this.fileHandle) {
//                             this.fileHandle = await fs.open(walFile, "a");
//                         }

//                         const offset = await this.fileHandle!.size();
//                         await this.fileHandle!.write(
//                             entry,
//                             0,
//                             entry.length,
//                             offset,
//                         );

//                         // バッファにも保持（クラッシュ回復用）
//                         this.writeBuffer.set(transactionId, entry);

//                         return undefined;
//                     },
//                     {
//                         retries: 2,
//                         notify: (e) => logFinancialError(e as WalError),
//                     },
//                 ).then(
//                     mapError((error) =>
//                         walWriteError(
//                             "append",
//                             transactionId,
//                             dataSize,
//                             cause ?? extractCause(error),
//                             {
//                                 layer: "Repository",
//                                 entityId: transactionId,
//                                 context: {
//                                     dataSize,
//                                     causeCode: cause ?? "unknown",
//                                     offset,
//                                     retries: 0,
//                                 },
//                             },
//                         ),
//                     ),
//                 );
//             });
//         });
//     }

//     private createWalEntry(
//         transactionId: string,
//         input: WalWriteInput,
//     ): Buffer {
//         const timestamp = Date.now();
//         const header = Buffer.alloc(32);

//         // ヘッダー形式: [timestamp:8][txIdLen:4][dataSize:4][checksum:16]
//         header.writeBigInt64LE(BigInt(timestamp), 0);
//         header.writeInt32LE(transactionId.length, 8);
//         header.writeInt32LE(input.dataSize, 12);

//         const checksum = crypto
//             .createHash("sha256")
//             .update(transactionId + timestamp.toString())
//             .digest();
//         checksum.copy(header, 16);

//         const txIdBuffer = Buffer.from(transactionId);
//         const dataBuffer = Buffer.alloc(input.dataSize);
//         // input.dataをdataBufferに書き込み（実装省略）

//         return Buffer.concat([header, txIdBuffer, dataBuffer]);
//     }

//     async initialize(transactionId: string): Promise<Result<void, WalError>> {
//         return safe(
//             async () => {
//                 await this.ensureWalDir();
//                 // 初期化処理（既存WAL回復等）
//                 return undefined;
//             },
//             { retries: 1 },
//         ).then(
//             mapError((error) =>
//                 walInitError(transactionId, {
//                     layer: "Repository",
//                     entityId: transactionId,
//                     httpStatus: 500,
//                 }),
//             ),
//         );
//     }

//     async close(): Promise<void> {
//         if (this.fileHandle) {
//             await this.fileHandle.close();
//             this.fileHandle = null;
//         }
//         this.writeBuffer.clear();
//     }
// }

// // ヘルパー関数
// function extractCause(error: unknown): string {
//     if (error instanceof Error) {
//         if (error.message.includes("EACCES")) return "permission_denied";
//         if (error.message.includes("ENOSPC")) return "disk_full";
//         if (error.message.includes("EAGAIN")) return "resource_exhausted";
//     }
//     return "unknown";
// }
