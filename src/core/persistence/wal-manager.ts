// TODO （後回しにした）スーパークラス化してるので、wal-repositoryと暗号モジュール等、分離。
import { appendFile, mkdir, open, writeFile, stat, readdir } from "fs/promises";
import { join } from "path";
import {
    createCipheriv,
    createDecipheriv,
    randomBytes,
    createHmac,
} from "crypto";
import { GlobalConfig } from "../../configs/global-config";
import { Log, WalEntryRaw } from "../../types/log";
import {
    walInitError,
    walWriteError,
    walReadError,
    walCryptoError,
    walDiskFullError,
    walCorruptedError,
    WalError,
    isWalError,
} from "../../shared/errors/infra/wal-error";
import {
    safe,
    mapError,
    type Result,
    isErr,
    err,
    tryCatch,
    isOk,
} from "../../shared/functional/result";
import { WalEntry as ProtoWalEntry } from "../../generated/src/proto/wal";
import { toProto, fromProto } from "../../infra/wal/wal-mapper";
import { validateWalEntry } from "../../shared/utils/guard-wal-entry-raw";
import { AppErrorMeta } from "../../shared/errors/app-error";
import { FileLock } from "../../infra/wal/file-lock";
import { atomicTruncate } from "../../infra/wal/atomic-file";

/**
 * WALレコードのフォーマット種別
 */
enum RecordMode {
    PLAIN = 0x00,
    ENCRYPTED_AES_256_GCM = 0x01,
}

export interface IWALManager {
    initialize(): Promise<Result<void, WalError>>;
    append(log: Log): Promise<Result<void, WalError>>;
    recover(): Promise<Result<Log[], WalError>>;
    truncate(): Promise<Result<void, WalError>>;
    dispose(): Promise<Result<void, WalError>>;
}

export class WALManager implements IWALManager {
    private walFilePath: string;
    private lockFilePath: string;
    private sequenceId = 0n;
    private previousHash = "";
    private readonly walId: string;
    private readonly encryptionKey: Buffer;
    private readonly hmacKey: Buffer;
    private fileLock: FileLock;

    // WALManager クラス上部に追加
    private static readonly HEADER_SIZE = 5;
    private static readonly GCM_IV_SIZE = 12;
    private static readonly GCM_TAG_SIZE = 16;
    private static readonly HMAC_SIZE = 32;
    private static readonly MIN_ENCRYPTED_PAYLOAD_SIZE = 60; // IV+TAG+最小暗号文

    constructor(
        private gConfig: GlobalConfig,
        kmsKeyBuffer: Buffer,
    ) {
        this.walId = gConfig.serviceId;
        this.walFilePath = join(
            this.gConfig.persistence.bufferDirectory,
            `wal-${this.walId}.wal`,
        );

        this.lockFilePath = `${this.walFilePath}.lock`;
        this.fileLock = new FileLock(this.lockFilePath, this.walId);

        const keyResult = this.validateKMSKey(kmsKeyBuffer);
        if (isErr(keyResult)) {
            throw keyResult.error;
        }

        this.encryptionKey = kmsKeyBuffer.subarray(0, 32);
        this.hmacKey = kmsKeyBuffer.subarray(0, 32);
    }

    /**
     * KMSキーの健全性チェック
     */
    private validateKMSKey(kmsKeyBuffer: Buffer): Result<void, WalError> {
        if (kmsKeyBuffer.length !== 32) {
            return err(
                walCryptoError("validateKMSKey", this.walId, this.walFilePath, {
                    reason: "Invalid key length",
                } as AppErrorMeta),
            );
        }

        // 本鍵からテスト用派生鍵を生成
        const testEncryptionKey = createHmac("sha256", kmsKeyBuffer)
            .update("wal-test-encryption-key-derivation")
            .digest()
            .subarray(0, 32);
        const testHmacKey = createHmac("sha256", kmsKeyBuffer)
            .update("wal-test-hmac-key-derivation")
            .digest()
            .subarray(0, 32);

        return tryCatch(
            () => {
                const testData = Buffer.from("integrity-check");
                // テスト鍵で暗号化
                const encRes = this.encryptBufferWithKeys(
                    testData,
                    RecordMode.ENCRYPTED_AES_256_GCM,
                    testEncryptionKey,
                    testHmacKey,
                );
                if (isErr(encRes)) throw encRes.error;

                // テスト鍵で復号
                const decRes = this.decryptBufferWithKeys(
                    encRes.value,
                    RecordMode.ENCRYPTED_AES_256_GCM,
                    testEncryptionKey,
                    testHmacKey,
                );
                if (isErr(decRes)) throw decRes.error;

                if (!decRes.value.equals(testData)) {
                    throw new Error("Test key decryption result mismatch");
                }
            },
            (e) =>
                walCryptoError("validateKMSKey", this.walId, this.walFilePath, {
                    originalError: e,
                } as AppErrorMeta),
        );
    }

    /**
     * テスト用：任意の鍵で暗号化（本番鍵汚染防止）
     */
    private encryptBufferWithKeys(
        data: Buffer,
        mode: RecordMode,
        encryptionKey: Buffer,
        hmacKey: Buffer,
    ): Result<Buffer, WalError> {
        return tryCatch(
            () => {
                if (mode === RecordMode.PLAIN) {
                    return data;
                }

                const iv = randomBytes(12);
                const cipher = createCipheriv("aes-256-gcm", encryptionKey, iv);

                const ciphertext = Buffer.concat([
                    cipher.update(data),
                    cipher.final(),
                ]);
                const authTag = cipher.getAuthTag();

                const bundle = Buffer.concat([iv, authTag, ciphertext]);

                const hmac = createHmac("sha256", hmacKey)
                    .update(bundle)
                    .digest();

                return Buffer.concat([hmac, bundle]);
            },
            (e) =>
                walCryptoError(
                    "encryptBufferWithKeys",
                    this.walId,
                    this.walFilePath,
                    {
                        originalError: e,
                    } as AppErrorMeta,
                ),
        );
    }

    /**
     * テスト用：任意の鍵で復号（本番鍵汚染防止）
     */
    private decryptBufferWithKeys(
        payload: Buffer,
        mode: RecordMode,
        encryptionKey: Buffer,
        hmacKey: Buffer,
    ): Result<Buffer, WalError> {
        return tryCatch(
            () => {
                if (mode === RecordMode.PLAIN) {
                    return payload;
                }

                if (mode !== RecordMode.ENCRYPTED_AES_256_GCM) {
                    throw new Error(`Unknown record mode: ${mode}`);
                }

                if (payload.length < WALManager.MIN_ENCRYPTED_PAYLOAD_SIZE) {
                    throw new Error("Payload too short for encrypted record");
                }

                const hmac = payload.subarray(0, WALManager.HMAC_SIZE);
                const bundle = payload.subarray(WALManager.HMAC_SIZE);

                const expectedHmac = createHmac("sha256", hmacKey)
                    .update(bundle)
                    .digest();

                if (!hmac.equals(expectedHmac)) {
                    throw new Error("HMAC verification failed");
                }

                const iv = bundle.subarray(0, WALManager.GCM_IV_SIZE);
                const authTag = bundle.subarray(
                    WALManager.GCM_IV_SIZE,
                    WALManager.GCM_IV_SIZE + WALManager.GCM_TAG_SIZE,
                );
                const ciphertext = bundle.subarray(
                    WALManager.GCM_IV_SIZE + WALManager.GCM_TAG_SIZE,
                );

                const decipher = createDecipheriv(
                    "aes-256-gcm",
                    encryptionKey,
                    iv,
                );
                decipher.setAuthTag(authTag);

                return Buffer.concat([
                    decipher.update(ciphertext),
                    decipher.final(),
                ]);
            },
            (e) =>
                walCryptoError(
                    "decryptBufferWithKeys",
                    this.walId,
                    this.walFilePath,
                    {
                        originalError: e,
                    } as AppErrorMeta,
                ),
        );
    }

    public async initialize(): Promise<Result<void, WalError>> {
        // 初期化は短時間ロックで十分
        const lockRes = await this.fileLock.acquire();
        if (isErr(lockRes)) {
            return mapError(lockRes, (e) =>
                walInitError(this.walId, this.walFilePath, {
                    originalError: e,
                } as AppErrorMeta),
            );
        }

        const initRes = safe(async () => {
            await mkdir(this.gConfig.persistence.bufferDirectory, {
                recursive: true,
            });

            const statRes = await safe(() => stat(this.walFilePath));
            if (
                isErr(statRes) &&
                (statRes.error as NodeJS.ErrnoException).code !== "ENOENT"
            ) {
                throw statRes.error;
            }
            if (isErr(statRes)) {
                await writeFile(this.walFilePath, Buffer.alloc(0));
            }
        }).then((res) =>
            mapError(res, (e) =>
                walInitError(this.walId, this.walFilePath, {
                    originalError: e,
                } as AppErrorMeta),
            ),
        );

        // 初期化完了後、即ロック解放（運用中は別途ロック）
        await this.fileLock.release().catch(console.error);
        return initRes;
    }

    public async append(log: Log): Promise<Result<void, WalError>> {
        // ロック取得（排他制御）
        const lockRes = await this.fileLock.acquire();
        if (isErr(lockRes)) {
            return mapError(lockRes, (e) =>
                walWriteError("append:lock", this.walId, this.walFilePath, {
                    originalError: e,
                } as AppErrorMeta),
            );
        }

        // ディスク容量チェック
        const diskRes = await this.checkDiskSpace();
        if (isErr(diskRes)) {
            this.fileLock
                .release()
                .catch((e) =>
                    console.error(
                        `Failed to release lock after disk check: ${e}`,
                    ),
                );
            return diskRes;
        }

        // シーケンス番号更新
        this.sequenceId++;

        // WALエントリ作成
        const entryRaw: WalEntryRaw = {
            ...log,
            sequenceId: this.sequenceId,
            prevHash: this.previousHash,
        };

        // Protobufシリアライズ
        const encodeRes = tryCatch(
            () => {
                const protoObj = toProto(entryRaw);
                return Buffer.from(ProtoWalEntry.encode(protoObj).finish());
            },
            (e) =>
                walWriteError("append:encode", this.walId, this.walFilePath, {
                    originalError: e,
                } as AppErrorMeta),
        );
        if (isErr(encodeRes)) {
            this.fileLock.release().catch(console.error);
            return encodeRes;
        }
        const dataBuffer = encodeRes.value;

        // ハッシュチェーン更新
        this.previousHash = this.computeHash(dataBuffer);

        // 暗号化モード決定
        const mode = this.gConfig.security.encryptionAtRest
            ? RecordMode.ENCRYPTED_AES_256_GCM
            : RecordMode.PLAIN;

        // 暗号化
        const encryptRes = this.encryptBuffer(dataBuffer, mode);
        if (isErr(encryptRes)) {
            this.fileLock.release().catch(console.error);
            return encryptRes;
        }
        const payload = encryptRes.value;

        // ヘッダー作成（モード1byte + サイズ4byte）
        const header = Buffer.alloc(WALManager.HEADER_SIZE);
        header.writeUInt8(mode, 0);
        header.writeUInt32BE(payload.length, 1);

        // 原子的書き込み
        const writeRes = await safe(async () => {
            await appendFile(
                this.walFilePath,
                Buffer.concat([header, payload]),
            );
        }).then((res) =>
            mapError(res, (e) =>
                walWriteError("append:write", this.walId, this.walFilePath, {
                    originalError: e,
                } as AppErrorMeta),
            ),
        );

        // ロック解放（必ず実行）
        this.fileLock
            .release()
            .catch((e) => console.error(`Failed to release append lock: ${e}`));

        return writeRes;
    }

    public async recover(): Promise<Result<Log[], WalError>> {
        // ロック取得（必須）
        const lockRes = await this.fileLock.acquire();
        if (isErr(lockRes)) {
            return mapError(lockRes, (e) =>
                walReadError("recover:lock", this.walId, this.walFilePath, {
                    originalError: e,
                } as AppErrorMeta),
            );
        }

        try {
            return safe(async () => {
                // ファイル存在確認
                const statRes = await safe(() => stat(this.walFilePath));
                if (isErr(statRes)) return []; // ファイル不存在時は空配列

                // ファイルハンドル取得
                const fileHandle = await open(this.walFilePath, "r");
                try {
                    // ファイルサイズ確認
                    const stats = await fileHandle.stat();
                    if (stats.size === 0) {
                        return []; // 空ファイル
                    }

                    // 一括読み込み（高性能）
                    const buffer = Buffer.alloc(stats.size);
                    await fileHandle.read(buffer, 0, stats.size, 0);

                    // WAL解析
                    const logs: Log[] = [];
                    let position = 0;
                    let expectedSeq = 0n;
                    let isFirstEntry = true;
                    let expectedPrevHash = "";

                    while (position < stats.size) {
                        // ヘッダー長チェック
                        if (stats.size - position < WALManager.HEADER_SIZE) {
                            throw walCorruptedError(
                                "recover",
                                this.walId,
                                this.walFilePath,
                                `Incomplete header at pos ${position}`,
                            );
                        }

                        // ヘッダー解析
                        const mode = buffer[position] as RecordMode;
                        const bodyLength = buffer.readUInt32BE(position + 1);
                        position += WALManager.HEADER_SIZE;

                        // ボディ長チェック
                        if (stats.size - position < bodyLength) {
                            throw walCorruptedError(
                                "recover",
                                this.walId,
                                this.walFilePath,
                                `Incomplete body at pos ${position}: expected ${bodyLength}`,
                            );
                        }

                        // ボディ抽出
                        const bodyBuf = buffer.subarray(
                            position,
                            position + bodyLength,
                        );
                        position += bodyLength;

                        // 復号
                        const decryptRes = this.decryptBuffer(bodyBuf, mode);
                        if (isErr(decryptRes)) {
                            throw decryptRes.error;
                        }

                        // Protobufデシリアライズ
                        const rawObj = fromProto(
                            ProtoWalEntry.decode(decryptRes.value),
                        );

                        // 検証
                        const validateRes = validateWalEntry(rawObj);
                        if (isErr(validateRes)) {
                            throw walCorruptedError(
                                "recover",
                                this.walId,
                                this.walFilePath,
                                `Validation failed: ${validateRes.error.message}`,
                            );
                        }
                        const entry = validateRes.value;

                        // シーケンス整合性検証
                        if (isFirstEntry) {
                            expectedSeq = entry.sequenceId + 1n;
                        } else {
                            if (entry.sequenceId !== expectedSeq) {
                                throw walCorruptedError(
                                    "recover",
                                    this.walId,
                                    this.walFilePath,
                                    `Sequence mismatch: expected ${expectedSeq}, got ${entry.sequenceId}`,
                                );
                            }
                            if (entry.prevHash !== expectedPrevHash) {
                                throw walCorruptedError(
                                    "recover",
                                    this.walId,
                                    this.walFilePath,
                                    `Hash chain broken`,
                                );
                            }
                            expectedSeq++;
                        }

                        // 状態更新
                        expectedPrevHash = this.computeHash(decryptRes.value);
                        this.sequenceId = entry.sequenceId;
                        this.previousHash = expectedPrevHash;
                        isFirstEntry = false;

                        // ログ蓄積
                        logs.push(entry);
                    }

                    return logs;
                } finally {
                    // ファイルハンドル確実閉鎖
                    await fileHandle.close();
                }
            }).then((res) =>
                mapError(res, (e) => {
                    if (isWalError(e)) return e;
                    return walReadError(
                        "recover",
                        this.walId,
                        this.walFilePath,
                        {
                            originalError: e,
                        } as AppErrorMeta,
                    );
                }),
            );
        } finally {
            // ロック確実解放
            await this.fileLock.release().catch((e) => {
                console.error(`Failed to release recover lock: ${e}`);
            });
        }
    }

    public async truncate(): Promise<Result<void, WalError>> {
        const result = await atomicTruncate(this.walFilePath, this.walId);
        if (result.success) {
            // 成功時のみ状態リセット
            this.sequenceId = 0n;
            this.previousHash = "";
        }
        return result;
    }

    /**
     * アプリケーション終了時にロックを解放
     * (DIコンテナの終了フックなどで呼び出し)
     */
    public async dispose(): Promise<Result<void, WalError>> {
        return this.fileLock.release();
    }

    // --- Private Helpers ---

    private async checkDiskSpace(): Promise<Result<void, WalError>> {
        const maxWalSizeBytes =
            (this.gConfig.persistence.maxWalSizeMb ?? 100) * 1024 * 1024;

        return safe(async () => {
            // 1. WALファイルサイズチェック（ファイルが存在する場合のみ）
            const fileStatRes = await safe(() => stat(this.walFilePath));
            if (
                isOk(fileStatRes) &&
                fileStatRes.value.size > maxWalSizeBytes * 0.9
            ) {
                throw new Error(
                    `WAL file too large: ${fileStatRes.value.size}B > ${maxWalSizeBytes * 0.9}B`,
                );
            }

            // 2. ディレクトリ存在確認＋簡易容量チェック
            // Node.js標準APIで完全な空き容量取得は困難なため、保守的チェック
            const dirStatRes = await safe(() =>
                stat(this.gConfig.persistence.bufferDirectory),
            );
            if (isErr(dirStatRes)) {
                // ディレクトリ不存在時は後でmkdirされるためOK
                return;
            }

            // 3. ディレクトリ直下の全ファイル合計サイズで簡易空き容量推定
            // ※厳密なfs.statfs()相当はNode.js標準APIにないため代替実装
            const freeSpaceThreshold = maxWalSizeBytes * 2; // WALの2倍空き必要
            const dirSize = await this.estimateDirectorySize(
                this.gConfig.persistence.bufferDirectory,
            );

            if (dirSize > freeSpaceThreshold) {
                throw new Error(
                    `Buffer directory usage too high: ${dirSize}B > ${freeSpaceThreshold}B threshold`,
                );
            }
        }).then((res) =>
            mapError(res, (e) =>
                walDiskFullError(
                    "checkDiskSpace",
                    this.walId,
                    this.walFilePath,
                    {
                        reason: e.message,
                    } as AppErrorMeta,
                ),
            ),
        );
    }

    private async estimateDirectorySize(dirPath: string): Promise<number> {
        try {
            const entries = await readdir(dirPath, { withFileTypes: true });
            let totalSize = 0;

            for (const entry of entries) {
                const fullPath = join(dirPath, entry.name);
                if (entry.isDirectory()) {
                    totalSize += await this.estimateDirectorySize(fullPath);
                } else {
                    const statRes = await safe(() => stat(fullPath));
                    if (isOk(statRes)) {
                        totalSize += statRes.value.size;
                    }
                }
            }
            return totalSize;
        } catch {
            return 0; // エラー時は保守的に0（チェックスキップ）
        }
    }

    private computeHash(data: Buffer): string {
        return createHmac("sha256", this.hmacKey).update(data).digest("hex");
    }

    private encryptBuffer(
        data: Buffer,
        mode: RecordMode,
    ): Result<Buffer, WalError> {
        return tryCatch(
            () => {
                if (mode === RecordMode.PLAIN) {
                    return data;
                }

                const iv = randomBytes(WALManager.GCM_IV_SIZE);
                const cipher = createCipheriv(
                    "aes-256-gcm",
                    this.encryptionKey,
                    iv,
                );

                const ciphertext = Buffer.concat([
                    cipher.update(data),
                    cipher.final(),
                ]);
                const authTag = cipher.getAuthTag();

                const bundle = Buffer.concat([iv, authTag, ciphertext]);

                const hmac = createHmac("sha256", this.hmacKey)
                    .update(bundle)
                    .digest();

                return Buffer.concat([hmac, bundle]);
            },
            (e) =>
                walCryptoError("encryptBuffer", this.walId, this.walFilePath, {
                    originalError: e,
                } as AppErrorMeta),
        );
    }

    private decryptBuffer(
        payload: Buffer,
        mode: RecordMode,
    ): Result<Buffer, WalError> {
        return tryCatch(
            () => {
                if (mode === RecordMode.PLAIN) return payload;

                if (mode !== RecordMode.ENCRYPTED_AES_256_GCM) {
                    throw new Error(`Unknown record mode: ${mode}`);
                }

                if (payload.length < WALManager.MIN_ENCRYPTED_PAYLOAD_SIZE) {
                    throw new Error("Payload too short for encrypted record");
                }

                const hmac = payload.subarray(0, WALManager.HMAC_SIZE);
                const bundle = payload.subarray(WALManager.HMAC_SIZE);

                const expectedHmac = createHmac("sha256", this.hmacKey)
                    .update(bundle)
                    .digest();
                if (!hmac.equals(expectedHmac)) {
                    throw new Error("HMAC verification failed");
                }

                const iv = bundle.subarray(0, WALManager.GCM_IV_SIZE);
                const authTag = bundle.subarray(
                    WALManager.GCM_IV_SIZE,
                    WALManager.GCM_IV_SIZE + WALManager.GCM_TAG_SIZE,
                );
                const ciphertext = bundle.subarray(
                    WALManager.GCM_IV_SIZE + WALManager.GCM_TAG_SIZE,
                );

                const decipher = createDecipheriv(
                    "aes-256-gcm",
                    this.encryptionKey,
                    iv,
                );
                decipher.setAuthTag(authTag);

                return Buffer.concat([
                    decipher.update(ciphertext),
                    decipher.final(),
                ]);
            },
            (e) =>
                walCryptoError("decryptBuffer", this.walId, this.walFilePath, {
                    originalError: e,
                } as AppErrorMeta),
        );
    }
}
