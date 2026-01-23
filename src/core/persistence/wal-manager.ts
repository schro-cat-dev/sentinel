import { appendFile, mkdir, readFile, writeFile } from "fs/promises";
import { join } from "path";
import { createCipheriv, createDecipheriv, randomBytes } from "crypto";
import { GlobalConfig } from "../../configs/global-config";
import { Log } from "../../types/log";

export class WALManager {
    private walFilePath: string;
    // TODO 本来は KMS や環境変数から取得すべき 32バイトの鍵
    private readonly encryptionKey = Buffer.alloc(
        32,
        "secure-key-national-project-2026",
    );

    constructor(private gConfig: GlobalConfig) {
        this.walFilePath = join(
            this.gConfig.persistence.bufferDirectory,
            `wal-${this.gConfig.serviceId}.log`,
        );
    }

    public async initialize(): Promise<void> {
        try {
            await mkdir(this.gConfig.persistence.bufferDirectory, {
                recursive: true,
            });
            // 起動時にファイルが存在しなければ作成（touch）
            await appendFile(this.walFilePath, "");
        } catch (error) {
            throw new Error(`Failed to initialize WAL: ${String(error)}`);
        }
    }

    public async append(log: Log): Promise<void> {
        const data = JSON.stringify(log) + "\n";

        // 暗号化設定がある場合、ここで暗号化してから書き込む
        const payload = this.gConfig.security.encryptionAtRest
            ? this.encrypt(data)
            : data;

        try {
            await appendFile(this.walFilePath, payload, { flag: "a" });
        } catch (error) {
            console.error(
                "[WALManager] Critical Failure: Could not write to disk.",
                error,
            );
            // 金融グレードではここでプロセスを落とす、あるいは代替ストレージに切り替える判断が必要
            //   throw new Error(`[WALManager] Critical write failure: ${String(error)}`);
        }
    }

    private encrypt(data: string): string {
        // 実際の実装ではKMS等から鍵を取得する
        const key = Buffer.alloc(32, "secure-key-placeholder");
        const iv = randomBytes(16);
        const cipher = createCipheriv("aes-256-cbc", key, iv);
        let encrypted = cipher.update(data, "utf8", "hex");
        encrypted += cipher.final("hex");
        return `${iv.toString("hex")}:${encrypted}\n`;
    }

    private decrypt(encryptedLine: string): string {
        const [ivHex, data] = encryptedLine.split(":");
        if (!ivHex || !data) throw new Error("Invalid encrypted format");

        const iv = Buffer.from(ivHex, "hex");
        const decipher = createDecipheriv(
            "aes-256-cbc",
            this.encryptionKey,
            iv,
        );
        let decrypted = decipher.update(data, "hex", "utf8");
        decrypted += decipher.final("utf8");
        return decrypted;
    }

    /**
     * クラッシュリカバリ：未送信ログの全抽出
     */
    public async recover(): Promise<Log[]> {
        try {
            const content = await readFile(this.walFilePath, "utf8");
            if (!content.trim()) return [];

            const lines = content.split("\n").filter((l) => l.trim() !== "");
            const recoveredLogs: Log[] = [];

            for (const line of lines) {
                try {
                    const decrypted = this.gConfig.security.encryptionAtRest
                        ? this.decrypt(line)
                        : line;
                    const log = JSON.parse(decrypted) as Log;
                    recoveredLogs.push(log);
                } catch (e) {
                    console.error(
                        "[WALManager] Corrupted log line skipped during recovery",
                        e,
                    );
                }
            }
            return recoveredLogs;
        } catch (error) {
            console.error("[WALManager] Recovery read failed", error);
            return [];
        }
    }

    /**
     * リカバリ完了後のファイル初期化（切り詰め）
     */
    public async truncate(): Promise<void> {
        try {
            // ファイルサイズを0に上書き
            await writeFile(this.walFilePath, "", "utf8");
        } catch (error) {
            console.error("[WALManager] Failed to truncate WAL file", error);
        }
    }
}
