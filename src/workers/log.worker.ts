import { parentPort, workerData } from "node:worker_threads";
import { GlobalConfig } from "../configs/global-config";
import { DetailedConfig } from "../configs/detailed-config";
import { Log } from "../types/log";
import { EventDetector } from "../intelligence/detector/event-detector";
import { MaskingService } from "../security/masking-service";
import { IntegritySigner } from "../security/integrity-signer";
import { WorkerToMainMessage } from "../types/event";

const { gConfig, dConfig } = workerData as {
    gConfig: GlobalConfig;
    dConfig: DetailedConfig;
    workerId: string;
};

// 内部状態：不変性を担保するハッシュチェーンの起点
let previousHash = "0".repeat(64);

parentPort?.on("message", async (message: { type: string; payload: Log }) => {
    if (message.type !== "PROCESS_LOG") return;

    try {
        // 直接書き換えではなく、コピー作成
        const log = { ...message.payload };

        // --- 1. マスキング (PII保護) ---
        if (dConfig.masking.enabled) {
            log.input = MaskingService.mask(
                log.input,
                dConfig.masking.rules,
                dConfig.masking.preserveFields,
            ) as string | number | undefined;
            log.message = MaskingService.mask(
                log.message,
                dConfig.masking.rules,
                dConfig.masking.preserveFields,
            ) as string;
        }

        // --- 2. ハッシュチェーン構築 (改ざん防止) ---
        if (gConfig.security.enableHashChain) {
            log.previousHash = previousHash;
            log.hash = IntegritySigner.calculateHash(log, previousHash);
            previousHash = log.hash;
        }

        // --- 3. 電子署名 (非改ざん証明) ---
        const keyId = gConfig.security.signingKeyId;
        if (keyId && log.hash) {
            // 取得した keyId を引数に渡し、署名を実行
            log.signature = IntegritySigner.sign(log.hash, keyId);
        }

        // --- 4. イベント検知 ---
        const detection = EventDetector.detect(log);
        if (detection) {
            const eventMsg: WorkerToMainMessage = {
                type: "EVENT_DETECTED",
                payload: { detection, originalLog: log },
            };
            parentPort?.postMessage(eventMsg);
        }

        // --- 5. 処理完了通知 ---
        const processedMsg: WorkerToMainMessage = {
            type: "LOG_PROCESSED",
            payload: log,
        };
        parentPort?.postMessage(processedMsg);
    } catch (error) {
        const errMsg: WorkerToMainMessage = {
            type: "ERROR",
            payload: {
                message: "Worker processing failed",
                error: error instanceof Error ? error.message : String(error),
            },
        };
        parentPort?.postMessage(errMsg);
    }
});
