// 実行環境との「インターフェース」

import process from "node:process";
import { ServiceInfo, AIAgentProcessorInfo } from "../types/log";
import { GlobalConfig } from "../configs/global-config";

/**
 * 実行環境メタデータを生成するユーティリティ
 * 静的なハードコードを排除し、システム構成に基づいた情報を生成
 */
export class EnvironmentMetadata {
    /**
     * 現在のサービス・インスタンス情報を生成
     * @param gConfig グローバル設定（サービスIDやバージョン取得用）
     */
    public static getServiceInfo(gConfig: GlobalConfig): ServiceInfo {
        return {
            serviceId: gConfig.serviceId,
            instanceId: process.env["HOSTNAME"] ?? "local-development", // 実行時の環境変数から取得
            version: "1.0.0", // プロジェクトのメタデータや環境変数から取得
            deployment: process.env["NODE_ENV"] ?? "development",
            DIContainerRuntime: "di-containerd",
        };
    }

    /**
     * AI推論に使用されたリソース情報をパッケージ化
     * @param gConfig グローバル設定
     */
    public static getProcessorInfo(
        gConfig: GlobalConfig,
    ): AIAgentProcessorInfo {
        return {
            resourceInfo: {
                cpu: {
                    quantity: Number(process.env["CPU_LIMIT"] ?? 1),
                    unit: "vCPU",
                },
                memory: {
                    quantity: Number(process.env["MEMORY_LIMIT_MB"] ?? 512),
                    unit: "MB",
                },
                outerStorage: {
                    quantity: 0,
                    unit: "GB",
                },
                serviceInfo: this.getServiceInfo(gConfig),
            },
        };
    }
}
