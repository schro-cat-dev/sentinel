/**
 * Sentinel v1 SDK - Basic Usage
 *
 * このサンプルはTypeScript Client SDKの基本的な使い方を示します。
 * Go backendサーバなしでローカルでパイプラインを実行できます。
 */
import { Sentinel, createDefaultConfig } from "../src/index";

async function main() {
    // 1. 設定を作成
    const sentinel = Sentinel.initialize(
        createDefaultConfig({
            projectName: "fintech-core-2026",
            serviceId: "payment-gateway-01",
            environment: "development",

            // PII マスキング（クレジットカード番号を自動検出・マスク）
            masking: {
                enabled: true,
                rules: [
                    { type: "PII_TYPE", category: "CREDIT_CARD" },
                    { type: "PII_TYPE", category: "EMAIL" },
                ],
                preserveFields: ["traceId", "spanId"],
            },

            // ハッシュチェーン（改ざん検知）
            security: { enableHashChain: true },

            // タスク自動生成ルール
            taskRules: [
                {
                    ruleId: "crit-notify",
                    eventName: "SYSTEM_CRITICAL_FAILURE",
                    severity: "HIGH",
                    actionType: "SYSTEM_NOTIFICATION",
                    executionLevel: "AUTO",
                    priority: 1,
                    description: "Slack通知: クリティカル障害",
                    executionParams: { notificationChannel: "#incidents" },
                    guardrails: {
                        requireHumanApproval: false,
                        timeoutMs: 30000,
                        maxRetries: 3,
                    },
                },
            ],
        }),
    );

    // 2. タスクアクションのハンドラを登録
    sentinel.onTaskAction("SYSTEM_NOTIFICATION", (task) => {
        console.log(`[Handler] Task dispatched: ${task.taskId}`);
        console.log(`  Rule: ${task.ruleId}`);
        console.log(`  Severity: ${task.severity}`);
        console.log(`  Source: ${task.sourceLog.boundary} - ${task.sourceLog.message}`);
    });

    // 3. 通常のビジネスログ（イベント検知なし）
    const result1 = await sentinel.ingest({
        type: "BUSINESS-AUDIT",
        level: 3,
        message: "User initiated payment: card 4111-1111-1111-1111",
        actorId: "user_99a",
        boundary: "PaymentController",
    });
    console.log("\n--- Normal log ---");
    console.log(`TraceID: ${result1.traceId}`);
    console.log(`Hash chain: ${result1.hashChainValid}`);
    console.log(`Masked: ${result1.masked}`);
    console.log(`Tasks: ${result1.tasksGenerated.length}`);

    // 4. クリティカルログ（タスク自動生成される）
    const result2 = await sentinel.ingest({
        message: "Database connection pool exhausted - all 50 connections in use",
        isCritical: true,
        level: 6,
        boundary: "DatabaseService:connection-pool",
    });
    console.log("\n--- Critical log ---");
    console.log(`TraceID: ${result2.traceId}`);
    console.log(`Tasks generated: ${result2.tasksGenerated.length}`);
    if (result2.tasksGenerated.length > 0) {
        console.log(`  Task status: ${result2.tasksGenerated[0].status}`);
        console.log(`  Rule: ${result2.tasksGenerated[0].ruleId}`);
    }
}

main().catch(console.error);
