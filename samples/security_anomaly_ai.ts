/**
 * Sentinel v1 SDK - Security Anomaly Detection
 *
 * このサンプルはセキュリティイベントの検知とタスク自動生成を示します。
 *
 * v1ではAIエージェント実行はGoサーバ側の責務です。
 * TS SDKはイベント検知→タスク生成→ハンドラ呼び出しまでを担当します。
 * 実際のAI分析やSIEM連携はGoサーバまたは外部サービスで実行します。
 */
import { Sentinel, createDefaultConfig, GeneratedTask } from "../src/index";

async function runAnomalyDemo() {
    const dispatchedTasks: GeneratedTask[] = [];

    const sentinel = Sentinel.initialize(
        createDefaultConfig({
            projectName: "security-demo",
            serviceId: "auth-service-01",
            environment: "development",
            masking: {
                enabled: true,
                rules: [{ type: "PII_TYPE", category: "EMAIL" }],
                preserveFields: ["traceId"],
            },
            security: { enableHashChain: true },
            taskRules: [
                {
                    ruleId: "sec-ai-analyze",
                    eventName: "SECURITY_INTRUSION_DETECTED",
                    severity: "HIGH",
                    actionType: "AI_ANALYZE",
                    executionLevel: "AUTO",
                    priority: 1,
                    description: "AI analysis of security intrusion",
                    executionParams: {},
                    guardrails: {
                        requireHumanApproval: false,
                        timeoutMs: 60000,
                        maxRetries: 2,
                    },
                },
                {
                    ruleId: "comp-escalate",
                    eventName: "COMPLIANCE_VIOLATION",
                    severity: "MEDIUM",
                    actionType: "ESCALATE",
                    executionLevel: "MANUAL",
                    priority: 1,
                    description: "Escalate to legal team",
                    executionParams: {
                        notificationChannel: "#legal-compliance",
                    },
                    guardrails: {
                        requireHumanApproval: true,
                        timeoutMs: 86400000,
                        maxRetries: 0,
                    },
                },
            ],
        }),
    );

    // ハンドラ登録
    sentinel.onTaskAction("AI_ANALYZE", (task) => {
        dispatchedTasks.push(task);
        console.log(
            `[AI_ANALYZE] Task ${task.taskId} dispatched (${task.severity})`,
        );
    });

    console.log("--- Scenario: Brute force login attack ---\n");

    // 1. セキュリティイベント → AI分析タスク自動生成
    for (let i = 0; i < 3; i++) {
        const result = await sentinel.ingest({
            type: "SECURITY",
            level: 5,
            message: `Failed login attempt from IP 192.168.10.55 (attempt ${i + 1})`,
            boundary: "AuthService:login",
            tags: [{ key: "ip", category: "192.168.10.55" }],
        });
        console.log(`Log ${i + 1}: tasks=${result.tasksGenerated.length}`);
    }
    console.log(`\nAI tasks dispatched: ${dispatchedTasks.length}`);

    // 2. AI_AGENT ループ防止テスト
    console.log("\n--- AI_AGENT log (loop prevention) ---");
    const aiResult = await sentinel.ingest({
        type: "SECURITY",
        level: 5,
        origin: "AI_AGENT",
        message: "AI analysis complete",
        boundary: "AIAnalyzer",
    });
    console.log(
        `AI log tasks: ${aiResult.tasksGenerated.length} (expected: 0)`,
    );

    // 3. コンプライアンス違反（承認必須）
    console.log("\n--- Compliance violation ---");
    const compResult = await sentinel.ingest({
        type: "COMPLIANCE",
        level: 4,
        message: "Data retention policy violation detected",
        boundary: "DataRetention:audit",
        actorId: "system",
        resourceIds: ["policy-DR-001"],
    });
    for (const task of compResult.tasksGenerated) {
        console.log(`  ${task.ruleId}: ${task.status}`);
    }

    Sentinel.reset();
    console.log("\n--- Demo complete ---");
}

runAnomalyDemo().catch(console.error);
