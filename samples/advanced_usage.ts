/**
 * Sentinel v2 SDK - Advanced Usage
 *
 * 新機能のデモ:
 * - カスタム検知ルール (detectionRules)
 * - ホワイトリスト検証 (whitelist + extensions)
 * - メトリクスフック (metrics)
 * - トレーシングフック (tracer)
 * - エラールーティング (errorRouting + ConsoleAuditSink)
 * - 動的コールバック更新 (updateCallbacks)
 * - ハンドラのdispose
 */
import { Sentinel, createDefaultConfig, ConsoleAuditSink } from "../src/index";

async function main() {
    // --- メトリクス収集 ---
    const metrics = { ingested: 0, detected: 0, dispatched: 0 };

    // --- トレーシング（OpenTelemetry等に接続可能） ---
    const spans: { op: string; ms: number }[] = [];

    const sentinel = Sentinel.initialize(createDefaultConfig({
        projectName: "fintech-app",
        serviceId: "payment-api",
        environment: "production",

        // PII マスキング（8カテゴリ対応）
        masking: {
            enabled: true,
            rules: [
                { type: "PII_TYPE", category: "CREDIT_CARD" },
                { type: "PII_TYPE", category: "EMAIL" },
                { type: "PII_TYPE", category: "PHONE" },
                { type: "PII_TYPE", category: "JAPAN_ACCOUNT" },
            ],
            preserveFields: ["traceId"],
        },

        security: { enableHashChain: true },

        // カスタム検知ルール（不正アクセスパターン）
        detectionRules: [
            {
                ruleId: "brute-force-login",
                eventName: "SECURITY_INTRUSION_DETECTED",
                priority: "HIGH",
                conditions: {
                    logTypes: ["SECURITY"],
                    minLevel: 4,
                    messagePattern: /failed.*login|brute.*force|authentication.*failed/i,
                },
            },
            {
                ruleId: "data-exfiltration",
                eventName: "COMPLIANCE_VIOLATION",
                priority: "MEDIUM",
                conditions: {
                    logTypes: ["BUSINESS-AUDIT"],
                    messagePattern: /bulk.*export|mass.*download/i,
                },
            },
        ],

        // タスク自動生成ルール
        taskRules: [
            {
                ruleId: "security-alert",
                eventName: "SECURITY_INTRUSION_DETECTED",
                severity: "HIGH",
                actionType: "ESCALATE",
                executionLevel: "AUTO",
                priority: 1,
                description: "セキュリティチームにエスカレート",
                executionParams: { notificationChannel: "#security-critical" },
                guardrails: { requireHumanApproval: false, timeoutMs: 5000, maxRetries: 1 },
            },
        ],

        // ホワイトリスト（strict: 組込み値のみ許可）
        whitelist: { level: "strict" },

        // メトリクスフック
        metrics: {
            onIngest: () => { metrics.ingested++; },
            onDetection: () => { metrics.detected++; },
            onTaskDispatch: () => { metrics.dispatched++; },
        },

        // トレーシングフック
        tracer: {
            onPipelineStart: (ctx) => { console.log(`[Trace] Start: ${ctx.operation} (${ctx.traceId})`); },
            onPipelineEnd: (ctx) => {
                spans.push({ op: ctx.operation, ms: ctx.durationMs });
                console.log(`[Trace] End: ${ctx.operation} (${ctx.durationMs}ms)`);
            },
        },

        // エラールーティング（CRITICAL→タスク+通知+監査ログ）
        errorRouting: {
            enabled: true,
            sinks: { audit: new ConsoleAuditSink() },
            onTaskRequest: (req) => {
                console.log(`[ErrorRoute:Task] ${req.actionType}: ${req.description}`);
            },
            onNotification: (err, decision) => {
                console.log(`[ErrorRoute:Notify] ${decision.action}: ${err.kind} (${err.severity})`);
            },
        },
    }));

    // --- ハンドラ登録（dispose関数で後から解除可能） ---
    const dispose = sentinel.onTaskAction("ESCALATE", (task) => {
        console.log(`\n[Handler] ESCALATE: ${task.description}`);
        console.log(`  Event: ${task.eventName}, Severity: ${task.severity}`);
    });

    // --- ログ投入: 通常ログ ---
    console.log("=== Normal business log ===");
    await sentinel.ingest({
        type: "BUSINESS-AUDIT",
        level: 3,
        message: "Payment processed: card 4111-1111-1111-1111, user alice@example.com",
        actorId: "user_001",
        boundary: "PaymentController:process",
    });

    // --- ログ投入: セキュリティ脅威 ---
    console.log("\n=== Security threat detected ===");
    const result = await sentinel.ingest({
        type: "SECURITY",
        level: 5,
        message: "Brute force attack from 10.0.0.99 — 50 failed login attempts in 60s",
        boundary: "AuthService:login",
        tags: [{ key: "ip", category: "10.0.0.99" }],
    });

    console.log(`Detection: ${result.detection?.eventName ?? "none"}`);
    console.log(`Tasks: ${result.tasksGenerated.length}`);

    // --- 動的コールバック更新 ---
    console.log("\n=== Dynamic callback update ===");
    sentinel.updateCallbacks({
        onLogProcessed: (log) => {
            console.log(`[Updated CB] Processed: ${log.message.substring(0, 40)}...`);
        },
    });
    await sentinel.ingest({ message: "This uses the updated callback", level: 2 });

    // --- ハンドラ解除 ---
    dispose();
    console.log("\n=== Handler disposed ===");

    // --- メトリクスサマリ ---
    console.log("\n=== Metrics ===");
    console.log(`  Ingested: ${metrics.ingested}`);
    console.log(`  Detected: ${metrics.detected}`);
    console.log(`  Dispatched: ${metrics.dispatched}`);
    console.log(`  Spans: ${spans.length}`);

    await sentinel.shutdown();
    console.log("\nShutdown complete.");
}

main().catch(console.error);
