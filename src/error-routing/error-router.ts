import { ErrorClassifier } from "./error-classifier";
import { RoutingEngine } from "./routing-engine";
import type { ErrorRoutingConfig, ClassifiedError, RoutingDecision } from "./types";

/**
 * エラールーティングのオーケストレーター。
 * 分類 → ルール評価 → アダプタ実行 を制御する。
 *
 * 設計制約:
 * - maxRoutingDepth=1: Executor内のエラーはroute()に再投入しない（無限ループ防止）
 * - enabled=false: 何もしない（ゼロオーバーヘッド）
 * - shutdown後: route()は安全に無視
 */
export class ErrorRouter {
    private readonly config: ErrorRoutingConfig;
    private readonly classifier: ErrorClassifier;
    private readonly engine: RoutingEngine;
    private isShutdown = false;
    private routingDepth = 0; // 再帰防止（並行ルーティングは許可）

    constructor(config: ErrorRoutingConfig) {
        this.config = config;
        this.classifier = new ErrorClassifier(config.severityConfig);
        this.engine = new RoutingEngine(config.rules);
    }

    /**
     * エラーをルーティングする（非同期、non-blocking）。
     * 内部エラーはconsole.errorに出力し、決して再帰しない。
     */
    async route(error: Error, context: string, traceId?: string): Promise<void> {
        if (!this.config.enabled || this.isShutdown) return;

        // 再帰防止（depth > 0 = execute()内からの再帰呼出し）。並行ルーティングは許可。
        if (this.routingDepth > 0) {
            console.error(`[Sentinel:ErrorRouter] reentrant route() call blocked: ${ErrorRouter.truncate(error.message)}`);
            return;
        }

        this.routingDepth++;
        try {
            const classified = this.classifier.classify({ error, context, traceId });
            const decisions = this.engine.evaluate(classified);

            await Promise.allSettled(
                decisions.map((d) => this.execute(classified, d)),
            );
        } catch (err) {
            // 最終防壁: route()自体のエラーはconsole.errorで終了。再帰しない。
            const safeMsg = err instanceof Error
                ? err.message.substring(0, 200)
                : "[non-Error thrown]";
            console.error(`[Sentinel:ErrorRouter] routing failed: ${safeMsg}`);
        } finally {
            this.routingDepth--;
        }
    }

    shutdown(): void {
        this.isShutdown = true;
    }

    /** PII漏洩防止のためメッセージを200文字に切り詰める */
    private static truncate(msg: string, maxLen = 200): string {
        return msg.length > maxLen ? msg.substring(0, maxLen) + "..." : msg;
    }

    /**
     * 個別のRoutingDecisionを実行する。
     * エラーはconsole.errorに出力（route()に戻さない = 防壁2）。
     */
    private async execute(error: ClassifiedError, decision: RoutingDecision): Promise<void> {
        try {
            switch (decision.destination) {
                case "audit_sink":
                    await this.config.sinks?.audit?.send(error);
                    break;
                case "dead_letter":
                    await this.config.sinks?.deadLetter?.enqueue(error, decision.metadata ?? {});
                    break;
                case "log":
                    this.config.logger?.info(
                        `[ErrorRouter:log] ${error.kind}: ${error.message}`,
                        { severity: error.severity, traceId: error.meta.traceId ?? null },
                    );
                    break;
                case "task":
                    await Promise.resolve(this.config.onTaskRequest?.({
                        eventName: "ERROR_ESCALATION",
                        actionType: "ESCALATE",
                        description: `[ErrorRouter] ${error.kind}: ${ErrorRouter.truncate(error.message)}`,
                        source: error,
                    }));
                    break;
                case "ai_agent":
                    await Promise.resolve(this.config.onTaskRequest?.({
                        eventName: "ERROR_ESCALATION",
                        actionType: "AI_ANALYZE",
                        description: `[ErrorRouter:AI] ${error.kind}: ${ErrorRouter.truncate(error.message)}`,
                        source: error,
                    }));
                    break;
                case "notification":
                    await Promise.resolve(this.config.onNotification?.(error, decision));
                    break;
            }
        } catch (execErr) {
            // 防壁2: Executor自身のエラーはroute()に戻さない。PII漏洩防止のため200文字に切り詰め。
            const safeMsg = execErr instanceof Error
                ? execErr.message.substring(0, 200)
                : "[non-Error thrown]";
            console.error(`[Sentinel:ErrorRouter] executor failed for ${decision.destination}: ${safeMsg}`);
        }
    }
}
