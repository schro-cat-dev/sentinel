/**
 * シンプルなサーキットブレーカー (R-4)
 *
 * 連続失敗がしきい値に達するとopen状態に遷移し、
 * cooldown期間中はリクエストを即座に拒否する。
 * cooldown後に1回だけ試行し（half-open）、成功でclosedに戻る。
 */
export interface CircuitBreakerConfig {
    /** open に遷移するまでの連続失敗数（デフォルト: 5） */
    failureThreshold: number;
    /** open 状態の冷却期間（ミリ秒、デフォルト: 30000） */
    cooldownMs: number;
}

export const DEFAULT_CIRCUIT_BREAKER_CONFIG: CircuitBreakerConfig = {
    failureThreshold: 5,
    cooldownMs: 30_000,
};

export type CircuitState = "closed" | "open" | "half-open";

export class CircuitBreaker {
    private state: CircuitState = "closed";
    private consecutiveFailures = 0;
    private openedAt = 0;
    private readonly config: CircuitBreakerConfig;

    constructor(config?: Partial<CircuitBreakerConfig>) {
        this.config = { ...DEFAULT_CIRCUIT_BREAKER_CONFIG, ...config };
    }

    public getState(): CircuitState {
        if (this.state === "open" && Date.now() - this.openedAt >= this.config.cooldownMs) {
            this.state = "half-open";
        }
        return this.state;
    }

    /**
     * リクエスト実行可能か判定。open 中は false。
     */
    public canExecute(): boolean {
        const s = this.getState();
        return s === "closed" || s === "half-open";
    }

    /**
     * 成功を記録。closed に戻す。
     */
    public onSuccess(): void {
        this.consecutiveFailures = 0;
        this.state = "closed";
    }

    /**
     * 失敗を記録。しきい値超過で open に遷移。
     */
    public onFailure(): void {
        this.consecutiveFailures++;
        if (this.consecutiveFailures >= this.config.failureThreshold) {
            this.state = "open";
            this.openedAt = Date.now();
        }
    }

    public reset(): void {
        this.state = "closed";
        this.consecutiveFailures = 0;
        this.openedAt = 0;
    }
}
