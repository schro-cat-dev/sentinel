import { randomUUID } from "node:crypto";
import { Log } from "../../types/log";
import { TaskRule, GeneratedTask, TaskSeverity } from "../../types/task";
import { DetectionResult, SystemEventName } from "../../types/event";
import { SeverityClassifier } from "./severity-classifier";

/**
 * ルールベースのタスク自動生成エンジン
 *
 * Sentinel の独自価値の核: ログ → タスク変換
 *
 * EventDetector が検知したイベント名に紐づくルールを照合し、
 * 実行可能なタスクを生成する。
 */
export class TaskGenerator {
    private readonly ruleIndex: Map<string, TaskRule[]>;
    private readonly severityClassifier: SeverityClassifier;

    constructor(rules: TaskRule[]) {
        this.severityClassifier = new SeverityClassifier();
        this.ruleIndex = TaskGenerator.buildIndex(rules);
    }

    /**
     * 検知結果とログからタスクを生成
     */
    public generate(
        detection: DetectionResult<SystemEventName>,
        log: Log,
    ): GeneratedTask[] {
        const matchedRules = this.ruleIndex.get(detection.eventName) ?? [];

        if (matchedRules.length === 0) {
            return [];
        }

        const severity = this.severityClassifier.classify(detection, log);

        return matchedRules
            .filter((rule) => this.matchesSeverityThreshold(rule, severity))
            .sort((a, b) => a.priority - b.priority)
            .map((rule) => this.createTask(rule, detection, log, severity));
    }

    /**
     * ルールの登録数を取得
     */
    public getRuleCount(): number {
        let count = 0;
        for (const rules of this.ruleIndex.values()) {
            count += rules.length;
        }
        return count;
    }

    /**
     * イベント名に紐づくルールを取得
     */
    public getRulesForEvent(eventName: string): TaskRule[] {
        return this.ruleIndex.get(eventName) ?? [];
    }

    private matchesSeverityThreshold(rule: TaskRule, actualSeverity: TaskSeverity): boolean {
        const severityOrder = ["INFO", "LOW", "MEDIUM", "HIGH", "CRITICAL"];
        const ruleIdx = severityOrder.indexOf(rule.severity);
        const actualIdx = severityOrder.indexOf(actualSeverity);
        // 未知のseverity（-1）はマッチしない
        if (ruleIdx === -1 || actualIdx === -1) return false;
        // ルールの重大度以上の場合にマッチ
        return actualIdx >= ruleIdx;
    }

    private createTask(
        rule: TaskRule,
        detection: DetectionResult<SystemEventName>,
        log: Log,
        severity: TaskSeverity,
    ): GeneratedTask {
        return {
            taskId: randomUUID(),
            ruleId: rule.ruleId,
            eventName: detection.eventName,
            severity,
            actionType: rule.actionType,
            executionLevel: rule.executionLevel,
            priority: rule.priority,
            description: rule.description,
            // サニタイズ済み（buildIndex時に __proto__/constructor 除去済み）
            executionParams: rule.executionParams,
            guardrails: rule.guardrails,
            sourceLog: {
                traceId: log.traceId,
                message: log.message,
                boundary: log.boundary,
                level: log.level,
                timestamp: log.timestamp,
            },
            createdAt: new Date().toISOString(),
        };
    }

    /** prototype pollution 防御: __proto__/constructor キーを初期化時に除去 */
    private static sanitizeRule(rule: TaskRule): TaskRule {
        return {
            ...rule,
            executionParams: TaskGenerator.filterProtoKeys(rule.executionParams) as typeof rule.executionParams,
            guardrails: TaskGenerator.filterProtoKeys(rule.guardrails) as typeof rule.guardrails,
        };
    }

    private static filterProtoKeys<T extends object>(obj: T): T {
        return Object.fromEntries(
            Object.entries(obj).filter(([k]) => k !== "__proto__" && k !== "constructor"),
        ) as T;
    }

    private static buildIndex(rules: TaskRule[]): Map<string, TaskRule[]> {
        const index = new Map<string, TaskRule[]>();
        for (const rule of rules) {
            const sanitized = TaskGenerator.sanitizeRule(rule);
            const existing = index.get(sanitized.eventName) ?? [];
            existing.push(sanitized);
            index.set(sanitized.eventName, existing);
        }
        return index;
    }
}
