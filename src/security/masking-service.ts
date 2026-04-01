import { MaskingRule } from "../configs/masking-rule";
import type { SentinelLogger } from "../configs/sentinel-config";

interface MaskingContext {
    readonly seen: WeakSet<object>;
    depth: number;
    readonly maxDepth: number;
}

export class MaskingService {
    private static readonly PII_PATTERNS: Record<string, RegExp> = {
        CREDIT_CARD: /\b\d{4}[\s-]?\d{4}[\s-]?\d{4}[\s-]?\d{1,7}\b/g,
        PHONE: /(\+81|0)[- ]?\d{1,4}[- ]?\d{1,4}[- ]?\d{4}/g,
        EMAIL: /[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}/g,
        GOVERNMENT_ID: /\b\d{12}\b/g,
        JAPAN_ACCOUNT: /\d{3}[-]\d{7}|\d{4}[-]\d{7}/g,
        POSTAL_CODE: /(?:〒?\s?)?\d{3}[-]?\d{4}/g,
        DRIVER_LICENSE: /\b[1-9]\d{5,7}[0-9\\*]\d{2,4}\b/g,
        HEALTH_INSURANCE: /\b\d{2}\s?\d{2}\s?\d{6}\b/g,
    } as const;

    /**
     * データ構造を再帰的にマスキングする。
     * 入力と同じ構造を返す（ジェネリクスで呼び出し側のキャスト不要）。
     * 内部的にはunknownを経由するが、構造を保持するため型パラメータTで返す。
     */
    public static mask<T>(
        data: T,
        rules: readonly MaskingRule[] = [],
        preserveFields: readonly string[] = [],
        options: { maxDepth?: number; maxArrayLength?: number; logger?: SentinelLogger } = {},
    ): T {
        return MaskingService.maskValue(data, rules, preserveFields, options) as T;
    }

    private static maskValue(
        data: unknown,
        rules: readonly MaskingRule[],
        preserveFields: readonly string[],
        options: { maxDepth?: number; maxArrayLength?: number; logger?: SentinelLogger },
    ): unknown {
        if (data === null || data === undefined) return data;
        if (typeof data !== "object") {
            return typeof data === "string"
                ? MaskingService.maskString(data, rules, options.logger)
                : data;
        }
        const context: MaskingContext = {
            seen: new WeakSet(),
            depth: 0,
            maxDepth: options.maxDepth ?? 10,
        };
        const preserveSet = new Set(preserveFields);
        return MaskingService.maskInternal(
            data,
            rules,
            preserveSet,
            context,
            options,
        );
    }

    private static maskInternal(
        data: object,
        rules: readonly MaskingRule[],
        preserveFields: ReadonlySet<string>,
        context: MaskingContext,
        options: { maxArrayLength?: number; logger?: SentinelLogger },
    ): unknown {
        if (context.depth >= context.maxDepth || context.seen.has(data)) {
            return "[CIRCULAR_REFERENCE_OR_TOO_DEEP]";
        }

        context.seen.add(data);
        context.depth++;

        try {
            if (Array.isArray(data)) {
                const maxLength = options.maxArrayLength ?? 50;
                const result: unknown[] = [];
                for (let i = 0; i < Math.min(data.length, maxLength); i++) {
                    const item = data[i];
                    if (item === null || item === undefined) {
                        result.push(item);
                    } else if (typeof item === "string") {
                        result.push(MaskingService.maskString(item, rules, options.logger));
                    } else if (typeof item === "object") {
                        result.push(
                            MaskingService.maskInternal(
                                item,
                                rules,
                                preserveFields,
                                context,
                                options,
                            ),
                        );
                    } else {
                        result.push(item);
                    }
                }
                return result;
            }

            const obj = data as Record<string, unknown>;
            const result: Record<string, unknown> = {};

            for (const key in obj) {
                if (!Object.prototype.hasOwnProperty.call(obj, key)) continue;

                const value = obj[key];
                if (value === null || value === undefined) {
                    result[key] = value;
                    continue;
                }

                if (preserveFields.has(key)) {
                    result[key] = value;
                    continue;
                }

                const lowerKey = key.toLowerCase();
                const keyMatchRule = rules.find(
                    (rule) =>
                        rule.type === "KEY_MATCH" &&
                        rule.sensitiveKeys?.some(
                            (sk) => sk.toLowerCase() === lowerKey,
                        ),
                ) as Extract<MaskingRule, { type: "KEY_MATCH" }> | undefined;

                if (keyMatchRule) {
                    result[key] = keyMatchRule.replacement ?? "[MASKED_KEY]";
                    continue;
                }

                if (typeof value === "string") {
                    result[key] = MaskingService.maskString(value, rules, options.logger);
                } else if (typeof value === "object") {
                    result[key] = MaskingService.maskInternal(
                        value,
                        rules,
                        preserveFields,
                        context,
                        options,
                    );
                } else {
                    result[key] = value;
                }
            }

            return result;
        } finally {
            context.depth--;
        }
    }

    private static maskString(
        text: string,
        rules: readonly MaskingRule[],
        logger?: SentinelLogger,
    ): string {
        if (text.length === 0) return text;
        let result = text;

        for (const rule of rules) {
            try {
                switch (rule.type) {
                    case "REGEX": {
                        // 元のフラグを保持しつつ、gフラグを追加（replaceAllに必要）
                        const originalFlags = rule.pattern.flags.replace(/[gy]/g, "");
                        const globalPattern = new RegExp(
                            rule.pattern.source,
                            originalFlags + "g",
                        );
                        result = result.replace(
                            globalPattern,
                            rule.replacement,
                        );
                        break;
                    }
                    case "PII_TYPE": {
                        const piiPattern = MaskingService.getPiiPattern(
                            rule.category,
                        );
                        if (piiPattern) {
                            piiPattern.lastIndex = 0;
                            result = result.replace(
                                piiPattern,
                                `[MASKED_${rule.category}]`,
                            );
                        }
                        break;
                    }
                    case "KEY_MATCH":
                        break;
                    default:
                        break;
                }
            } catch (error) {
                logger?.warn(`Masking rule failed: ${String(rule.type)}`);
                continue;
            }
        }
        return result;
    }

    private static getPiiPattern(category: string): RegExp | undefined {
        return (MaskingService.PII_PATTERNS as Record<string, RegExp>)[
            category
        ];
    }
}
