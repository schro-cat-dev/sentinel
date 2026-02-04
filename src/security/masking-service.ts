import { MaskingRule } from "../configs/detailed-config";

interface MaskingContext {
    readonly seen: WeakSet<object>;
    depth: number;
    readonly maxDepth: number;
}

export class MaskingService {
    private static readonly PII_PATTERNS: Record<string, RegExp> = {
        CREDIT_CARD: /\b(?:\d[ -]*?){13,19}\b/g,
        PHONE: /(\+81|0)\d{1,4}[- ]?\d{1,4}[- ]?\d{4}/g,
        EMAIL: /[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}/g,
        GOVERNMENT_ID: /\b\d{12}\b/g,
        JAPAN_ACCOUNT: /\d{3}[-]\d{7}|\d{4}[-]\d{7}/g,
        POSTAL_CODE: /(?:〒?\s?)?\d{3}[-]?\d{4}/g,
        DRIVER_LICENSE: /\b[1-9]\d{5,7}[0-9\\*]\d{2,4}\b/g,
        HEALTH_INSURANCE: /[A-Z0-9]{8,10}/g,
    } as const;

    public static mask(
        data: unknown,
        rules: readonly MaskingRule[] = [],
        preserveFields: readonly string[] = [],
        options: { maxDepth?: number; maxArrayLength?: number } = {},
    ): unknown {
        if (data === null || data === undefined) return data;
        if (typeof data !== "object") {
            return typeof data === "string"
                ? MaskingService.maskString(data, rules)
                : data;
        }
        const context: MaskingContext = {
            seen: new WeakSet(),
            depth: 0,
            maxDepth: options.maxDepth ?? 10,
        };
        return MaskingService.maskInternal(
            data,
            rules,
            preserveFields,
            context,
            options,
        );
    }

    private static maskInternal(
        data: object,
        rules: readonly MaskingRule[],
        preserveFields: readonly string[],
        context: MaskingContext,
        options: { maxArrayLength?: number },
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
                    const itemResult = MaskingService.maskInternal(
                        item,
                        rules,
                        preserveFields,
                        { ...context, depth: context.depth }, // 子コンテキスト共有
                        options,
                    );
                    result.push(itemResult);
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

                if (preserveFields.includes(key)) {
                    result[key] = value;
                    continue;
                }

                const keyMatchRule = rules.find(
                    (rule) =>
                        rule.type === "KEY_MATCH" &&
                        rule.sensitiveKeys?.includes(key),
                ) as Extract<MaskingRule, { type: "KEY_MATCH" }> | undefined;

                if (keyMatchRule) {
                    result[key] = keyMatchRule.replacement ?? "[MASKED_KEY]";
                    continue;
                }

                result[key] = MaskingService.maskInternal(
                    value,
                    rules,
                    preserveFields,
                    { ...context, depth: context.depth },
                    options,
                );
            }

            return result;
        } finally {
            context.depth--;
        }
    }

    private static maskString(
        text: string,
        rules: readonly MaskingRule[],
    ): string {
        if (text.length === 0) return text;
        let result = text;

        for (const rule of rules) {
            try {
                switch (rule.type) {
                    case "REGEX": {
                        const globalPattern = new RegExp(
                            rule.pattern.source,
                            "g",
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
                            const safePattern = new RegExp(
                                piiPattern.source,
                                "g",
                            );
                            result = result.replace(
                                safePattern,
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
                console.warn(
                    `Masking rule failed: ${String(rule.type)}`,
                    error,
                );
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
