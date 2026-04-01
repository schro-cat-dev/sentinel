import { MaskingRule } from "../configs/masking-rule";
import { PII_CATEGORIES } from "../configs/masking-rule";
import { getPiiPatternForMasking } from "./pii-patterns";
import type { SentinelLogger } from "../configs/sentinel-config";

interface MaskingContext {
    readonly seen: WeakSet<object>;
    depth: number;
    readonly maxDepth: number;
}

export class MaskingService {
    /** PII パターン（pii-patterns.ts の単一ソースから生成） */
    private static readonly PII_PATTERNS: Record<string, RegExp> = Object.fromEntries(
        PII_CATEGORIES.map((cat) => [cat, getPiiPatternForMasking(cat)]),
    );

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

    /** REDOS-003: ユーザ定義REGEX実行時の入力長上限。これを超える文字列にはREGEXルールを適用しない */
    private static readonly MAX_REGEX_INPUT_LENGTH = 65536;

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
                        // REDOS-003: 入力長ガード — 巨大文字列へのユーザ定義regex実行を回避
                        if (result.length > MaskingService.MAX_REGEX_INPUT_LENGTH) {
                            break;
                        }
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
        return MaskingService.PII_PATTERNS[category];
    }
}
