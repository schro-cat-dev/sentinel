import { MaskingRule } from "../configs/detailed-config";

export class MaskingService {
    private static PII_PATTERNS: Record<string, RegExp> = {
        CREDIT_CARD: /\b(?:\d[ -]*?){13,16}\b/g,
        PHONE: /(\+81|0)\d{1,4}[- ]?\d{1,4}[- ]?\d{4}/g,
        EMAIL: /[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}/g,
        GOVERNMENT_ID: /\b\d{12}\b/g,
    };

    /**
     * オブジェクトまたは文字列を再帰的にマスキングする
     */
    public static mask(
        data: unknown,
        rules: MaskingRule[],
        preserveFields: string[],
    ): unknown {
        if (!data) return data;

        // 文字列の場合
        if (typeof data === "string") {
            return this.maskString(data, rules);
        }

        // 配列・オブジェクト以外はそのまま返す
        if (typeof data !== "object") {
            return data;
        }

        // 配列の場合
        if (Array.isArray(data)) {
            return data.map((item) => this.mask(item, rules, preserveFields));
        }

        // オブジェクトの場合
        const maskedObj: Record<string, unknown> = {};
        const obj = data as Record<string, unknown>;

        for (const key in obj) {
            if (preserveFields.includes(key)) {
                maskedObj[key] = obj[key]; // 保護フィールドはそのまま
            } else {
                maskedObj[key] = this.mask(obj[key], rules, preserveFields);
            }
        }

        return maskedObj;
    }

    private static maskString(text: string, rules: MaskingRule[]): string {
        let result = text;
        for (const rule of rules) {
            if (rule.type === "REGEX") {
                result = result.replace(rule.pattern, rule.replacement);
            } else if (rule.type === "PII_TYPE") {
                const pattern = this.PII_PATTERNS[rule.category];
                if (pattern) {
                    result = result.replace(
                        pattern,
                        `[MASKED_${rule.category}]`,
                    );
                }
            }
            // KEY_MATCH はオブジェクト走査時に適用されるためここではスキップ
        }
        return result;
    }
}
