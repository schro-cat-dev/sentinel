import type { WhitelistDefinition, WhitelistExtensions } from "./whitelist-types";
import { ValidationError } from "./log-validator";

/**
 * 複数ドメインのホワイトリストを統合し、フィールド値を検証するレジストリ。
 *
 * 各ドメイン（security, task, privacy）のWhitelistDefinitionを合成し、
 * ユーザー拡張値をマージした上で、O(1) の Set.has() で検証する。
 */
export class WhitelistRegistry {
    /** field → Set<validValue> */
    private readonly validSets: Map<string, Set<string>>;
    /** field → domain name（エラーメッセージ用） */
    private readonly fieldDomains: Map<string, string>;

    constructor(
        definitions: readonly WhitelistDefinition[],
        extensions?: WhitelistExtensions,
    ) {
        this.validSets = new Map();
        this.fieldDomains = new Map();

        for (const def of definitions) {
            for (const [field, values] of Object.entries(def.fields)) {
                if (field === "__proto__" || field === "constructor") continue;

                if (!this.validSets.has(field)) {
                    this.validSets.set(field, new Set(values));
                    this.fieldDomains.set(field, def.domain);
                } else {
                    const existing = this.validSets.get(field)!;
                    for (const v of values) existing.add(v);
                }
            }
        }

        if (extensions) {
            for (const [field, values] of Object.entries(extensions)) {
                if (field === "__proto__" || field === "constructor") continue;
                if (!values || values.length === 0) continue;

                const existing = this.validSets.get(field) ?? new Set<string>();
                for (const v of values) existing.add(v);
                this.validSets.set(field, existing);
            }
        }
    }

    /**
     * フィールド値を検証する。
     * ホワイトリスト未登録のフィールドは検証をスキップ（制限なし）。
     * @throws ValidationError 不正値の場合
     */
    validate(field: string, value: string): void {
        const validSet = this.validSets.get(field);
        if (!validSet) return;
        if (!validSet.has(value)) {
            const domain = this.fieldDomains.get(field) ?? "custom";
            throw new ValidationError(
                field,
                `invalid ${field}: "${value}" (domain: ${domain}, valid: [${[...validSet].join(", ")}])`,
            );
        }
    }

    /**
     * 配列内の全値を検証する。
     */
    validateAll(field: string, values: readonly string[]): void {
        for (const v of values) {
            this.validate(field, v);
        }
    }

    /** フィールドにホワイトリストが登録されているか */
    hasField(field: string): boolean {
        return this.validSets.has(field);
    }

    /** フィールドの有効値一覧を取得（デバッグ・テスト用） */
    getValidValues(field: string): readonly string[] {
        const set = this.validSets.get(field);
        return set ? [...set] : [];
    }
}
