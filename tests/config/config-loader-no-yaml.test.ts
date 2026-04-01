/**
 * yaml パッケージ未インストール時のエラーメッセージテスト
 * yamlParser: false を渡して未インストール状態をシミュレート。
 */
import { describe, it, expect } from "vitest";
import { parseConfigYaml } from "../../src/configs/config-loader";

describe("parseConfigYaml — yaml package not installed", () => {
    it("throws user-friendly error when yamlParser is false (simulating missing yaml)", () => {
        expect(() => parseConfigYaml("project_name: p\nservice_id: s", {
            yamlParser: false,
        })).toThrow(
            'YAML parsing requires the "yaml" package',
        );
    });
});
