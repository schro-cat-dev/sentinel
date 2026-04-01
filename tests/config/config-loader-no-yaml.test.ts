/**
 * yaml パッケージ未インストール時のエラーメッセージテスト
 * requireFn の依存注入で Cannot find module をシミュレート。
 */
import { describe, it, expect } from "vitest";
import { parseConfigYaml } from "../../src/configs/config-loader";

describe("parseConfigYaml — yaml package not installed", () => {
    it("throws user-friendly error when require('yaml') fails", () => {
        const failingRequire = () => {
            throw new Error("Cannot find module 'yaml'");
        };

        expect(() => parseConfigYaml("project_name: p\nservice_id: s", {
            requireFn: failingRequire,
        })).toThrow(
            'YAML parsing requires the "yaml" package',
        );
    });

    it("re-throws non-module errors from require", () => {
        const failingRequire = () => {
            throw new Error("Some other require error");
        };

        expect(() => parseConfigYaml("project_name: p\nservice_id: s", {
            requireFn: failingRequire,
        })).toThrow("Some other require error");
    });
});
