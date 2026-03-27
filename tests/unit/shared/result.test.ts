import { describe, it, expect } from "vitest";
import {
    success,
    failure,
    tryCatch,
    map,
    match,
    isOk,
    isErr,
    issuccess,
    isfailure,
    flatMap,
    safe,
    mapError,
    guard,
    all,
} from "../../../src/shared/functional/result";

describe("Result<T, E>", () => {
    describe("success / failure constructors", () => {
        it("success creates a success result", () => {
            const r = success(42);
            expect(r.success).toBe(true);
            expect(r).toEqual({ success: true, value: 42 });
        });

        it("failure creates a failure result", () => {
            const r = failure("error");
            expect(r.success).toBe(false);
            expect(r).toEqual({ success: false, error: "error" });
        });

        it("success with complex object", () => {
            const data = { id: 1, name: "test", nested: { a: [1, 2] } };
            const r = success(data);
            expect(r.success).toBe(true);
            if (r.success) expect(r.value).toEqual(data);
        });

        it("failure with Error instance", () => {
            const err = new Error("something broke");
            const r = failure(err);
            if (!r.success) expect(r.error.message).toBe("something broke");
        });
    });

    describe("type guards: isOk / isErr / issuccess / isfailure", () => {
        it("isOk returns true for success", () => {
            expect(isOk(success(1))).toBe(true);
            expect(isOk(failure("x"))).toBe(false);
        });

        it("isErr returns true for failure", () => {
            expect(isErr(failure("x"))).toBe(true);
            expect(isErr(success(1))).toBe(false);
        });

        it("issuccess is alias for isOk", () => {
            expect(issuccess(success(1))).toBe(true);
            expect(issuccess(failure("x"))).toBe(false);
        });

        it("isfailure is alias for isErr", () => {
            expect(isfailure(failure("x"))).toBe(true);
            expect(isfailure(success(1))).toBe(false);
        });

        it("type narrowing works after isOk check", () => {
            const r = success(42);
            if (isOk(r)) {
                // TypeScript should narrow to { success: true, value: number }
                expect(r.value).toBe(42);
            }
        });

        it("type narrowing works after isErr check", () => {
            const r = failure("err");
            if (isErr(r)) {
                expect(r.error).toBe("err");
            }
        });
    });

    describe("tryCatch", () => {
        it("captures successful sync execution", () => {
            const r = tryCatch(() => 42);
            expect(isOk(r)).toBe(true);
            if (isOk(r)) expect(r.value).toBe(42);
        });

        it("captures thrown exception as failure", () => {
            const r = tryCatch(() => {
                throw new Error("boom");
            });
            expect(isErr(r)).toBe(true);
            if (isErr(r)) expect((r.error as Error).message).toBe("boom");
        });

        it("uses custom error mapper", () => {
            const r = tryCatch(
                () => { throw new Error("raw"); },
                (e) => `mapped: ${(e as Error).message}`,
            );
            expect(isErr(r)).toBe(true);
            if (isErr(r)) expect(r.error).toBe("mapped: raw");
        });

        it("handles non-Error throws", () => {
            const r = tryCatch(() => { throw "string error"; });
            expect(isErr(r)).toBe(true);
        });
    });

    describe("map", () => {
        it("transforms success value", () => {
            const r = map(success(5), (v) => v * 2);
            expect(r).toEqual({ success: true, value: 10 });
        });

        it("passes through failure unchanged", () => {
            const r = map(failure("err"), (v: number) => v * 2);
            expect(r).toEqual({ success: false, error: "err" });
        });
    });

    describe("match", () => {
        it("calls onOk for success", () => {
            const result = match(
                success(42),
                (v) => `ok: ${v}`,
                (e) => `err: ${e}`,
            );
            expect(result).toBe("ok: 42");
        });

        it("calls onErr for failure", () => {
            const result = match(
                failure("bad"),
                (v) => `ok: ${v}`,
                (e) => `err: ${e}`,
            );
            expect(result).toBe("err: bad");
        });
    });

    describe("flatMap", () => {
        it("chains successful computations", () => {
            const r = flatMap(success(5), (v) => success(v * 3));
            expect(r).toEqual({ success: true, value: 15 });
        });

        it("short-circuits on first failure", () => {
            const r = flatMap(failure("first"), (_v: number) => success(99));
            expect(r).toEqual({ success: false, error: "first" });
        });

        it("propagates inner failure", () => {
            const r = flatMap(success(5), () => failure("inner"));
            expect(r).toEqual({ success: false, error: "inner" });
        });
    });

    describe("mapError", () => {
        it("transforms error type", () => {
            const r = mapError(failure("raw"), (e) => ({ code: 500, msg: e }));
            expect(r).toEqual({ success: false, error: { code: 500, msg: "raw" } });
        });

        it("passes through success unchanged", () => {
            const r = mapError(success(42), (e: string) => ({ code: 0, msg: e }));
            expect(r).toEqual({ success: true, value: 42 });
        });
    });

    describe("guard", () => {
        it("returns success when predicate passes", () => {
            const isPositive = guard<number, string>((v) => v > 0, "must be positive");
            const r = isPositive(5);
            expect(r).toEqual({ success: true, value: 5 });
        });

        it("returns failure when predicate fails", () => {
            const isPositive = guard<number, string>((v) => v > 0, "must be positive");
            const r = isPositive(-1);
            expect(r).toEqual({ success: false, error: "must be positive" });
        });
    });

    describe("all", () => {
        it("collects all success values", () => {
            const results = [success(1), success(2), success(3)];
            const r = all(results);
            expect(r).toEqual({ success: true, value: [1, 2, 3] });
        });

        it("returns first failure", () => {
            const results = [success(1), failure("err"), success(3)];
            const r = all(results);
            expect(r).toEqual({ success: false, error: "err" });
        });

        it("handles empty array", () => {
            const r = all([]);
            expect(r).toEqual({ success: true, value: [] });
        });
    });

    describe("safe (async)", () => {
        it("wraps successful async operation", async () => {
            const r = await safe(() => Promise.resolve(42));
            expect(isOk(r)).toBe(true);
            if (isOk(r)) expect(r.value).toBe(42);
        });

        it("captures async rejection", async () => {
            const r = await safe(() => Promise.reject(new Error("async fail")));
            expect(isErr(r)).toBe(true);
            if (isErr(r)) expect((r.error as Error).message).toBe("async fail");
        });

        it("retries on failure", async () => {
            let attempts = 0;
            const r = await safe(
                () => {
                    attempts++;
                    if (attempts < 3) throw new Error("not yet");
                    return Promise.resolve("done");
                },
                { retries: 2 },
            );
            expect(isOk(r)).toBe(true);
            if (isOk(r)) expect(r.value).toBe("done");
            expect(attempts).toBe(3);
        });

        it("fails after exhausting retries", async () => {
            const r = await safe(
                () => { throw new Error("always fail"); },
                { retries: 2 },
            );
            expect(isErr(r)).toBe(true);
        });

        it("calls notify callback on each failure", async () => {
            const notified: string[] = [];
            await safe(
                () => { throw new Error("fail"); },
                {
                    retries: 1,
                    notify: (e) => notified.push(e.message),
                },
            );
            expect(notified).toEqual(["fail", "fail"]);
        });
    });
});
