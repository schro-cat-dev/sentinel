# Sentinel Security Audit Report v4 (Post-Refactoring Re-scan)

**Date:** 2026-04-01
**Target:** v0.1.0-alpha.2 / branch main / pending commit
**Scope:** `src/` full 22-file manual code review (all `.ts` files)
**Method:** Manual line-by-line audit of all source files, cross-referenced against v3 final-assurance findings
**Auditor:** Claude Code (AI-assisted security review)
**Baseline:** final-assurance-v3.md (37 findings, 22 fixed in client SDK)

---

## 1. Regression Check: All Previous Security Fixes

| ID | Fix | File | Status |
|----|-----|------|--------|
| NEW-01 | `timingSafeEqual` in hash comparison | `src/security/integrity-signer.ts:55-58` | INTACT -- `timingSafeEqual(a, b)` with length pre-check |
| NEW-02 | Async mutex for hash chain | `src/core/engine/ingestion-engine.ts:21,95-101,121-132` | INTACT -- `withChainLock()` serializes read-compute-update |
| NEW-03 | Full-object masking (not just message) | `src/core/engine/ingestion-engine.ts:68-75` | INTACT -- `MaskingService.mask(log, ...)` applied to entire Log object |
| NEW-04 | `/g` flag removal in `isPiiSafe` | `src/shared/utils/error-utils.ts:6-21` | INTACT -- all PII_PATTERNS use `/i` or no flags, zero `/g` flags |
| NEW-05 | `__proto__` filter in task generation | `src/core/task/task-generator.ts:87-95` | INTACT -- both `executionParams` and `guardrails` filter `__proto__` and `constructor` |
| NEW-06 | `SafeLogSubset` in event-detector | `src/core/detection/event-detector.ts:38-47` | INTACT -- `rawLog` contains only safe fields (traceId, type, level, timestamp, boundary, serviceId, message, isCritical) |
| NEW-07 | NaN/Infinity rejection in signer | `src/security/integrity-signer.ts:97` | INTACT -- `Number.isFinite()` check in `isJsonValue` |
| NEW-09 | Deep-merge config | `src/configs/sentinel-config.ts:71-79` | INTACT -- masking and security objects deep-merged |
| NEW-11 | message required validation | `src/validation/log-validator.ts:34-49` | INTACT -- null/undefined/empty/null-byte checks |
| NEW-13 | Retry cap in `safe()` | `src/shared/functional/result.ts:92` | INTACT -- `Math.min(Math.max(0, rawRetries), MAX_RETRIES)` with MAX=10 |
| NEW-15 | KEY_MATCH case-insensitive | `src/security/masking-service.ts:107-113` | INTACT -- `toLowerCase()` comparison |

**Result: 0 regressions detected. All 11 verifiable security fixes remain intact.**

---

## 2. New Code Analysis

### 2.1 `getLastProcessedLog()` -- Mutable Reference Leak

**File:** `src/core/engine/ingestion-engine.ts:42-44`

```typescript
getLastProcessedLog(): Log | null {
    return this.lastProcessedLog;
}
```

**Severity: LOW**
**Analysis:** This returns a direct reference to the internal `lastProcessedLog` object. The caller (`Sentinel.ingest()` at `src/index.ts:133`) passes it to `sendWithTimeout()` which calls `transport.send(log)`. The user-provided transport implementation could mutate this object, potentially corrupting the engine's internal state.

However, the practical impact is limited because:
1. `lastProcessedLog` is overwritten on every `handle()` call (line 107)
2. It is only read in `dual` mode after `handle()` completes
3. The transport `send()` is expected to serialize, not mutate

**Verdict: LOW risk. Defensive copy (`{ ...this.lastProcessedLog }`) would be ideal but not critical.**

---

### 2.2 `emitSafe()` -- Error Handling

**File:** `src/core/engine/ingestion-engine.ts:134-141`

```typescript
private emitSafe(fn: () => void, context = "callback"): void {
    try {
        fn();
    } catch (e) {
        const error = e instanceof Error ? e : new Error(String(e));
        try { this.config.onError?.(error, context); } catch { /* */ }
    }
}
```

**Severity: NONE**
**Analysis:** Double try-catch correctly prevents user callback errors from crashing the pipeline. The inner catch swallows onError failures to prevent infinite recursion. This is correct.

---

### 2.3 `withChainLock()` -- Narrow Mutex

**File:** `src/core/engine/ingestion-engine.ts:121-132`

**Severity: NONE**
**Analysis:** The promise-chain mutex pattern is correct:
1. New promise created, resolver captured
2. Previous lock reference saved before overwrite (prevents lost-update)
3. `await previousLock` blocks until predecessor completes
4. `finally` block ensures release even on exception
5. The critical section (`fn()`) is synchronous, eliminating re-entrancy risk

The narrow scope (only hash-chain update) is correct -- normalize, mask, detect, and task dispatch are outside the lock.

---

### 2.4 `shutdown()` -- State Cleanup

**File:** `src/index.ts:93-101`

```typescript
public async shutdown(): Promise<void> {
    try {
        await this.transportConfig.transport?.close?.();
    } catch {
        // transport close errors are best-effort
    }
    this.taskExecutor.clearHandlers();
    Sentinel.instance = null;
}
```

**Severity: NONE**
**Analysis:** Correct. Transport close is best-effort. Handlers are cleared (MEM-01). Singleton nulled. No `this.initialized = false` set, but since the instance reference is discarded, this is not exploitable.

---

### 2.5 `normalizeOnly()` -- Masking Before Remote Send

**File:** `src/core/engine/ingestion-engine.ts:49-59`

**Severity: NONE**
**Analysis:** When masking is enabled, `normalizeOnly()` applies `MaskingService.mask()` before returning. This is called by `Sentinel.ingest()` in remote mode (line 118). PII is masked before transmission. Correct.

---

### 2.6 `sendWithTimeout()` -- Promise.race Pattern

**File:** `src/index.ts:160-170`

```typescript
private async sendWithTimeout(log: Log): Promise<IngestionResult> {
    const transport = this.transportConfig.transport!;
    const timeoutMs = this.transportConfig.timeoutMs ?? 30_000;
    const sendPromise = transport.send(log);
    const timeoutPromise = new Promise<never>((_, reject) => {
        setTimeout(() => reject(new Error(`Transport timeout after ${timeoutMs}ms`)), timeoutMs);
    });
    return Promise.race([sendPromise, timeoutPromise]);
}
```

**Severity: LOW (CWE-404 -- Improper Resource Shutdown)**
**Finding:** The `setTimeout` timer is never cleared when `sendPromise` wins the race. The timer continues to run and will fire (rejecting a now-ignored promise). This causes:
1. A minor memory/timer leak per call (timer lives for `timeoutMs` after resolution)
2. An unhandled rejection if Node's `--unhandled-rejections=throw` is set (the timeout promise rejects with no `.catch()`)

**Note:** In practice, Node.js default behavior ignores the orphaned rejection from the losing Promise.race branch. But it is technically a resource leak.

---

### 2.7 `TaskExecutor.invokeWithTimeout()` -- Same Pattern

**File:** `src/core/task/task-executor.ts:113-124`

```typescript
private async invokeWithTimeout(task: GeneratedTask): Promise<void> {
    const timeoutMs = task.guardrails.timeoutMs;
    if (timeoutMs > 0) {
        const handlerPromise = this.invokeHandlers(task);
        const timeoutPromise = new Promise<never>((_, reject) => {
            setTimeout(() => reject(...), timeoutMs);
        });
        await Promise.race([handlerPromise, timeoutPromise]);
    } else {
        await this.invokeHandlers(task);
    }
}
```

**Severity: LOW (CWE-404 -- Improper Resource Shutdown)**
**Finding:** Same `setTimeout` leak as `sendWithTimeout()`. The timer is never cleared when the handler completes before timeout. Identical root cause and impact.

---

### 2.8 `LogNormalizer` -- Defensive Fallback Without validate()

**File:** `src/core/engine/log-normalizer.ts:18-44`

**Severity: NONE**
**Analysis:** The normalizer correctly applies defensive fallbacks:
- `message`: falls back to `""` (empty string after trim) -- but `validateLogInput()` at SDK boundary already rejects empty messages
- `type`: falls back to `"SYSTEM"` if not in valid set
- `level`: falls back to `3` if not in valid set
- `origin`: defaults to `"SYSTEM"` unless exactly `"AI_AGENT"`
- `isCritical`: defaults to `false`

The responsibility split is clean: `validateLogInput()` enforces constraints at the SDK boundary, `LogNormalizer` provides safe defaults for internal use.

---

## 3. Responsibility Boundary Verification

| Module | Responsibility | Verified |
|--------|---------------|----------|
| `validateLogInput` | SDK public boundary: type checks, length limits, null-byte rejection, required field enforcement | CORRECT -- no normalization, pure validation |
| `LogNormalizer` | Defaults/fallback only, no validation throws | CORRECT -- no exceptions thrown, pure defaulting |
| `MaskingService` | Stateless, no side effects | CORRECT -- static methods, creates new objects, WeakSet is per-call |
| `IntegritySigner` | Hash computation + chain state (instance holds `previousHash`) | CORRECT -- `calculateHash` is static/pure, chain state is instance-level |
| `EventDetector` | Detection only, SafeLogSubset for rawLog | CORRECT -- no mutation of input log, SafeLogSubset limits PII exposure |
| `TaskGenerator` | Rule matching, no mutation | CORRECT -- creates new task objects, filters __proto__, does not mutate input |
| `TaskExecutor` | Dispatch + timeout | CORRECT -- handler invocation with guardrail checks |
| `IngestionEngine` | Orchestration, narrow mutex | CORRECT -- mutex only around hash chain, callbacks wrapped in emitSafe |

**Result: All 8 responsibility boundaries are clean and correctly separated.**

---

## 4. Findings Summary

### Real Issues Found

| # | Severity | CWE | File:Line | Description |
|---|----------|-----|-----------|-------------|
| V4-01 | LOW | CWE-404 | `src/index.ts:165-167` | `sendWithTimeout()`: setTimeout never cleared on successful send. Timer leak + potential unhandled rejection from orphaned timeout promise. |
| V4-02 | LOW | CWE-404 | `src/core/task/task-executor.ts:117-119` | `invokeWithTimeout()`: Same setTimeout leak pattern as V4-01. |
| V4-03 | LOW | CWE-200 | `src/core/engine/ingestion-engine.ts:42-44` | `getLastProcessedLog()` returns mutable reference. A malicious transport implementation could mutate the returned object. |

### Scan Limitation

The automated security scan (`.security/scan.sh --regex`) could not be executed in this audit session due to tool permission restrictions. A manual review of the scan rules was performed against the source code instead. No issues matching the 10 custom rules (ReDoS, dynamic RegExp, error leakage, eval, prototype pollution, hardcoded secrets, weak crypto, command injection, path traversal, insecure transport) were found in `src/`.

**Known expected findings from previous scans (unchanged):**
- RULE-002: `new RegExp()` in `masking-service.ts:154` (accepted -- reconstructs user-provided pattern with forced `/g` flag)
- RULE-005: `__proto__` string literal in `task-generator.ts:88,92` (false positive -- this IS the filter, not the vulnerability)

---

## 5. Recommended Fixes

### V4-01 / V4-02: setTimeout Leak in Promise.race

Both `sendWithTimeout()` and `invokeWithTimeout()` should clear the timer:

```typescript
// Recommended pattern:
const controller = { timer: undefined as ReturnType<typeof setTimeout> | undefined };
const timeoutPromise = new Promise<never>((_, reject) => {
    controller.timer = setTimeout(() => reject(new Error(`Timeout`)), timeoutMs);
});
try {
    return await Promise.race([sendPromise, timeoutPromise]);
} finally {
    clearTimeout(controller.timer);
}
```

### V4-03: Defensive Copy for getLastProcessedLog

```typescript
getLastProcessedLog(): Log | null {
    return this.lastProcessedLog ? { ...this.lastProcessedLog } : null;
}
```

Note: Shallow copy is sufficient since Log fields are primitives, strings, or arrays of simple objects.

---

## 6. Final Verdict

```
+---------------------------------------------+
|         AUDIT RESULT: v4 RE-SCAN            |
+---------------------------------------------+
| Previous fixes regressed:    0 / 11         |
| New vulnerabilities (HIGH+):  0              |
| New vulnerabilities (LOW):    3              |
| Responsibility boundaries:    8/8 correct    |
| Automated scan:               NOT RUN *      |
|                                              |
| * Permission restricted. Manual rule         |
|   review performed instead.                  |
|                                              |
| STATUS: CLEAN (no regressions, 3 LOW)       |
+---------------------------------------------+
```

**Signature:** Claude Code (AI-assisted security review)
**Timestamp:** 2026-03-30
