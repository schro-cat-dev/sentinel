// システム全体の「エラーハンドリング・プロトコル」

// NOTE:
// 同期 / 非同期両対応
// リトライ / 通知 / 回復
// 検証 / ガード処理
// 並列処理集約
// レイヤー間エラー変換

export type Result<T, E = Error> =
    | { success: true; value: T }
    | { success: false; error: E };

export const ok = <T>(value: T): Result<T, never> => ({
    success: true,
    value,
});

export const err = <E>(error: E): Result<never, E> => ({
    success: false,
    error,
});

// 同期処理の例外を捕捉して Result に変換
export const tryCatch = <T, E = Error>(
    fn: () => T,
    onError?: (e: unknown) => E,
): Result<T, E> => {
    try {
        return ok(fn());
    } catch (e) {
        const error = onError ? onError(e) : (e as E);
        return err(error);
    }
};

// Resultプロトコルを破棄して値を強制取得するための緊急脱出ハッチ的な - 信頼性を考慮した時使わない。
// export const unwrap = <T, E>(result: Result<T, E>): T => {
//     if (result.success) {
//         return result.value;
//     }
//     throw result.error;
// };

export const map = <T, E, U>(r: Result<T, E>, fn: (v: T) => U): Result<U, E> =>
    r.success ? ok(fn(r.value)) : r;

export const match = <T, E, R>(
    r: Result<T, E>,
    onOk: (v: T) => R,
    onErr: (e: E) => R,
): R => (r.success ? onOk(r.value) : onErr(r.error));

/**
 * Result が成功ケースか（型ガード）
 */
export const isOk = <T, E>(
    result: Result<T, E>,
): result is Extract<Result<T, E>, { success: true }> => result.success;

/**
 * Result が失敗ケースか（型ガード）
 */
export const isErr = <T, E>(
    result: Result<T, E>,
): result is Extract<Result<T, E>, { success: false }> => !result.success;

// Resultを返す関数とのチェイン（非同期/複雑処理必須）
export const flatMap = <T, E, U, F>(
    r: Result<T, E>,
    fn: (v: T) => Result<U, F>,
): Result<U, E | F> => (r.success ? fn(r.value) : (r as Result<U, E>));

// PromiseをResultに変換（外部API/DB必須）
export const safe = async <T, E extends Error = Error>(
    fn: () => Promise<T>,
    config: {
        retries?: number;
        notify?: (error: E) => void;
    } = {},
): Promise<Result<T, E>> => {
    const { retries = 0, notify } = config;

    for (let i = 0; i <= retries; i++) {
        try {
            return ok(await fn());
        } catch (error) {
            const appError = error as E;
            notify?.(appError);
            if (i === retries) return err(appError);
            // eslint-disable-next-line no-await-in-loop
            await new Promise((r) => setTimeout(r, i * 100));
        }
    }
    throw new Error("Unreachable");
};

// エラーのみを変換（レイヤー間境界）
export const mapError = <T, E, F>(
    r: Result<T, E>,
    fn: (e: E) => F,
): Result<T, F> => (r.success ? r : err(fn(r.error)));

// 条件分岐（検証系処理）
export const guard =
    <T, E>(
        predicate: (value: T) => boolean,
        error: E,
    ): ((value: T) => Result<T, E>) =>
    (value) =>
        predicate(value) ? ok(value) : err(error);

// 全Resultを1つに集約（複数処理後）
export const all = <T, E>(results: Result<T, E>[]): Result<T[], E> => {
    const values: T[] = [];
    for (const result of results) {
        if (!result.success) return result;
        values.push(result.value);
    }
    return ok(values);
};

// --- Usage ---
// ex1: Service layer
// function executeTrade(order: Order): Result<TradeResult, AppError> {
//   return ok(order.amount)
//     .map(v => checkBalance(v))      // number → boolean? → Result
//     .map(v => validateLimit(v))     // boolean → void? → Result
//     .map(v => execute(v));          // void → TradeResult
// }

// ex2: Controller layer
// match(executeTrade(req.body),
//   trade => res.json(trade),           // 200 OK
//   error => res.status(400).json(error) // 400 Bad Request
// );

// ex1: Service layer
// async function executeTrade(order: Order): Promise<Result<TradeResult, AppError>> {
//   return ok(order)
//     .flatMap(async v => safe(async () => checkBalance(v), { retries: 2 }))  // DBリトライ
//     .flatMap(async v => safe(async () => checkInventory(v)))               // 在庫確認
//     .flatMap(v => guard(v => v <= userLimit, LimitExceededError))          // 限度額ガード
//     .flatMap(async v => safe(async () => executePayment(v)))               // 決済
//     .map(commitTransaction);
// }

// ex2: Controller layer
// match(await executeTrade(req.body),
//   trade => res.json({ success: trade }),           // 200 OK
//   error => {
//     auditLog(error);
//     res.status(400).json({ error: error.message }); // 400 Bad Request
//   }
//     );

// ex3: 複数並列処理
// const [userResult, balanceResult] = await Promise.all([
//   safe(() => db.getUser(id)),
//   safe(() => db.getBalance(id))
// ]);
// const result = all([userResult, balanceResult]);
