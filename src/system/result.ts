// システム全体の「エラーハンドリング・プロトコル」

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

export const unwrap = <T, E>(result: Result<T, E>): T => {
    if (result.success) {
        return result.value;
    }
    throw result.error;
};
