// Union → 値の配列
export const unionToArray = <const T extends readonly string[]>(arr: T): T =>
    arr;

// Union → 型ガードジェネレータ（Set使用）
export const createIsUnionMember = <const T extends readonly string[]>(
    values: T,
) => {
    type Union = T[number];
    const valueSet = new Set(values);

    return (value: string): value is Union => valueSet.has(value);
};
