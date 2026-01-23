export {}; // モジュールとして認識させる

declare global {
    namespace NodeJS {
        interface ImportMeta {
            dirname: string;
            filename: string;
        }
    }
}
