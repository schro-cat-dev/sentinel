export {};

declare global {
    interface Window {
        crypto: Crypto;
    }

    namespace NodeJS {
        interface Global {
            crypto: Crypto;
        }
    }
    namespace NodeJS {
        interface ImportMeta {
            dirname: string;
            filename: string;
        }
    }
}
