import { defineConfig } from "vitest/config";

export default defineConfig({
    test: {
        globals: true,
        root: ".",
        include: ["tests/**/*.test.ts"],
        exclude: ["node_modules", "dist"],
        testTimeout: 10000,
        pool: "forks",
    },
    resolve: {
        alias: {
            "@": "/src",
        },
    },
});
