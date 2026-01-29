/**
 * HASH_TYPES represents the supported hash algorithms for PBKDF2.
 */
export const HASH_TYPES = {
    SHA1: "SHA-1",
    SHA256: "SHA-256",
    SHA384: "SHA-384",
    SHA512: "SHA-512",
} as const;

export type HashType = (typeof HASH_TYPES)[keyof typeof HASH_TYPES];

/**
 * CRYPTO_PARAMETERS holds all cryptographic constants with initial default values.
 * It utilizes HASH_TYPES for defining the hash algorithm.
 */
export const CRYPTO_PARAMETERS = {
    SALT_LENGTH: 16, // Length of the salt in bytes
    PBKDF2_ITERATIONS: 200000, // Number of iterations for PBKDF2
    PBKDF2_HASH: HASH_TYPES.SHA512, // Hash algorithm for PBKDF2
    AES_KEY_LENGTH: 256, // Length of the AES key in bits
} as const;

/**
 * DeriveKeyOptions defines the options for the deriveKey function.
 * - passphrase: Required parameter and this field should be at least 8 characters.
 * - saltLength, iterations, hash, keyLength: Optional parameters with default values from CRYPTO_PARAMETERS.
 */
export interface DeriveKeyOptions {
    passphrase: string; // Required: The passphrase to derive the key from
    saltLength?: number; // Optional: Length of the salt in bytes
    iterations?: number; // Optional: Number of iterations for PBKDF2
    hash?: HashType; // Optional: Hash algorithm for PBKDF2
    keyLength?: number; // Optional: Length of the AES key in bits
}

type DeriveKeyOptionsKeys = keyof DeriveKeyOptions;

/**
 * Validate DeriveKeyOptions parameters.
 * Throws Error if validation fails.
 */
export function validateDeriveKeyOptions(options: DeriveKeyOptions): void {
    const allowedKeys: DeriveKeyOptionsKeys[] = [
        "passphrase",
        "saltLength",
        "iterations",
        "hash",
        "keyLength",
    ];
    const optionKeys = Object.keys(options) as DeriveKeyOptionsKeys[];

    for (const key of optionKeys) {
        if (!allowedKeys.includes(key)) {
            throw new Error(
                `Unknown property: ${key}. Allowed: ${allowedKeys.join(", ")}`,
            );
        }
    }

    if (!options.passphrase || options.passphrase.length < 8) {
        throw new Error("Passphrase must be at least 8 characters long.");
    }

    if (
        options.saltLength !== undefined &&
        (typeof options.saltLength !== "number" || options.saltLength <= 0)
    ) {
        throw new Error("saltLength must be a positive number.");
    }

    if (
        options.iterations !== undefined &&
        (typeof options.iterations !== "number" || options.iterations <= 0)
    ) {
        throw new Error("iterations must be a positive number.");
    }

    if (options.hash !== undefined && !(options.hash in HASH_TYPES)) {
        throw new Error(
            `Invalid hash algorithm: ${options.hash}. Must be one of: ${Object.values(HASH_TYPES).join(", ")}`,
        );
    }

    if (
        options.keyLength !== undefined &&
        (typeof options.keyLength !== "number" || options.keyLength <= 0)
    ) {
        throw new Error("keyLength must be a positive number.");
    }
}

/**
 * EncryptionAlgorithm defines the supported encryption algorithms.
 */
export type EncryptionAlgorithm = "AES-GCM"; // Future expansion to other algorithms possible

/**
 * EncryptionOptions defines the options for initializing encryption strategies.
 * - algorithm: The encryption algorithm to use.
 * - passphrase: The passphrase for key derivation.
 * - saltLength, iterations, hash, keyLength: Optional parameters for key derivation.
 */
export interface EncryptionOptions extends DeriveKeyOptions {
    algorithm: EncryptionAlgorithm; // Required: The encryption algorithm to use
}

export const DEFAULT_ENCRYPTION_OPTIONS: EncryptionOptions = {
    passphrase: "YourSecureDefaultPassphrase", // TODO ここはセキュリティ要件に応じて設定
    algorithm: "AES-GCM",
    saltLength: 16,
    iterations: 200000,
    hash: "SHA-512",
    keyLength: 256,
};

/**
 * Validate EncryptionOptions parameters.
 * Throws Error if validation fails.
 */
export function validateEncryptionOptions(options: EncryptionOptions): void {
    validateDeriveKeyOptions(options);

    if (!options.algorithm || options.algorithm !== "AES-GCM") {
        throw new Error("algorithm must be 'AES-GCM'");
    }
}

/**
 * An array of numbers, which indicate where to insert iv and salt strings in the encrypted data body string.
 * Each element of the array is an index of the insertion position.
 */
export const INSERT_POSITIONS: number[] = [5, 10];
