// SPDX-License-Identifier: MPL-2.0
/*
 * fut_hmac.h - SHA-256 and HMAC-SHA256 cryptographic functions
 *
 * Copyright (c) 2025 Kelsi Davis
 * Licensed under the MPL v2.0 — see LICENSE for details.
 *
 * Provides SHA-256 hash and HMAC-SHA256 message authentication code
 * implementations for kernel security features including:
 *   - Capability token verification
 *   - Service registry authentication
 *   - Integrity checking
 *
 * These implementations are optimized for correctness over speed and
 * are suitable for kernel use where security is critical.
 */

#pragma once

#include <stddef.h>
#include <stdint.h>

/* SHA-256 block size in bytes (512 bits) */
#define FUT_SHA256_BLOCK_LEN 64u

/* SHA-256 digest size in bytes (256 bits) */
#define FUT_SHA256_DIGEST_LEN 32u

/**
 * SHA-256 context structure.
 *
 * Maintains the intermediate state during incremental hashing.
 * Initialize with fut_sha256_init() before use.
 */
typedef struct {
    uint32_t state[8];                      /**< Current hash state (A-H) */
    uint64_t bit_len;                       /**< Total bits processed */
    uint8_t buffer[FUT_SHA256_BLOCK_LEN];   /**< Partial block buffer */
    size_t buffer_len;                      /**< Bytes in buffer */
} fut_sha256_ctx;

/**
 * Initialize SHA-256 context.
 *
 * Must be called before fut_sha256_update(). Sets initial hash values
 * per FIPS 180-4.
 *
 * @param ctx  Context to initialize
 */
void fut_sha256_init(fut_sha256_ctx *ctx);

/**
 * Update SHA-256 hash with additional data.
 *
 * Can be called multiple times to hash data incrementally.
 *
 * @param ctx   Initialized context
 * @param data  Data to hash
 * @param len   Length of data in bytes
 */
void fut_sha256_update(fut_sha256_ctx *ctx, const uint8_t *data, size_t len);

/**
 * Finalize SHA-256 hash and output digest.
 *
 * Pads the message, processes final block, and outputs the 32-byte digest.
 * The context should not be used after this call without reinitializing.
 *
 * @param ctx  Context to finalize
 * @param out  Output buffer (must be at least FUT_SHA256_DIGEST_LEN bytes)
 */
void fut_sha256_final(fut_sha256_ctx *ctx, uint8_t out[FUT_SHA256_DIGEST_LEN]);

/**
 * Compute HMAC-SHA256 message authentication code.
 *
 * Computes HMAC as defined in RFC 2104 using SHA-256 as the underlying
 * hash function. HMAC provides both data integrity and authenticity
 * verification when used with a secret key.
 *
 * @param key       Secret key
 * @param key_len   Length of key in bytes
 * @param data      Message to authenticate
 * @param data_len  Length of message in bytes
 * @param out       Output buffer (must be at least FUT_SHA256_DIGEST_LEN bytes)
 *
 * Example:
 *   uint8_t mac[FUT_SHA256_DIGEST_LEN];
 *   fut_hmac_sha256(secret_key, 32, message, msg_len, mac);
 *   // Compare mac with received MAC to verify authenticity
 */
void fut_hmac_sha256(const uint8_t *key,
                     size_t key_len,
                     const uint8_t *data,
                     size_t data_len,
                     uint8_t out[FUT_SHA256_DIGEST_LEN]);
