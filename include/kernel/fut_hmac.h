// SPDX-License-Identifier: MPL-2.0
#pragma once

#include <stddef.h>
#include <stdint.h>

#define FUT_SHA256_BLOCK_LEN 64u
#define FUT_SHA256_DIGEST_LEN 32u

typedef struct {
    uint32_t state[8];
    uint64_t bit_len;
    uint8_t buffer[FUT_SHA256_BLOCK_LEN];
    size_t buffer_len;
} fut_sha256_ctx;

void fut_sha256_init(fut_sha256_ctx *ctx);
void fut_sha256_update(fut_sha256_ctx *ctx, const uint8_t *data, size_t len);
void fut_sha256_final(fut_sha256_ctx *ctx, uint8_t out[FUT_SHA256_DIGEST_LEN]);

void fut_hmac_sha256(const uint8_t *key,
                     size_t key_len,
                     const uint8_t *data,
                     size_t data_len,
                     uint8_t out[FUT_SHA256_DIGEST_LEN]);
