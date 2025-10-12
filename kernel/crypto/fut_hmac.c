// SPDX-License-Identifier: MPL-2.0
#include <kernel/fut_hmac.h>
#include <string.h>

#define ROTR(x, n) (((x) >> (n)) | ((x) << (32 - (n))))
#define CH(x, y, z) (((x) & (y)) ^ (~(x) & (z)))
#define MAJ(x, y, z) (((x) & (y)) ^ ((x) & (z)) ^ ((y) & (z)))
#define SIGMA0(x) (ROTR((x), 2) ^ ROTR((x), 13) ^ ROTR((x), 22))
#define SIGMA1(x) (ROTR((x), 6) ^ ROTR((x), 11) ^ ROTR((x), 25))
#define sigma0(x) (ROTR((x), 7) ^ ROTR((x), 18) ^ ((x) >> 3))
#define sigma1(x) (ROTR((x), 17) ^ ROTR((x), 19) ^ ((x) >> 10))

static const uint32_t k_table[64] = {
    0x428a2f98u, 0x71374491u, 0xb5c0fbcfu, 0xe9b5dba5u,
    0x3956c25bu, 0x59f111f1u, 0x923f82a4u, 0xab1c5ed5u,
    0xd807aa98u, 0x12835b01u, 0x243185beu, 0x550c7dc3u,
    0x72be5d74u, 0x80deb1feu, 0x9bdc06a7u, 0xc19bf174u,
    0xe49b69c1u, 0xefbe4786u, 0x0fc19dc6u, 0x240ca1ccu,
    0x2de92c6fu, 0x4a7484aau, 0x5cb0a9dcu, 0x76f988dau,
    0x983e5152u, 0xa831c66du, 0xb00327c8u, 0xbf597fc7u,
    0xc6e00bf3u, 0xd5a79147u, 0x06ca6351u, 0x14292967u,
    0x27b70a85u, 0x2e1b2138u, 0x4d2c6dfcu, 0x53380d13u,
    0x650a7354u, 0x766a0abbu, 0x81c2c92eu, 0x92722c85u,
    0xa2bfe8a1u, 0xa81a664bu, 0xc24b8b70u, 0xc76c51a3u,
    0xd192e819u, 0xd6990624u, 0xf40e3585u, 0x106aa070u,
    0x19a4c116u, 0x1e376c08u, 0x2748774cu, 0x34b0bcb5u,
    0x391c0cb3u, 0x4ed8aa4au, 0x5b9cca4fu, 0x682e6ff3u,
    0x748f82eeu, 0x78a5636fu, 0x84c87814u, 0x8cc70208u,
    0x90befffau, 0xa4506cebu, 0xbef9a3f7u, 0xc67178f2u
};

static void sha256_transform(fut_sha256_ctx *ctx, const uint8_t block[64]) {
    uint32_t w[64];
    for (size_t i = 0; i < 16; ++i) {
        size_t j = i * 4;
        w[i] = ((uint32_t)block[j] << 24) | ((uint32_t)block[j + 1] << 16) |
               ((uint32_t)block[j + 2] << 8) | ((uint32_t)block[j + 3]);
    }
    for (size_t i = 16; i < 64; ++i) {
        w[i] = sigma1(w[i - 2]) + w[i - 7] + sigma0(w[i - 15]) + w[i - 16];
    }

    uint32_t a = ctx->state[0];
    uint32_t b = ctx->state[1];
    uint32_t c = ctx->state[2];
    uint32_t d = ctx->state[3];
    uint32_t e = ctx->state[4];
    uint32_t f = ctx->state[5];
    uint32_t g = ctx->state[6];
    uint32_t h = ctx->state[7];

    for (size_t i = 0; i < 64; ++i) {
        uint32_t temp1 = h + SIGMA1(e) + CH(e, f, g) + k_table[i] + w[i];
        uint32_t temp2 = SIGMA0(a) + MAJ(a, b, c);
        h = g;
        g = f;
        f = e;
        e = d + temp1;
        d = c;
        c = b;
        b = a;
        a = temp1 + temp2;
    }

    ctx->state[0] += a;
    ctx->state[1] += b;
    ctx->state[2] += c;
    ctx->state[3] += d;
    ctx->state[4] += e;
    ctx->state[5] += f;
    ctx->state[6] += g;
    ctx->state[7] += h;
}

void fut_sha256_init(fut_sha256_ctx *ctx) {
    ctx->state[0] = 0x6a09e667u;
    ctx->state[1] = 0xbb67ae85u;
    ctx->state[2] = 0x3c6ef372u;
    ctx->state[3] = 0xa54ff53au;
    ctx->state[4] = 0x510e527fu;
    ctx->state[5] = 0x9b05688cu;
    ctx->state[6] = 0x1f83d9abu;
    ctx->state[7] = 0x5be0cd19u;
    ctx->bit_len = 0;
    ctx->buffer_len = 0;
}

void fut_sha256_update(fut_sha256_ctx *ctx, const uint8_t *data, size_t len) {
    if (!len) {
        return;
    }
    size_t i = 0;
    if (ctx->buffer_len) {
        size_t fill = FUT_SHA256_BLOCK_LEN - ctx->buffer_len;
        if (len < fill) {
            memcpy(ctx->buffer + ctx->buffer_len, data, len);
            ctx->buffer_len += len;
            return;
        }
        memcpy(ctx->buffer + ctx->buffer_len, data, fill);
        sha256_transform(ctx, ctx->buffer);
        ctx->bit_len += FUT_SHA256_BLOCK_LEN * 8ULL;
        ctx->buffer_len = 0;
        i += fill;
    }
    for (; i + FUT_SHA256_BLOCK_LEN <= len; i += FUT_SHA256_BLOCK_LEN) {
        sha256_transform(ctx, data + i);
        ctx->bit_len += FUT_SHA256_BLOCK_LEN * 8ULL;
    }
    size_t remaining = len - i;
    if (remaining) {
        memcpy(ctx->buffer, data + i, remaining);
        ctx->buffer_len = remaining;
    }
}

void fut_sha256_final(fut_sha256_ctx *ctx, uint8_t out[FUT_SHA256_DIGEST_LEN]) {
    ctx->bit_len += ctx->buffer_len * 8ULL;

    ctx->buffer[ctx->buffer_len++] = 0x80u;
    if (ctx->buffer_len > 56) {
        while (ctx->buffer_len < FUT_SHA256_BLOCK_LEN) {
            ctx->buffer[ctx->buffer_len++] = 0;
        }
        sha256_transform(ctx, ctx->buffer);
        ctx->buffer_len = 0;
    }
    while (ctx->buffer_len < 56) {
        ctx->buffer[ctx->buffer_len++] = 0;
    }

    for (int i = 7; i >= 0; --i) {
        ctx->buffer[ctx->buffer_len++] = (uint8_t)((ctx->bit_len >> (i * 8)) & 0xFFu);
    }

    sha256_transform(ctx, ctx->buffer);

    for (size_t i = 0; i < 8; ++i) {
        out[i * 4]     = (uint8_t)(ctx->state[i] >> 24);
        out[i * 4 + 1] = (uint8_t)(ctx->state[i] >> 16);
        out[i * 4 + 2] = (uint8_t)(ctx->state[i] >> 8);
        out[i * 4 + 3] = (uint8_t)(ctx->state[i]);
    }

    memset(ctx, 0, sizeof(*ctx));
}

void fut_hmac_sha256(const uint8_t *key,
                     size_t key_len,
                     const uint8_t *data,
                     size_t data_len,
                     uint8_t out[FUT_SHA256_DIGEST_LEN]) {
    uint8_t k_ipad[FUT_SHA256_BLOCK_LEN];
    uint8_t k_opad[FUT_SHA256_BLOCK_LEN];
    uint8_t key_block[FUT_SHA256_DIGEST_LEN];

    if (key_len > FUT_SHA256_BLOCK_LEN) {
        fut_sha256_ctx tctx;
        fut_sha256_init(&tctx);
        fut_sha256_update(&tctx, key, key_len);
        fut_sha256_final(&tctx, key_block);
        key = key_block;
        key_len = FUT_SHA256_DIGEST_LEN;
    }

    memset(k_ipad, 0x36, sizeof(k_ipad));
    memset(k_opad, 0x5c, sizeof(k_opad));
    for (size_t i = 0; i < key_len; ++i) {
        k_ipad[i] ^= key[i];
        k_opad[i] ^= key[i];
    }

    fut_sha256_ctx ctx;
    fut_sha256_init(&ctx);
    fut_sha256_update(&ctx, k_ipad, sizeof(k_ipad));
    fut_sha256_update(&ctx, data, data_len);
    uint8_t inner[FUT_SHA256_DIGEST_LEN];
    fut_sha256_final(&ctx, inner);

    fut_sha256_init(&ctx);
    fut_sha256_update(&ctx, k_opad, sizeof(k_opad));
    fut_sha256_update(&ctx, inner, sizeof(inner));
    fut_sha256_final(&ctx, out);

    memset(inner, 0, sizeof(inner));
    memset(key_block, 0, sizeof(key_block));
}

#undef ROTR
#undef CH
#undef MAJ
#undef SIGMA0
#undef SIGMA1
#undef sigma0
#undef sigma1
