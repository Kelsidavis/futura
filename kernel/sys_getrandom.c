/* kernel/sys_getrandom.c - Random number generation with ChaCha20 CSPRNG
 *
 * Copyright (c) 2025 Kelsi Davis
 * Licensed under the MPL v2.0 — see LICENSE for details.
 *
 * Implements getrandom() for userspace random number generation.
 * Uses a ChaCha20-based CSPRNG seeded from RDRAND (x86_64) or TSC/CNTVCT.
 * Entropy is tracked per-bit; /dev/random blocks when pool is low,
 * /dev/urandom and default getrandom() never block.
 */

#include <kernel/fut_task.h>
#include <kernel/fut_memory.h>
#include <kernel/uaccess.h>
#include <kernel/errno.h>
#include <kernel/kprintf.h>
#include <kernel/fut_timer.h>
#include <kernel/fut_thread.h>
#include <stdint.h>

/* Architecture-specific paging headers for KERNEL_VIRTUAL_BASE */
#include <platform/platform.h>
#include <stddef.h>

/* getrandom flags */
#define GRND_NONBLOCK   0x0001
#define GRND_RANDOM     0x0002
#define GRND_INSECURE   0x0004

/* Maximum bytes per call (same as Linux) */
#define GETRANDOM_MAX   (256 * 1024 * 1024)  /* 256 MB */

/* ============================================================
 *   Entropy Pool -- tracks estimated bits of real entropy
 * ============================================================ */

#define ENTROPY_POOL_BITS    4096   /* Maximum pool capacity in bits */
#define ENTROPY_LOW_WATERMARK 128   /* /dev/random blocks below this */

static uint32_t g_entropy_avail = 0;  /* estimated bits of entropy */
static bool     rng_seeded = false;

uint32_t getrandom_get_entropy_avail(void) {
    return g_entropy_avail;
}

/* Credit entropy bits to the pool (clamped to max) */
static void entropy_credit(uint32_t bits) {
    uint32_t new_val = g_entropy_avail + bits;
    if (new_val > ENTROPY_POOL_BITS)
        new_val = ENTROPY_POOL_BITS;
    g_entropy_avail = new_val;
}

/* Debit entropy bits from the pool */
static void entropy_debit(uint32_t bits) {
    if (bits >= g_entropy_avail)
        g_entropy_avail = 0;
    else
        g_entropy_avail -= bits;
}

/* ============================================================
 *   ChaCha20 CSPRNG -- RFC 8439 quarter-round based
 * ============================================================
 *
 * State: 256-bit key + 96-bit nonce + 32-bit counter = 512-bit block
 * Produces 64 bytes of keystream per block. Reseeded from entropy
 * sources periodically and at init.
 */

/* ChaCha20 state: key[8], counter, nonce[3] in uint32_t words */
static uint32_t chacha_key[8];     /* 256-bit key */
static uint32_t chacha_nonce[3];   /* 96-bit nonce */
static uint64_t chacha_counter;    /* 64-bit block counter */

/* Buffered keystream for partial reads */
static uint8_t  chacha_buf[64];
static uint32_t chacha_buf_pos = 64; /* starts exhausted to force first gen */

/* Reseed counter: force periodic reseeding */
static uint64_t chacha_bytes_since_reseed = 0;
#define CHACHA_RESEED_INTERVAL (1024 * 1024)  /* reseed every 1MB */

static inline uint32_t rotl32(uint32_t x, int n) {
    return (x << n) | (x >> (32 - n));
}

#define QUARTERROUND(a, b, c, d) do { \
    a += b; d ^= a; d = rotl32(d, 16); \
    c += d; b ^= c; b = rotl32(b, 12); \
    a += b; d ^= a; d = rotl32(d, 8);  \
    c += d; b ^= c; b = rotl32(b, 7);  \
} while (0)

/**
 * Generate one 64-byte ChaCha20 block.
 * Input: key[8], counter (low 32 bits), nonce[3]
 * Output: 64-byte keystream block in out
 */
static void chacha20_block(uint8_t out[64]) {
    /* "expand 32-byte k" constant */
    static const uint32_t sigma[4] = {
        0x61707865, 0x3320646e, 0x79622d32, 0x6b206574
    };

    uint32_t state[16];
    state[0]  = sigma[0];
    state[1]  = sigma[1];
    state[2]  = sigma[2];
    state[3]  = sigma[3];
    state[4]  = chacha_key[0];
    state[5]  = chacha_key[1];
    state[6]  = chacha_key[2];
    state[7]  = chacha_key[3];
    state[8]  = chacha_key[4];
    state[9]  = chacha_key[5];
    state[10] = chacha_key[6];
    state[11] = chacha_key[7];
    state[12] = (uint32_t)(chacha_counter & 0xFFFFFFFF);
    state[13] = chacha_nonce[0];
    state[14] = chacha_nonce[1];
    state[15] = chacha_nonce[2];

    uint32_t working[16];
    __builtin_memcpy(working, state, sizeof(state));

    /* 20 rounds (10 double-rounds) */
    for (int i = 0; i < 10; i++) {
        /* Column rounds */
        QUARTERROUND(working[0], working[4], working[8],  working[12]);
        QUARTERROUND(working[1], working[5], working[9],  working[13]);
        QUARTERROUND(working[2], working[6], working[10], working[14]);
        QUARTERROUND(working[3], working[7], working[11], working[15]);
        /* Diagonal rounds */
        QUARTERROUND(working[0], working[5], working[10], working[15]);
        QUARTERROUND(working[1], working[6], working[11], working[12]);
        QUARTERROUND(working[2], working[7], working[8],  working[13]);
        QUARTERROUND(working[3], working[4], working[9],  working[14]);
    }

    /* Add original state back */
    for (int i = 0; i < 16; i++)
        working[i] += state[i];

    /* Serialize to bytes (little-endian) */
    for (int i = 0; i < 16; i++) {
        out[i * 4 + 0] = (uint8_t)(working[i]);
        out[i * 4 + 1] = (uint8_t)(working[i] >> 8);
        out[i * 4 + 2] = (uint8_t)(working[i] >> 16);
        out[i * 4 + 3] = (uint8_t)(working[i] >> 24);
    }

    chacha_counter++;
}

/* ============================================================
 *   Hardware entropy collection
 * ============================================================ */

/* Read a 64-bit value from the best available hardware source */
static uint64_t hw_entropy_read(void) {
    uint64_t val = 0;
#ifdef __x86_64__
    /* Try RDRAND first (true hardware RNG) */
    unsigned char ok = 0;
    __asm__ volatile("rdrand %0; setc %1" : "=r"(val), "=qm"(ok));
    if (ok)
        return val;
    /* Fallback to RDTSC (timing jitter) */
    uint32_t lo, hi;
    __asm__ volatile("rdtsc" : "=a"(lo), "=d"(hi));
    val = ((uint64_t)hi << 32) | lo;
#elif defined(__aarch64__)
    __asm__ volatile("mrs %0, cntvct_el0" : "=r"(val));
#endif
    return val;
}

/* Mix 64 bits of entropy into the ChaCha20 key via XOR folding.
 * This is a fast entropy injection that preserves existing key state. */
static void entropy_mix_into_key(uint64_t entropy) {
    /* XOR entropy into rotating key positions */
    static uint32_t mix_idx = 0;
    chacha_key[mix_idx % 8] ^= (uint32_t)(entropy);
    chacha_key[(mix_idx + 1) % 8] ^= (uint32_t)(entropy >> 32);
    mix_idx += 2;
}

/**
 * Seed (or reseed) the ChaCha20 CSPRNG from available entropy sources.
 * Collects multiple hardware samples and mixes them into the key.
 */
static void chacha_seed(void) {
    /* Collect entropy from multiple samples */
    for (int i = 0; i < 8; i++) {
        uint64_t hw = hw_entropy_read();
        chacha_key[i] ^= (uint32_t)(hw);
        chacha_key[i] ^= (uint32_t)(hw >> 32);
    }

    /* Mix in timer ticks for additional entropy */
    uint64_t ticks = fut_get_ticks();
    chacha_nonce[0] ^= (uint32_t)(ticks);
    chacha_nonce[1] ^= (uint32_t)(ticks >> 32);
    chacha_nonce[2] ^= (uint32_t)(ticks * 0x9E3779B97F4A7C15ULL >> 32);

    /* Ensure non-degenerate state */
    bool all_zero = true;
    for (int i = 0; i < 8; i++) {
        if (chacha_key[i] != 0) { all_zero = false; break; }
    }
    if (all_zero) {
        /* Fallback: SHA-256 initial hash constants */
        chacha_key[0] = 0x6A09E667;
        chacha_key[1] = 0xBB67AE85;
        chacha_key[2] = 0x3C6EF372;
        chacha_key[3] = 0xA54FF53A;
        chacha_key[4] = 0x510E527F;
        chacha_key[5] = 0x9B05688C;
        chacha_key[6] = 0x1F83D9AB;
        chacha_key[7] = 0x5BE0CD19;
        chacha_nonce[0] = 0xDEADBEEF;
        chacha_nonce[1] = 0xCAFEBABE;
        chacha_nonce[2] = 0x01234567;
    }

    chacha_counter = 0;
    chacha_buf_pos = 64;  /* force fresh block generation */
    chacha_bytes_since_reseed = 0;

    if (!rng_seeded) {
        rng_seeded = true;
        g_entropy_avail = 256;  /* initial seed provides ~256 bits */
    }
}

/**
 * Generate random bytes from the ChaCha20 CSPRNG into a kernel buffer.
 * Handles buffered output and periodic reseeding.
 */
static void chacha_generate(uint8_t *out, size_t len) {
    /* Check if we need to reseed */
    if (chacha_bytes_since_reseed >= CHACHA_RESEED_INTERVAL) {
        chacha_seed();
    }

    size_t written = 0;
    while (written < len) {
        /* Refill buffer if exhausted */
        if (chacha_buf_pos >= 64) {
            chacha20_block(chacha_buf);
            chacha_buf_pos = 0;
        }

        size_t avail = 64 - chacha_buf_pos;
        size_t chunk = len - written;
        if (chunk > avail) chunk = avail;

        __builtin_memcpy(out + written, chacha_buf + chacha_buf_pos, chunk);
        chacha_buf_pos += (uint32_t)chunk;
        written += chunk;
    }

    chacha_bytes_since_reseed += len;
}

/* ============================================================
 *   Entropy source mixing -- called from interrupt handlers
 * ============================================================ */

/* Timing accumulator for entropy estimation from interrupt jitter.
 * We track the last few timestamps and estimate entropy from their
 * delta-delta (second derivative), which captures true timing jitter. */
static uint64_t last_event_time[4] = {0};
static uint32_t event_idx = 0;

/**
 * getrandom_add_entropy -- Called from timer interrupt to replenish entropy.
 * Each timer tick contributes entropy from timing jitter between ticks.
 * Entropy estimate: ~2 bits per tick from TSC jitter (conservative).
 */
void getrandom_add_entropy(void) {
    uint64_t now = hw_entropy_read();

    /* Compute timing deltas for entropy estimation */
    uint64_t delta = now - last_event_time[event_idx % 4];
    last_event_time[event_idx % 4] = now;
    event_idx++;

    /* Mix the raw timestamp into the CSPRNG key */
    entropy_mix_into_key(now ^ (delta * 0x9E3779B97F4A7C15ULL));

    /* Conservative entropy credit: timer ticks have ~2 bits of jitter
     * from CPU frequency variation, cache state, interrupt latency. */
    entropy_credit(2);
}

/**
 * getrandom_add_hwrng_entropy -- Called to mix in hardware RNG entropy.
 * Provides high-quality entropy from RDRAND or equivalent.
 * @param sample  Raw entropy sample to mix in
 * @param bits    Estimated entropy bits contributed (0 = mix only, no credit)
 */
void getrandom_add_hwrng_entropy(uint64_t sample, uint32_t bits) {
    entropy_mix_into_key(sample);
    if (bits > 0)
        entropy_credit(bits);
}

/**
 * getrandom_add_io_entropy -- Called from disk I/O completion, network
 * packet arrival, or other I/O events. Timing of I/O events is
 * unpredictable and provides good entropy.
 */
void getrandom_add_io_entropy(void) {
    uint64_t now = hw_entropy_read();
    entropy_mix_into_key(now);
    /* I/O timing jitter: ~4 bits per event (disk seek, network RTT) */
    entropy_credit(4);
}

/**
 * getrandom_add_input_entropy -- Called from keyboard/mouse input handlers.
 * Human input timing is highly unpredictable and contributes significant
 * entropy (~8 bits per keystroke from inter-key timing).
 * @param scancode  The raw scancode/input value (mixed into pool)
 */
void getrandom_add_input_entropy(uint32_t scancode) {
    uint64_t now = hw_entropy_read();
    /* Mix both the timestamp and the scancode value */
    entropy_mix_into_key(now ^ ((uint64_t)scancode << 32));
    /* Keyboard timing: ~8 bits per keystroke (conservative estimate) */
    entropy_credit(8);
}

/* ============================================================
 *   sys_getrandom -- main syscall entry point
 * ============================================================ */

/**
 * sys_getrandom - Fill buffer with random bytes
 *
 * @param buf:    Buffer to fill with random data
 * @param buflen: Number of bytes to generate
 * @param flags:  GRND_NONBLOCK | GRND_RANDOM | GRND_INSECURE
 *
 * Returns:
 *   - Number of bytes written on success
 *   - -EFAULT if buf is invalid
 *   - -EINVAL if flags contains unknown bits
 *   - -EINVAL if buflen > 256MB
 *   - -EAGAIN if GRND_NONBLOCK | GRND_RANDOM and entropy too low
 *
 * Behavior:
 *   - Default (flags=0): reads from urandom pool, never blocks
 *   - GRND_RANDOM: blocks if entropy < 128 bits (like /dev/random)
 *   - GRND_NONBLOCK | GRND_RANDOM: returns -EAGAIN if would block
 *   - GRND_INSECURE: always returns immediately, no entropy debit
 */
long sys_getrandom(void *buf, size_t buflen, unsigned int flags) {
    /* Validate flags */
    if (flags & ~(GRND_NONBLOCK | GRND_RANDOM | GRND_INSECURE)) {
        return -EINVAL;
    }

    /* Validate buffer */
    if (!buf) {
        return -EFAULT;
    }

    if (buflen == 0) {
        return 0;
    }

    if (buflen > GETRANDOM_MAX) {
        return -EINVAL;
    }

    /* Seed CSPRNG on first use */
    if (!rng_seeded) {
        chacha_seed();
    }

    /* GRND_RANDOM: wait for sufficient entropy (like /dev/random).
     * In kernel test context (kernel pointer), never block -- tests
     * call sys_getrandom directly and cannot sleep. */
    bool is_kernel_ptr = false;
#ifdef KERNEL_VIRTUAL_BASE
    is_kernel_ptr = ((uintptr_t)buf >= KERNEL_VIRTUAL_BASE);
#endif

    if ((flags & GRND_RANDOM) && !(flags & GRND_INSECURE) && !is_kernel_ptr) {
        /* Need at least ENTROPY_LOW_WATERMARK bits to proceed */
        if (g_entropy_avail < ENTROPY_LOW_WATERMARK) {
            if (flags & GRND_NONBLOCK) {
                return -EAGAIN;
            }
            /* Block: sleep in a loop waiting for entropy to accumulate.
             * Timer interrupts call getrandom_add_entropy() which will
             * gradually refill the pool. */
            int wait_loops = 0;
            while (g_entropy_avail < ENTROPY_LOW_WATERMARK) {
                fut_thread_sleep(10);  /* sleep 10ms, let timer ticks add entropy */
                wait_loops++;
                if (wait_loops > 500) {
                    /* Safety: don't block forever (5 seconds max).
                     * Force reseed from hardware and continue. */
                    chacha_seed();
                    break;
                }
            }
        }
    }

    /* Generate random bytes into the output buffer */
    size_t remaining = buflen;
    uint8_t *dst = (uint8_t *)buf;

    while (remaining > 0) {
        uint8_t kbuf[64];
        size_t chunk = (remaining < 64) ? remaining : 64;

        chacha_generate(kbuf, chunk);

        if (is_kernel_ptr) {
            /* Direct copy for kernel pointers (self-test context) */
            __builtin_memcpy(dst, kbuf, chunk);
        } else {
            /* Copy through kernel buffer for userspace */
            if (fut_copy_to_user(dst, kbuf, chunk) != 0) {
                return (buflen - remaining) > 0 ? (long)(buflen - remaining) : -EFAULT;
            }
        }

        dst += chunk;
        remaining -= chunk;
    }

    /* Track entropy consumption:
     * - GRND_RANDOM: debit actual bits consumed (1 bit per byte, conservative)
     * - GRND_INSECURE: no debit (fast, no entropy accounting)
     * - Default (urandom): small debit but never blocks */
    if (!(flags & GRND_INSECURE)) {
        if (flags & GRND_RANDOM) {
            /* /dev/random behavior: debit 1 bit per byte consumed */
            entropy_debit((uint32_t)buflen);
        } else {
            /* /dev/urandom behavior: small debit, never causes blocking */
            uint32_t debit = (uint32_t)(buflen / 8);
            if (debit < 1) debit = 1;
            if (debit > g_entropy_avail && g_entropy_avail > 0)
                debit = g_entropy_avail > 1 ? g_entropy_avail - 1 : 0;
            entropy_debit(debit);
        }
    }

    return (long)buflen;
}
