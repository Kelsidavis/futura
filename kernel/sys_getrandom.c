/* kernel/sys_getrandom.c - Random number generation syscall
 *
 * Copyright (c) 2025 Kelsi Davis
 * Licensed under the MPL v2.0 — see LICENSE for details.
 *
 * Implements getrandom() for userspace random number generation.
 * Uses a simple xorshift128+ PRNG seeded from hardware sources.
 * Not cryptographically secure — suitable for non-security purposes.
 */

#include <kernel/fut_task.h>
#include <kernel/fut_memory.h>
#include <kernel/uaccess.h>
#include <kernel/errno.h>
#include <kernel/kprintf.h>
#include <kernel/fut_timer.h>
#include <stdint.h>

/* Architecture-specific paging headers for KERNEL_VIRTUAL_BASE */
#ifdef __x86_64__
#include <platform/x86_64/memory/paging.h>
#elif defined(__aarch64__)
#include <platform/arm64/memory/paging.h>
#endif
#include <stddef.h>

/* getrandom flags */
#define GRND_NONBLOCK   0x0001
#define GRND_RANDOM     0x0002
#define GRND_INSECURE   0x0004

/* Maximum bytes per call (same as Linux) */
#define GETRANDOM_MAX   (256 * 1024 * 1024)  /* 256 MB */

/* xorshift128+ state — seeded at first use */
static uint64_t rng_state[2] = {0, 0};
static bool rng_seeded = false;

/**
 * Seed the RNG from available entropy sources.
 * Uses TSC (if available), timer ticks, and task PID as entropy.
 */
static void rng_seed(void) {
    uint64_t seed0 = 0, seed1 = 0;

    /* Try to read TSC for hardware entropy */
#ifdef __x86_64__
    uint32_t lo, hi;
    __asm__ volatile("rdtsc" : "=a"(lo), "=d"(hi));
    seed0 = ((uint64_t)hi << 32) | lo;
#elif defined(__aarch64__)
    __asm__ volatile("mrs %0, cntvct_el0" : "=r"(seed0));
#endif

    /* Mix in timer ticks and a constant */
    seed1 = fut_get_ticks();
    seed1 ^= 0x6A09E667F3BCC908ULL;  /* SHA-256 fractional constant */

    /* Ensure non-zero state */
    if (seed0 == 0) seed0 = 0xDEADBEEFCAFEBABEULL;
    if (seed1 == 0) seed1 = 0x0123456789ABCDEFULL;

    rng_state[0] = seed0;
    rng_state[1] = seed1;
    rng_seeded = true;
}

/**
 * xorshift128+ — fast, high-quality PRNG
 * Period: 2^128 - 1
 */
static uint64_t rng_next(void) {
    uint64_t s0 = rng_state[0];
    uint64_t s1 = rng_state[1];
    uint64_t result = s0 + s1;

    s1 ^= s0;
    rng_state[0] = ((s0 << 55) | (s0 >> 9)) ^ s1 ^ (s1 << 14);
    rng_state[1] = (s1 << 36) | (s1 >> 28);

    return result;
}

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

    /* Seed RNG on first use */
    if (!rng_seeded) {
        rng_seed();
    }

    /* Generate random bytes into a kernel buffer, then copy to user */
    size_t remaining = buflen;
    uint8_t *dst = (uint8_t *)buf;

    /* Check if this is a kernel pointer (for self-tests) */
    bool is_kernel_ptr = false;
#ifdef KERNEL_VIRTUAL_BASE
    is_kernel_ptr = ((uintptr_t)buf >= KERNEL_VIRTUAL_BASE);
#endif

    while (remaining > 0) {
        uint64_t rval = rng_next();
        size_t chunk = (remaining < 8) ? remaining : 8;

        if (is_kernel_ptr) {
            /* Direct copy for kernel pointers (self-test context) */
            for (size_t i = 0; i < chunk; i++) {
                dst[i] = (uint8_t)(rval >> (i * 8));
            }
        } else {
            /* Copy through kernel buffer for userspace */
            uint8_t kbuf[8];
            for (size_t i = 0; i < chunk; i++) {
                kbuf[i] = (uint8_t)(rval >> (i * 8));
            }
            if (fut_copy_to_user(dst, kbuf, chunk) != 0) {
                /* Return bytes written so far, or EFAULT if none */
                return (buflen - remaining) > 0 ? (long)(buflen - remaining) : -EFAULT;
            }
        }

        dst += chunk;
        remaining -= chunk;
    }

    return (long)buflen;
}
