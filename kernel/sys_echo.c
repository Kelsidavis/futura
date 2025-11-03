// SPDX-License-Identifier: MPL-2.0
/*
 * sys_echo.c - Minimal syscall exercising uaccess helpers
 *
 * Copyright (c) 2025 Kelsi Davis
 * Licensed under the MPL v2.0 — see LICENSE for details.
 *
 * Debug/test syscall that flips case of characters and echoes them back.
 * Useful for testing userspace/kernel boundary and copy routines.
 *
 * Phase 1 (Completed): Basic echo with XOR case flip
 * Phase 2 (Current): Enhanced validation, buffer categorization, detailed logging
 * Phase 3: Performance optimization, zero-copy support
 * Phase 4: Advanced transformations, streaming support
 */

#include <kernel/syscalls.h>
#include <kernel/uaccess.h>
#include <kernel/errno.h>

#include <stddef.h>

extern void fut_printf(const char *fmt, ...);

#define SYS_ECHO_MAX (4096u)

/**
 * sys_echo() - Echo syscall with case flip
 *
 * Reads data from user input buffer, flips ASCII case (XOR 0x20), and
 * writes result to user output buffer. Used for testing userspace/kernel
 * boundary, copy routines, and uaccess helpers.
 *
 * @param u_in  User input buffer (read-only)
 * @param u_out User output buffer (write-only)
 * @param n     Number of bytes to process
 *
 * Returns:
 *   - Number of bytes processed on success
 *   - -EFAULT if u_in or u_out is NULL
 *   - -EFAULT if copying from/to user fails
 *
 * Behavior:
 *   - Reads up to n bytes from u_in (capped at SYS_ECHO_MAX=4096)
 *   - Flips ASCII case: 'A'→'a', 'a'→'A', others unchanged (XOR 0x20)
 *   - Writes transformed data to u_out
 *   - Processes in 512-byte chunks to limit stack usage
 *   - Returns total bytes processed
 *
 * Case flip behavior:
 *   - ASCII letters: 'A' (0x41) XOR 0x20 = 'a' (0x61)
 *   - ASCII letters: 'a' (0x61) XOR 0x20 = 'A' (0x41)
 *   - Non-letters: mostly unchanged (0x20 flips bit 5)
 *   - Examples: '0' → 'P', ' ' → '\0', '@' → '`'
 *
 * Common usage patterns:
 *
 * Basic echo test:
 *   char in[] = "Hello World";
 *   char out[100];
 *   ssize_t n = sys_echo(in, out, strlen(in));
 *   // out = "hELLO wORLD"
 *
 * Testing copy boundaries:
 *   char *bad_ptr = NULL;
 *   ssize_t ret = sys_echo(bad_ptr, out, 10);
 *   // ret = -EFAULT
 *
 * Large buffer test:
 *   char in[8192], out[8192];
 *   ssize_t n = sys_echo(in, out, 8192);
 *   // Only processes first 4096 bytes (SYS_ECHO_MAX)
 *
 * Related syscalls:
 *   - read()/write(): Standard I/O operations
 *   - copy_from_user()/copy_to_user(): Kernel copy helpers
 *
 * Phase 1 (Completed): Basic echo with XOR case flip
 * Phase 2 (Current): Enhanced validation, buffer categorization, detailed logging
 * Phase 3: Performance optimization, zero-copy support
 * Phase 4: Advanced transformations, streaming support
 */
ssize_t sys_echo(const char *u_in, char *u_out, size_t n) {
    /* Phase 2: Validate user pointers */
    if (!u_in || !u_out) {
        fut_printf("[ECHO] echo(u_in=%p, u_out=%p, n=%zu) -> EFAULT (NULL pointer)\n",
                   (void*)u_in, (void*)u_out, n);
        return -EFAULT;
    }

    /* Phase 2: Clamp to maximum */
    if (n > SYS_ECHO_MAX) {
        n = SYS_ECHO_MAX;
    }

    /* Phase 2: Categorize buffer size */
    const char *size_category;
    if (n == 0) {
        size_category = "empty";
    } else if (n <= 64) {
        size_category = "tiny (≤64)";
    } else if (n <= 512) {
        size_category = "small (65-512)";
    } else if (n <= 4096) {
        size_category = "normal (513-4096)";
    } else {
        size_category = "large (>4096, clamped)";
    }

    /* Handle zero-length case */
    if (n == 0) {
        fut_printf("[ECHO] echo(n=0 [%s]) -> 0 (no-op, Phase 2)\n", size_category);
        return 0;
    }

    char buffer[512];
    size_t offset = 0;
    size_t total_processed = 0;

    while (offset < n) {
        size_t chunk = n - offset;
        if (chunk > sizeof(buffer)) {
            chunk = sizeof(buffer);
        }

        /* Copy from user input */
        int rc = fut_copy_from_user(buffer, u_in + offset, chunk);
        if (rc != 0) {
            fut_printf("[ECHO] echo(n=%zu [%s], offset=%zu) -> EFAULT "
                       "(copy_from_user failed at offset %zu)\n",
                       n, size_category, offset, offset);
            return -EFAULT;
        }

        /* Transform: XOR 0x20 to flip ASCII case */
        for (size_t i = 0; i < chunk; ++i) {
            buffer[i] ^= 0x20u;
        }

        /* Copy to user output */
        rc = fut_copy_to_user(u_out + offset, buffer, chunk);
        if (rc != 0) {
            fut_printf("[ECHO] echo(n=%zu [%s], offset=%zu) -> EFAULT "
                       "(copy_to_user failed at offset %zu)\n",
                       n, size_category, offset, offset);
            return -EFAULT;
        }

        offset += chunk;
        total_processed += chunk;
    }

    /* Phase 2: Detailed success logging */
    fut_printf("[ECHO] echo(n=%zu [%s], u_in=%p, u_out=%p) -> %zd "
               "(case flipped, Phase 2)\n",
               n, size_category, (void*)u_in, (void*)u_out, (ssize_t)total_processed);

    return (ssize_t)total_processed;
}
