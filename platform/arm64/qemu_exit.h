/* platform/arm64/qemu_exit.h - Exit QEMU on AArch64 via semihosting
 *
 * Copyright (c) 2025 Kelsi Davis
 * Licensed under the MPL v2.0 — see LICENSE for details.
 *
 * Uses ARM semihosting SYS_EXIT_EXTENDED (0x20) to terminate QEMU with
 * a specific exit code. Requires QEMU to be started with:
 *   -semihosting-config enable=on,target=native
 *
 * Exit code mapping (matches x86_64 isa-debug-exit convention):
 *   code 0 → QEMU exit 1 (success, matches (0 << 1) | 1)
 *   code N → QEMU exit (N << 1) | 1
 */

#pragma once

#include <stdint.h>
#include <stdnoreturn.h>

/* ARM Semihosting operation numbers */
#define SEMIHOSTING_SYS_EXIT_EXTENDED  0x20

/* ADP (Angel Debug Protocol) stopped reasons */
#define ADP_Stopped_ApplicationExit   0x20026

static inline noreturn void qemu_exit(int code) {
    /* SYS_EXIT_EXTENDED takes a pointer to a two-word parameter block:
     *   [0] = ADP_Stopped_ApplicationExit (0x20026)
     *   [1] = exit code
     * Map code 0 → exit 1 (success), code N → exit (N<<1)|1 (failure) */
    uint64_t params[2] = {
        ADP_Stopped_ApplicationExit,
        (code == 0) ? 0 : (uint64_t)(((unsigned)code << 1) | 1)
    };

    register uint64_t x0 __asm__("x0") = SEMIHOSTING_SYS_EXIT_EXTENDED;
    register uint64_t x1 __asm__("x1") = (uint64_t)(uintptr_t)params;

    /* HLT #0xF000 is the semihosting trap for AArch64 */
    __asm__ volatile("hlt #0xF000" : "+r"(x0) : "r"(x1) : "memory");

    /* Fallback: PSCI SYSTEM_OFF if semihosting didn't work */
    x0 = 0x84000008;  /* PSCI_0_2_FN_SYSTEM_OFF */
    __asm__ volatile("hvc #0" : "+r"(x0));

    __builtin_unreachable();
}
