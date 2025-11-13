/* ARM64 Minimal Stubs for ARM64 Build
 * Provides minimal implementations to allow ARM64 kernel to link
 * These are stubs to satisfy linker requirements for boot
 */

#include <kernel/fut_mm.h>
#include <platform/arm64/interrupt/irq.h>
#include <stdint.h>
#include <stddef.h>
#include <string.h>

/* ============================================================
 *   Scheduler and Timer Management
 * ============================================================
 * NOTE: fut_scheduler_init() and fut_timer_set_timeout() are
 * implemented in kernel/sched/arm64_process.c and kernel/irq/arm64_irq.c
 * respectively. Remove stubs that would conflict with real implementations.
 * ============================================================ */

/* ============================================================
 *   C Library String Functions
 * ============================================================ */

/* Note: strcmp() and strstr() are defined in kernel/rt/memory.c
 * to avoid duplicates. This file only contains stubs that are
 * not defined elsewhere.
 */

/* ============================================================
 *   LibGCC Stubs
 * ============================================================ */

/**
 * Stub for __getauxval from libgcc.
 * libgcc uses this to detect LSE atomics support.
 * Returns 0 to indicate no auxiliary vector available (bare-metal).
 */
unsigned long __getauxval(unsigned long type) {
    (void)type;
    return 0;  /* No aux vector in bare-metal */
}

/* ============================================================
 *   IRQ Handler Registration
 * ============================================================
 * NOTE: fut_register_irq_handler() is implemented in kernel/irq/arm64_irq.c
 * Remove stub that would conflict with real implementation.
 * ============================================================ */

/* ============================================================
 *   Serial/Console I/O
 * ============================================================ */

/* Note: fut_serial_getc() and fut_serial_getc_blocking() are
 * defined in platform/arm64/platform_init.c to avoid duplicates.
 * This file only contains stubs that are not defined elsewhere.
 */
