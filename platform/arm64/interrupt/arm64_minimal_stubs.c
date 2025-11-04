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
 *   Scheduling Stubs
 * ============================================================ */

void fut_scheduler_init(void) {
    /* Stub: Scheduler initialization (basic stub for boot) */
    return;
}

/* ============================================================
 *   Timer Management Stubs
 * ============================================================ */

void fut_timer_set_timeout(uint64_t ticks) {
    /* Stub: Timer configuration for ARM64 */
    (void)ticks;
    return;
}

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
 *   IRQ Handler Registration Stub
 * ============================================================ */

/**
 * Stub for registering IRQ handlers on ARM64.
 * ARM64 interrupt handling is basic during early platform initialization.
 */
typedef void (*fut_irq_handler_t)(int, struct fut_interrupt_frame *);

int fut_register_irq_handler(int irq, fut_irq_handler_t handler) {
    (void)irq;
    (void)handler;
    return 0;  /* Success - stub implementation */
}

/* ============================================================
 *   Serial/Console I/O
 * ============================================================ */

/* Note: fut_serial_getc() and fut_serial_getc_blocking() are
 * defined in platform/arm64/platform_init.c to avoid duplicates.
 * This file only contains stubs that are not defined elsewhere.
 */
