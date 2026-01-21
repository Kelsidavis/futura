// SPDX-License-Identifier: MPL-2.0
/*
 * kernel/arch/arm64/hal_halt.c - ARM64 implementation of CPU halt
 */

#include <kernel/hal/halt.h>

#include <kernel/kprintf.h>

/**
 * Halt the CPU unconditionally.
 * ARM64: Wait for interrupt (wfi)
 */
void hal_cpu_halt(void) {
    __asm__ volatile("wfi");
}

/**
 * Enable interrupts and wait for an interrupt.
 * This is the idle thread loop on ARM64.
 * DAIF register: bit 1 is the IRQ mask (0 = enabled, 1 = masked)
 */
void hal_cpu_wait_intr(void) {
    /* Enable IRQ: msr daifset, #2 sets the IRQ mask bit (disabling IRQs)
     * We want daifclr (clear mask) which is #2, not daifset
     * Actually: DAIF[7:4] = {D, A, I, F}
     * I bit (bit 1 in the immediate) = IRQ
     * daifclr with #2 = clear I (enable IRQ)
     * daifset with #2 = set I (disable IRQ)
     * So we want daifclr #2 to enable, not daifset
     */
    __asm__ volatile("msr daifclr, #2\nwfi" ::: "memory");
}

/**
 * Halt the CPU with a panic message.
 */
void hal_cpu_panic_halt(const char *msg) {
    if (msg) {
        fut_printf("PANIC: %s\n", msg);
    }
    /* Disable interrupts before halting */
    __asm__ volatile("msr daifset, #2");  /* Disable IRQ */
    hal_cpu_halt();
}
