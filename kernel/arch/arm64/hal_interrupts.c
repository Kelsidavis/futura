// SPDX-License-Identifier: MPL-2.0
/*
 * kernel/arch/arm64/hal_interrupts.c - ARM64 implementation of interrupt control
 */

#include <kernel/hal/interrupts.h>
#include <stdint.h>

/**
 * Disable interrupts and return the previous state (DAIF.I bit).
 * ARM64 DAIF register: bits [7:4] = {D, A, I, F}
 * D = Debug exceptions (bit 7)
 * A = SError/Async abort (bit 6)
 * I = IRQ (bit 5)
 * F = FIQ (bit 4)
 */
unsigned long hal_intr_disable(void) {
    uint64_t daif, old_daif;

    /* Read DAIF register */
    __asm__ volatile("mrs %0, daif" : "=r"(daif));
    old_daif = daif;

    /* Disable IRQ (set I bit) */
    __asm__ volatile("msr daifset, #2");  /* #2 = IRQ bit */

    /* Return previous I bit state (bit 5 or shifted bit 1) */
    return (old_daif >> 5) & 1;  /* Isolate I bit (bit 5 in DAIF) */
}

/**
 * Enable interrupts.
 */
void hal_intr_enable(void) {
    __asm__ volatile("msr daifclr, #2");  /* #2 = IRQ bit */
}

/**
 * Restore interrupt state to a previous value.
 */
void hal_intr_restore(unsigned long state) {
    if (state) {
        hal_intr_enable();
    } else {
        __asm__ volatile("msr daifset, #2");  /* Disable IRQ */
    }
}

/**
 * Get current interrupt state.
 */
unsigned long hal_intr_state(void) {
    uint64_t daif;
    __asm__ volatile("mrs %0, daif" : "=r"(daif));
    return (daif >> 5) & 1;  /* Isolate I bit (bit 5 in DAIF) */
}

/**
 * Check if interrupts are enabled.
 * Note: ARM64 I bit is inverted: 0 = enabled, 1 = disabled
 * So we return !state to match the semantics of x86-64
 */
int hal_intr_enabled(void) {
    uint64_t daif;
    __asm__ volatile("mrs %0, daif" : "=r"(daif));
    return !((daif >> 5) & 1);  /* I bit: 0 = enabled, 1 = disabled */
}
