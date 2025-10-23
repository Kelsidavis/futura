// SPDX-License-Identifier: MPL-2.0
/*
 * kernel/arch/x86_64/hal_interrupts.c - x86-64 implementation of interrupt control
 */

#include <kernel/hal/interrupts.h>
#include <stdint.h>

/**
 * Disable interrupts and return the previous state (RFLAGS.IF bit).
 */
unsigned long hal_intr_disable(void) {
    uint64_t rflags;

    /* Read RFLAGS into rflags */
    __asm__ volatile("pushfq\npopq %0" : "=r"(rflags));

    /* Disable interrupts */
    __asm__ volatile("cli");

    /* Return previous state */
    return rflags & 0x200;  /* Isolate IF bit (bit 9) */
}

/**
 * Enable interrupts.
 */
void hal_intr_enable(void) {
    __asm__ volatile("sti");
}

/**
 * Restore interrupt state to a previous value.
 */
void hal_intr_restore(unsigned long state) {
    if (state) {
        hal_intr_enable();
    } else {
        __asm__ volatile("cli");
    }
}

/**
 * Get current interrupt state.
 */
unsigned long hal_intr_state(void) {
    uint64_t rflags;
    __asm__ volatile("pushfq\npopq %0" : "=r"(rflags));
    return rflags & 0x200;  /* Isolate IF bit (bit 9) */
}

/**
 * Check if interrupts are enabled.
 */
int hal_intr_enabled(void) {
    return hal_intr_state() != 0;
}
