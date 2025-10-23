// SPDX-License-Identifier: MPL-2.0
/*
 * kernel/arch/x86_64/hal_halt.c - x86-64 implementation of CPU halt
 */

#include <kernel/hal/halt.h>
#include <stdio.h>

extern void fut_printf(const char *fmt, ...);

/**
 * Halt the CPU unconditionally.
 */
void hal_cpu_halt(void) {
    __asm__ volatile("hlt");
}

/**
 * Enable interrupts and wait for an interrupt.
 * This is the idle thread loop on x86-64.
 */
void hal_cpu_wait_intr(void) {
    __asm__ volatile("sti\n\thlt" ::: "memory");
}

/**
 * Halt the CPU with a panic message.
 */
void hal_cpu_panic_halt(const char *msg) {
    if (msg) {
        fut_printf("PANIC: %s\n", msg);
    }
    /* Disable interrupts before halting */
    __asm__ volatile("cli");
    hal_cpu_halt();
}
