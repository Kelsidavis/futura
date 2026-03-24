// SPDX-License-Identifier: MPL-2.0
/*
 * kernel/arch/arm64/hal_halt.c - ARM64 implementation of CPU halt
 */

#include <kernel/hal/halt.h>
#include <stdint.h>
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
 * Prints stack trace to aid post-mortem debugging.
 */
void hal_cpu_panic_halt(const char *msg) {
    /* Disable interrupts immediately to prevent further damage */
    __asm__ volatile("msr daifset, #15");  /* Disable all exceptions */

    fut_printf("\n*** KERNEL PANIC ***\n");
    if (msg) {
        fut_printf("  %s\n", msg);
    }

    /* Print stack trace */
    extern void fut_platform_stack_trace(int max_frames);
    fut_platform_stack_trace(16);

    /* Print CPU state */
    uint64_t elr, esr, far_val, sp;
    __asm__ volatile("mrs %0, elr_el1" : "=r"(elr));
    __asm__ volatile("mrs %0, esr_el1" : "=r"(esr));
    __asm__ volatile("mrs %0, far_el1" : "=r"(far_val));
    __asm__ volatile("mov %0, sp" : "=r"(sp));
    fut_printf("  ELR=0x%016llx ESR=0x%016llx\n",
               (unsigned long long)elr, (unsigned long long)esr);
    fut_printf("  FAR=0x%016llx SP=0x%016llx\n",
               (unsigned long long)far_val, (unsigned long long)sp);

    fut_printf("*** System halted ***\n");

    for (;;) {
        hal_cpu_halt();
    }
}
