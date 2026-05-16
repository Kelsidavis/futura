/* gic_irq_handler.c - ARM64 GIC Interrupt Dispatcher
 *
 * Copyright (c) 2025 Kelsi Davis
 * Licensed under the MPL v2.0 — see LICENSE for details.
 *
 * Handles IRQ exceptions by reading the GIC interrupt acknowledge register,
 * dispatching to appropriate handlers, and sending EOI.
 */

#include <stdint.h>
#include <stddef.h>

/* GICv2 CPU Interface registers (from platform_init.c) */
extern volatile uint32_t *gic_cpu_base;

/* GIC CPU Interface register offsets */
#define GICC_IAR    0x000C  /* Interrupt Acknowledge Register */
#define GICC_EOIR   0x0010  /* End of Interrupt Register */

/* Timer interrupt handler.  fut_timer_irq_handler() is the platform-
 * specific wrapper that calls the common fut_timer_tick() *and* writes
 * the next compare value into CNTP_TVAL_EL0 to re-arm the ARM Generic
 * Timer.  Calling fut_timer_tick() alone leaves TVAL at zero (so the
 * timer's ISTATUS stays asserted), which on QEMU virt produced exactly
 * one timer interrupt and then nothing — system_ticks stuck at 1. */
extern void fut_timer_irq_handler(void);

/* ARM Generic Timer PPI assignments on the GIC (QEMU virt + most boards):
 *   26 = hypervisor physical timer
 *   27 = virtual timer       (used when running as a guest under EL2)
 *   29 = secure physical timer
 *   30 = non-secure physical timer  <-- what the kernel programs via CNTP_*
 *
 * platform_init.c configures CNTP_CTL_EL0 / CNTP_TVAL_EL0 (non-secure
 * physical timer), so the matching GIC PPI is 30.  The previous value
 * of 27 (virtual timer) meant the GIC never raised an IRQ for the
 * physical timer the kernel actually programmed. */
#define ARM_TIMER_IRQ   30  /* Non-secure EL1 physical timer (CNTP_*) */

/**
 * gic_handle_irq - Main IRQ dispatcher (arm64_vectors.S entry path)
 *
 * Forwards to the live IRQ dispatcher (`fut_irq_main` in
 * platform_init.c) so both the active boot.S/fut_irq_handler path and
 * the arm64_vectors.S path share the same backend-pointer dispatch,
 * IAR/EOI flow, timer routing, and irq_handlers[] consultation.
 * Previously this function duplicated the GIC IAR/EOI logic inline,
 * and changes (e.g. the Apple AIC backend hook in commit 942ee205)
 * had to be replicated by hand.
 */
void gic_handle_irq(void) {
    extern void fut_irq_main(void);
    fut_irq_main();
}
