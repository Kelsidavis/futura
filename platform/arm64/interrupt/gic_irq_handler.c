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

/* Timer interrupt handler */
extern void fut_timer_tick(void);

/* ARM Generic Timer interrupt ID on QEMU virt machine */
#define ARM_TIMER_IRQ   27  /* Virtual timer interrupt */

/**
 * gic_handle_irq - Main IRQ dispatcher
 *
 * Called from ARM64 IRQ exception vector. Reads the GIC IAR to determine
 * which interrupt fired, dispatches to appropriate handler, and sends EOI.
 */
void gic_handle_irq(void) {
    if (!gic_cpu_base) {
        /* GIC not initialized yet - spurious interrupt */
        return;
    }

    /* Read Interrupt Acknowledge Register to get interrupt ID */
    uint32_t iar = gic_cpu_base[GICC_IAR / sizeof(uint32_t)];
    uint32_t irq_id = iar & 0x3FF;  /* Lower 10 bits contain interrupt ID */

    /* Spurious interrupt check (ID 1023) */
    if (irq_id == 1023) {
        return;
    }

    /* Dispatch to appropriate handler */
    if (irq_id == ARM_TIMER_IRQ) {
        fut_timer_tick();
    } else {
        /* Dispatch to registered handler from irq_handlers table */
        extern int fut_dispatch_irq(uint32_t irq_id);
        fut_dispatch_irq(irq_id);
    }

    /* Send End of Interrupt signal to GIC */
    gic_cpu_base[GICC_EOIR / sizeof(uint32_t)] = iar;
}
