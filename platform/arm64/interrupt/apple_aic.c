/* apple_aic.c - Apple Interrupt Controller (AIC) Implementation
 *
 * Copyright (c) 2025 Kelsi Davis
 * Licensed under the MPL v2.0 — see LICENSE for details.
 *
 * Implementation of Apple Interrupt Controller for M1/M2/M3 SoCs.
 * Based on Asahi Linux AIC driver and documentation.
 */

#include <platform/arm64/apple_aic.h>
#include <platform/platform.h>
#include <string.h>
#include <stddef.h>

/* ============================================================
 *   AIC Register Access
 * ============================================================ */

/* Base address of AIC registers (set during init) */
static volatile uint8_t *aic_base = NULL;

/* Helper macros for register access */
#define AIC_READ32(offset)      (*((volatile uint32_t *)(aic_base + (offset))))
#define AIC_WRITE32(offset, val) (*((volatile uint32_t *)(aic_base + (offset))) = (val))

/* ============================================================
 *   AIC Event Bitmap Helpers
 * ============================================================ */

/**
 * Calculate the register offset and bit position for an IRQ.
 * AIC uses 32 IRQs per register (one bit per IRQ).
 */
static inline void aic_irq_to_reg_bit(uint32_t irq_num, uint32_t *reg_offset, uint32_t *bit) {
    *reg_offset = (irq_num / 32) * 4;  /* 4 bytes per register */
    *bit = irq_num % 32;
}

/* ============================================================
 *   AIC Initialization
 * ============================================================ */

bool fut_apple_aic_init(const fut_platform_info_t *info) {
    if (!info || !info->has_aic || info->aic_base == 0) {
        fut_printf("[AIC] Error: Invalid platform info or missing AIC\n");
        return false;
    }

    /* Map AIC base address */
    aic_base = (volatile uint8_t *)info->aic_base;

    /* Read AIC version/info register */
    uint32_t aic_info = AIC_READ32(AIC_INFO);
    uint32_t aic_version = (aic_info >> 16) & 0xFF;
    uint32_t num_irqs = (aic_info & 0xFFFF);

    fut_printf("[AIC] Apple Interrupt Controller detected\n");
    fut_printf("[AIC] Version: 0x%x, IRQs: %u\n", aic_version, num_irqs);
    fut_printf("[AIC] Base address: 0x%016llx\n", info->aic_base);

    /* Mask all IRQs initially (write 0xFFFFFFFF to all MASK_SET registers) */
    for (uint32_t i = 0; i < (AIC_MAX_IRQS / 32); i++) {
        AIC_WRITE32(AIC_MASK_SET + (i * 4), 0xFFFFFFFF);
    }

    /* Clear any pending events */
    for (uint32_t i = 0; i < (AIC_MAX_IRQS / 32); i++) {
        /* Read-only EVENT register, can't clear directly */
        /* Instead, acknowledge all by writing to mask */
    }

    /* Enable IPI support */
    AIC_WRITE32(AIC_IPI_MASK_CLR, 0xFFFFFFFF);  /* Unmask all IPI sources */

    /* Get current CPU ID */
    uint32_t cpu_id = fut_apple_aic_whoami();
    fut_printf("[AIC] Initialized on CPU %u\n", cpu_id);

    return true;
}

/* ============================================================
 *   IRQ Control Functions
 * ============================================================ */

void fut_apple_aic_enable_irq(uint32_t irq_num) {
    if (irq_num >= AIC_MAX_IRQS) {
        return;
    }

    uint32_t reg_offset, bit;
    aic_irq_to_reg_bit(irq_num, &reg_offset, &bit);

    /* Write to MASK_CLR to unmask (enable) the IRQ */
    AIC_WRITE32(AIC_MASK_CLR + reg_offset, (1U << bit));
}

void fut_apple_aic_disable_irq(uint32_t irq_num) {
    if (irq_num >= AIC_MAX_IRQS) {
        return;
    }

    uint32_t reg_offset, bit;
    aic_irq_to_reg_bit(irq_num, &reg_offset, &bit);

    /* Write to MASK_SET to mask (disable) the IRQ */
    AIC_WRITE32(AIC_MASK_SET + reg_offset, (1U << bit));
}

bool fut_apple_aic_is_pending(uint32_t irq_num) {
    if (irq_num >= AIC_MAX_IRQS) {
        return false;
    }

    uint32_t reg_offset, bit;
    aic_irq_to_reg_bit(irq_num, &reg_offset, &bit);

    /* Read EVENT register to check if IRQ is pending */
    uint32_t event = AIC_READ32(AIC_EVENT + reg_offset);
    return (event & (1U << bit)) != 0;
}

void fut_apple_aic_ack_irq(uint32_t irq_num) {
    if (irq_num >= AIC_MAX_IRQS) {
        return;
    }

    /* On AIC, EOI is done by the hardware when the event is processed */
    /* Some implementations may require explicit acknowledgment */
    /* For now, this is a no-op - hardware auto-clears on read */
}

/* ============================================================
 *   IPI (Inter-Processor Interrupt) Functions
 * ============================================================ */

void fut_apple_aic_send_ipi(uint32_t target_cpu, uint32_t ipi_num) {
    if (target_cpu >= AIC_MAX_CPUS || ipi_num >= AIC_MAX_IPIS) {
        return;
    }

    /* IPI_SEND register format: [31:24]=IPI num, [15:0]=target CPU mask */
    uint32_t ipi_cmd = (ipi_num << 24) | (1U << target_cpu);
    AIC_WRITE32(AIC_IPI_SEND, ipi_cmd);
}

void fut_apple_aic_ack_ipi(uint32_t ipi_num) {
    if (ipi_num >= AIC_MAX_IPIS) {
        return;
    }

    /* Acknowledge IPI by writing IPI number to ACK register */
    AIC_WRITE32(AIC_IPI_ACK, ipi_num);
}

uint32_t fut_apple_aic_whoami(void) {
    /* Read WHOAMI register to get current CPU ID */
    uint32_t whoami = AIC_READ32(AIC_WHOAMI);
    return whoami & 0xFF;  /* Lower 8 bits contain CPU ID */
}

/* ============================================================
 *   IRQ Handler
 * ============================================================ */

/* Timer interrupt handler (defined elsewhere) */
extern void fut_timer_tick(void);

void apple_aic_handle_irq(void) {
    if (!aic_base) {
        /* AIC not initialized yet - spurious interrupt */
        return;
    }

    /* Read event pending bitmap */
    uint32_t pending = AIC_READ32(AIC_EVENT_PENDING);

    if (pending == 0) {
        /* No pending interrupts - spurious */
        return;
    }

    /* Scan all IRQ registers to find pending interrupts */
    for (uint32_t reg = 0; reg < (AIC_MAX_IRQS / 32); reg++) {
        uint32_t event = AIC_READ32(AIC_EVENT + (reg * 4));

        if (event == 0) {
            continue;  /* No pending IRQs in this register */
        }

        /* Find first set bit (pending IRQ) */
        for (uint32_t bit = 0; bit < 32; bit++) {
            if (event & (1U << bit)) {
                uint32_t irq_num = (reg * 32) + bit;

                /* Dispatch to appropriate handler based on IRQ number */
                switch (irq_num) {
                    case APPLE_TIMER_IRQ:
                        /* ARM Generic Timer virtual timer interrupt */
                        fut_timer_tick();
                        break;

                    default:
                        /* Unknown interrupt - ignore for now */
                        break;
                }

                /* Acknowledge IRQ (auto-clears on most AIC versions) */
                fut_apple_aic_ack_irq(irq_num);

                /* Only handle one IRQ per exception for simplicity */
                return;
            }
        }
    }
}

/* ============================================================
 *   Platform Integration
 * ============================================================ */

void fut_apple_irq_init(const fut_platform_info_t *info) {
    if (!info || !info->has_aic) {
        fut_printf("[APPLE] Error: Platform does not support Apple AIC\n");
        return;
    }

    fut_printf("[APPLE] Initializing Apple Interrupt Controller\n");

    if (!fut_apple_aic_init(info)) {
        fut_printf("[APPLE] Error: Failed to initialize AIC\n");
        return;
    }

    /* Enable ARM Generic Timer interrupt (routed through FIQ, not AIC) */
    /* Timer initialization will be done separately */

    fut_printf("[APPLE] Apple interrupt subsystem initialized\n");
}
