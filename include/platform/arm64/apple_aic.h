/* apple_aic.h - Apple Interrupt Controller (AIC)
 *
 * Copyright (c) 2025 Kelsi Davis
 * Licensed under the MPL v2.0 — see LICENSE for details.
 *
 * Apple Interrupt Controller for M1/M2/M3 SoCs.
 * Based on Asahi Linux implementation and documentation.
 */

#ifndef __FUTURA_ARM64_APPLE_AIC_H__
#define __FUTURA_ARM64_APPLE_AIC_H__

#include <stdint.h>
#include <stdbool.h>
#include <platform/arm64/dtb.h>

/* ============================================================
 *   AIC Register Offsets (from Asahi Linux)
 * ============================================================ */

/* AIC version and info */
#define AIC_INFO            0x0004  /* AIC version and config */
#define AIC_CONFIG          0x0010  /* Global configuration */

/* Event registers (per-IRQ status) */
#define AIC_EVENT           0x2000  /* Event status (read-only) */
#define AIC_EVENT_TYPE      0x2800  /* Event type (0=IRQ, 1=FIQ) */

/* Mask set/clear registers */
#define AIC_MASK_SET        0x4000  /* Set interrupt mask (disable IRQ) */
#define AIC_MASK_CLR        0x4080  /* Clear interrupt mask (enable IRQ) */

/* Software-generated interrupts (IPI) */
#define AIC_IPI_SEND        0x6000  /* Send IPI to target CPU */
#define AIC_IPI_ACK         0x6004  /* Acknowledge IPI */
#define AIC_IPI_MASK_SET    0x6008  /* Mask IPI sources */
#define AIC_IPI_MASK_CLR    0x600C  /* Unmask IPI sources */

/* Target CPU registers (IRQ routing) */
#define AIC_TARGET_CPU      0x7000  /* IRQ target CPU (8 IRQs per u32) */

/* Per-CPU registers */
#define AIC_WHOAMI          0x2000  /* Current CPU ID */
#define AIC_EVENT_PENDING   0x2004  /* Pending event bitmap */

/* ============================================================
 *   AIC Constants
 * ============================================================ */

#define AIC_MAX_IRQS        896     /* Maximum hardware IRQs */
#define AIC_MAX_IPIS        32      /* Maximum IPI sources */
#define AIC_MAX_CPUS        16      /* Maximum CPU count */

/* ARM Generic Timer IRQ on Apple Silicon (bypasses AIC, wired to FIQ) */
#define APPLE_TIMER_IRQ     27      /* Virtual timer (same as GIC numbering) */

/* ============================================================
 *   AIC Initialization Functions
 * ============================================================ */

/**
 * Initialize Apple Interrupt Controller.
 * Maps AIC registers, configures defaults, enables IPIs.
 * @param info: Platform information with aic_base address
 * @return: true on success, false on failure
 */
bool fut_apple_aic_init(const fut_platform_info_t *info);

/**
 * Enable a specific hardware IRQ.
 * Unmasks the IRQ in the AIC MASK_CLR register.
 * @param irq_num: Hardware IRQ number (0-895)
 */
void fut_apple_aic_enable_irq(uint32_t irq_num);

/**
 * Disable a specific hardware IRQ.
 * Masks the IRQ in the AIC MASK_SET register.
 * @param irq_num: Hardware IRQ number (0-895)
 */
void fut_apple_aic_disable_irq(uint32_t irq_num);

/**
 * Check if an IRQ is pending.
 * Reads the AIC EVENT register to check IRQ status.
 * @param irq_num: Hardware IRQ number (0-895)
 * @return: true if pending, false otherwise
 */
bool fut_apple_aic_is_pending(uint32_t irq_num);

/**
 * Acknowledge (EOI) a hardware IRQ.
 * On AIC, this is typically done by clearing the event bit.
 * @param irq_num: Hardware IRQ number (0-895)
 */
void fut_apple_aic_ack_irq(uint32_t irq_num);

/**
 * Send an inter-processor interrupt (IPI).
 * @param target_cpu: Target CPU ID (0-15)
 * @param ipi_num: IPI number (0-31)
 */
void fut_apple_aic_send_ipi(uint32_t target_cpu, uint32_t ipi_num);

/**
 * Acknowledge an IPI on the current CPU.
 * @param ipi_num: IPI number to acknowledge
 */
void fut_apple_aic_ack_ipi(uint32_t ipi_num);

/**
 * Get the current CPU ID from AIC WHOAMI register.
 * @return: Current CPU ID (0-15)
 */
uint32_t fut_apple_aic_whoami(void);

/**
 * Main AIC IRQ handler.
 * Called from ARM64 IRQ exception vector on Apple Silicon.
 * Reads pending events, dispatches handlers, sends EOI.
 */
void apple_aic_handle_irq(void);

/* ============================================================
 *   AIC Integration with Platform
 * ============================================================ */

/**
 * Initialize Apple Silicon interrupt subsystem.
 * This is the high-level entry point called from platform init.
 * @param info: Platform information
 */
void fut_apple_irq_init(const fut_platform_info_t *info);

#endif /* __FUTURA_ARM64_APPLE_AIC_H__ */
