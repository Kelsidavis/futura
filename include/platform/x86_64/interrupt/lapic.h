/* lapic.h - x86_64 Local APIC (LAPIC) definitions
 *
 * Copyright (c) 2025 Futura OS
 * Licensed under the MPL v2.0 — see LICENSE for details.
 *
 * Local APIC provides per-CPU interrupt control, IPI, and timer.
 */

#pragma once

#include <stdint.h>
#include <stdbool.h>

/* LAPIC Register Offsets (from LAPIC base address) */
#define LAPIC_REG_ID                0x0020   /* LAPIC ID */
#define LAPIC_REG_VERSION           0x0030   /* LAPIC Version */
#define LAPIC_REG_TPR               0x0080   /* Task Priority Register */
#define LAPIC_REG_APR               0x0090   /* Arbitration Priority Register */
#define LAPIC_REG_PPR               0x00A0   /* Processor Priority Register */
#define LAPIC_REG_EOI               0x00B0   /* End Of Interrupt */
#define LAPIC_REG_RRD               0x00C0   /* Remote Read Register */
#define LAPIC_REG_LDR               0x00D0   /* Logical Destination Register */
#define LAPIC_REG_DFR               0x00E0   /* Destination Format Register */
#define LAPIC_REG_SVR               0x00F0   /* Spurious Interrupt Vector Register */
#define LAPIC_REG_ISR0              0x0100   /* In-Service Register (bits 0-31) */
#define LAPIC_REG_ISR1              0x0110   /* In-Service Register (bits 32-63) */
#define LAPIC_REG_ISR2              0x0120   /* In-Service Register (bits 64-95) */
#define LAPIC_REG_ISR3              0x0130   /* In-Service Register (bits 96-127) */
#define LAPIC_REG_ISR4              0x0140   /* In-Service Register (bits 128-159) */
#define LAPIC_REG_ISR5              0x0150   /* In-Service Register (bits 160-191) */
#define LAPIC_REG_ISR6              0x0160   /* In-Service Register (bits 192-223) */
#define LAPIC_REG_ISR7              0x0170   /* In-Service Register (bits 224-255) */
#define LAPIC_REG_TMR0              0x0180   /* Trigger Mode Register (bits 0-31) */
#define LAPIC_REG_IRR0              0x0200   /* Interrupt Request Register (bits 0-31) */
#define LAPIC_REG_ESR               0x0280   /* Error Status Register */
#define LAPIC_REG_LVT_CMCI          0x02F0   /* LVT CMCI Register */
#define LAPIC_REG_ICR_LOW           0x0300   /* Interrupt Command Register (bits 0-31) */
#define LAPIC_REG_ICR_HIGH          0x0310   /* Interrupt Command Register (bits 32-63) */
#define LAPIC_REG_LVT_TIMER         0x0320   /* LVT Timer Register */
#define LAPIC_REG_LVT_THERMAL       0x0330   /* LVT Thermal Sensor Register */
#define LAPIC_REG_LVT_PERF          0x0340   /* LVT Performance Counter Register */
#define LAPIC_REG_LVT_LINT0         0x0350   /* LVT LINT0 Register */
#define LAPIC_REG_LVT_LINT1         0x0360   /* LVT LINT1 Register */
#define LAPIC_REG_LVT_ERROR         0x0370   /* LVT Error Register */
#define LAPIC_REG_TIMER_INITIAL     0x0380   /* Timer Initial Count */
#define LAPIC_REG_TIMER_CURRENT     0x0390   /* Timer Current Count */
#define LAPIC_REG_TIMER_DIVIDE      0x03E0   /* Timer Divide Configuration */

/* LAPIC Register Bit Definitions */
#define LAPIC_SVR_ENABLE            0x100    /* APIC Software Enable/Disable */
#define LAPIC_SVR_FOCUS_DISABLED    0x200    /* Focus Processor Checking */

/* LAPIC Delivery Modes */
#define LAPIC_DM_FIXED              0x000
#define LAPIC_DM_LOWEST             0x100
#define LAPIC_DM_SMI                0x200
#define LAPIC_DM_NMI                0x400
#define LAPIC_DM_INIT               0x500
#define LAPIC_DM_STARTUP            0x600
#define LAPIC_DM_EXTINT             0x700

/* LAPIC Destination Modes */
#define LAPIC_DEST_PHYSICAL         0x000
#define LAPIC_DEST_LOGICAL          0x800

/* LAPIC Delivery Status */
#define LAPIC_DS_IDLE               0x0000
#define LAPIC_DS_PENDING            0x1000

/* LAPIC Level */
#define LAPIC_LEVEL_DEASSERT        0x0000
#define LAPIC_LEVEL_ASSERT          0x4000

/* LAPIC Trigger Mode */
#define LAPIC_TM_EDGE               0x0000
#define LAPIC_TM_LEVEL              0x8000

/* LAPIC Destination Shorthand */
#define LAPIC_DSH_DEST              0x00000
#define LAPIC_DSH_SELF              0x40000
#define LAPIC_DSH_ALL               0x80000
#define LAPIC_DSH_OTHERS            0xC0000

/* LAPIC Timer Modes */
#define LAPIC_TIMER_ONESHOT         0x00000
#define LAPIC_TIMER_PERIODIC        0x20000
#define LAPIC_TIMER_TSCDEADLINE     0x40000

/* LAPIC Timer Divide Values */
#define LAPIC_TIMER_DIV_1           0x0B
#define LAPIC_TIMER_DIV_2           0x00
#define LAPIC_TIMER_DIV_4           0x01
#define LAPIC_TIMER_DIV_8           0x02
#define LAPIC_TIMER_DIV_16          0x03
#define LAPIC_TIMER_DIV_32          0x08
#define LAPIC_TIMER_DIV_64          0x09
#define LAPIC_TIMER_DIV_128         0x0A

/* LVT Mask Bit */
#define LAPIC_LVT_MASKED            0x10000

/* Spurious interrupt vector */
#define LAPIC_SPURIOUS_VECTOR       0xFF

/**
 * Initialize Local APIC for the current CPU.
 * Maps LAPIC MMIO region, enables APIC, and sets up basic configuration.
 *
 * @param lapic_base Physical address of LAPIC (usually 0xFEE00000)
 */
void lapic_init(uint64_t lapic_base);

/**
 * Get the current CPU's APIC ID.
 *
 * @return APIC ID (0-255)
 */
uint32_t lapic_get_id(void);

/**
 * Get LAPIC version information.
 *
 * @return Version register value
 */
uint32_t lapic_get_version(void);

/**
 * Send End-Of-Interrupt to LAPIC.
 * Must be called at the end of interrupt handlers.
 */
void lapic_send_eoi(void);

/**
 * Send IPI (Inter-Processor Interrupt) to target CPU.
 *
 * @param apic_id Target CPU's APIC ID
 * @param vector Interrupt vector
 */
void lapic_send_ipi(uint32_t apic_id, uint32_t vector);

/**
 * Send INIT IPI to target CPU.
 *
 * @param apic_id Target CPU's APIC ID
 */
void lapic_send_init_ipi(uint32_t apic_id);

/**
 * Send SIPI (Startup IPI) to target CPU.
 *
 * @param apic_id Target CPU's APIC ID
 * @param vector Startup vector (page number where trampoline code is located)
 */
void lapic_send_sipi(uint32_t apic_id, uint8_t vector);

/**
 * Send IPI to all CPUs except self using destination shorthand.
 * Broadcasts efficiently without specifying individual APIC IDs.
 *
 * @param vector Interrupt vector
 */
void lapic_send_ipi_all_except_self(uint32_t vector);

/**
 * Send IPI to all CPUs including self using destination shorthand.
 * Broadcasts to all processors including the sender.
 *
 * @param vector Interrupt vector
 */
void lapic_send_ipi_all_including_self(uint32_t vector);

/**
 * Enable LAPIC timer in one-shot mode.
 *
 * @param initial_count Initial timer count
 * @param vector Interrupt vector for timer
 */
void lapic_timer_oneshot(uint32_t initial_count, uint8_t vector);

/**
 * Enable LAPIC timer in periodic mode.
 *
 * @param initial_count Initial timer count (reloaded automatically)
 * @param vector Interrupt vector for timer
 */
void lapic_timer_periodic(uint32_t initial_count, uint8_t vector);

/**
 * Disable LAPIC timer.
 */
void lapic_timer_disable(void);

/**
 * Check if LAPIC is enabled.
 *
 * @return true if LAPIC is enabled
 */
bool lapic_is_enabled(void);
