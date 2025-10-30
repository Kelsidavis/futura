/* ioapic.h - x86_64 IO-APIC (I/O Advanced Programmable Interrupt Controller)
 *
 * Copyright (c) 2025 Futura OS
 * Licensed under the MPL v2.0 — see LICENSE for details.
 *
 * IO-APIC routes external interrupts (IRQs) to LAPICs in SMP systems.
 */

#pragma once

#include <stdint.h>
#include <stdbool.h>

/* IO-APIC Register Offsets (from IO-APIC base) */
#define IOAPIC_REG_ID           0x00    /* IO-APIC ID */
#define IOAPIC_REG_VER          0x01    /* IO-APIC Version */
#define IOAPIC_REG_ARB          0x02    /* IO-APIC Arbitration ID */
#define IOAPIC_REG_REDTBL_BASE  0x10    /* Redirection Table base (entries 0x10-0x3F) */

/* IO-APIC Memory-Mapped Registers */
#define IOAPIC_REGSEL           0x00    /* Register Select (offset from base) */
#define IOAPIC_WIN              0x10    /* Register Window (offset from base) */

/* Redirection Table Entry Bits */
#define IOAPIC_REDIR_VECTOR_MASK    0x000000FF
#define IOAPIC_REDIR_DELMOD_MASK    0x00000700
#define IOAPIC_REDIR_DESTMOD        0x00000800  /* 0=Physical, 1=Logical */
#define IOAPIC_REDIR_DELIVS         0x00001000  /* Delivery Status (RO) */
#define IOAPIC_REDIR_INTPOL         0x00002000  /* Interrupt Polarity (0=High, 1=Low) */
#define IOAPIC_REDIR_REMOTEIRR      0x00004000  /* Remote IRR (RO) */
#define IOAPIC_REDIR_TRIGGERMOD     0x00008000  /* Trigger Mode (0=Edge, 1=Level) */
#define IOAPIC_REDIR_MASK           0x00010000  /* Interrupt Mask (0=Enabled, 1=Masked) */

/* Delivery Modes */
#define IOAPIC_DELMOD_FIXED         0x00000000
#define IOAPIC_DELMOD_LOWEST        0x00000100
#define IOAPIC_DELMOD_SMI           0x00000200
#define IOAPIC_DELMOD_NMI           0x00000400
#define IOAPIC_DELMOD_INIT          0x00000500
#define IOAPIC_DELMOD_EXTINT        0x00000700

/* Redirection Table Entry Structure */
typedef struct {
    uint64_t vector         : 8;    /* Interrupt vector (0-255) */
    uint64_t delmod         : 3;    /* Delivery mode */
    uint64_t destmod        : 1;    /* Destination mode (0=physical, 1=logical) */
    uint64_t delivs         : 1;    /* Delivery status (read-only) */
    uint64_t intpol         : 1;    /* Interrupt polarity (0=high, 1=low) */
    uint64_t remoteirr      : 1;    /* Remote IRR (read-only) */
    uint64_t triggermod     : 1;    /* Trigger mode (0=edge, 1=level) */
    uint64_t mask           : 1;    /* Interrupt mask (0=enabled, 1=masked) */
    uint64_t reserved       : 39;   /* Reserved */
    uint64_t destination    : 8;    /* Destination APIC ID */
} __attribute__((packed)) ioapic_redir_entry_t;

/* MADT Interrupt Override Structure */
typedef struct {
    uint8_t bus;                    /* Bus type (0 = ISA) */
    uint8_t source;                 /* Source IRQ */
    uint32_t gsi;                   /* Global System Interrupt */
    uint16_t flags;                 /* MPS INTI flags (polarity, trigger) */
    bool valid;                     /* Whether this entry is populated */
} ioapic_override_t;

/* GSI to Vector Mapping Structure */
typedef struct {
    uint32_t gsi;                   /* Global System Interrupt (0-23+) */
    uint8_t vector;                 /* Assigned interrupt vector */
    uint8_t polarity;               /* 0=high, 1=low (from MADT flags) */
    uint8_t trigger_mode;           /* 0=edge, 1=level (from MADT flags) */
    bool allocated;                 /* Whether this GSI has been configured */
} gsi_mapping_t;

/* Maximum number of overrides (ISA IRQs + device IRQs) */
#define IOAPIC_MAX_OVERRIDES 256
#define IOAPIC_MAX_GSI_MAPPINGS 256

/**
 * Initialize IO-APIC.
 *
 * @param ioapic_base Physical address of IO-APIC
 * @param gsi_base Global System Interrupt base for this IO-APIC
 * @return 0 on success, negative on error
 */
int ioapic_init(uint64_t ioapic_base, uint32_t gsi_base);

/**
 * Get IO-APIC ID.
 *
 * @return IO-APIC ID
 */
uint32_t ioapic_get_id(void);

/**
 * Get IO-APIC version and entry count.
 *
 * @param max_entries Output: maximum redirection entries (0-23 typically)
 * @return Version number
 */
uint32_t ioapic_get_version(uint32_t *max_entries);

/**
 * Set redirection entry for an IRQ.
 *
 * @param irq IRQ number (0-23)
 * @param vector Interrupt vector to route to
 * @param dest_apic_id Destination LAPIC ID
 * @param mask true to mask (disable), false to unmask (enable)
 * @param trigger_level true for level-triggered, false for edge-triggered
 */
void ioapic_set_irq(uint8_t irq, uint8_t vector, uint8_t dest_apic_id,
                    bool mask, bool trigger_level);

/**
 * Mask (disable) an IRQ.
 *
 * @param irq IRQ number to mask
 */
void ioapic_mask_irq(uint8_t irq);

/**
 * Unmask (enable) an IRQ.
 *
 * @param irq IRQ number to unmask
 */
void ioapic_unmask_irq(uint8_t irq);

/**
 * Read redirection table entry.
 *
 * @param irq IRQ number
 * @return 64-bit redirection entry
 */
uint64_t ioapic_read_redir(uint8_t irq);

/**
 * Write redirection table entry.
 *
 * @param irq IRQ number
 * @param value 64-bit redirection entry
 */
void ioapic_write_redir(uint8_t irq, uint64_t value);

/**
 * Store a MADT interrupt override for later processing.
 *
 * @param bus Bus number (typically 0 for ISA)
 * @param source Source IRQ on the bus
 * @param gsi Global System Interrupt number
 * @param flags MADT INTI flags (polarity, trigger mode)
 */
void ioapic_store_override(uint8_t bus, uint8_t source, uint32_t gsi, uint16_t flags);

/**
 * Look up the GSI for an ISA IRQ based on stored overrides.
 * Falls back to default mapping if no override found.
 *
 * @param isa_irq ISA IRQ number (0-15)
 * @return GSI number
 */
uint32_t ioapic_get_gsi_for_isa_irq(uint8_t isa_irq);

/**
 * Get interrupt override information.
 *
 * @param gsi Global System Interrupt
 * @return Pointer to override structure, or NULL if not found
 */
const ioapic_override_t *ioapic_get_override(uint32_t gsi);

/**
 * Get polarity setting for a GSI from MADT overrides.
 *
 * @param gsi Global System Interrupt
 * @return 0 for active high, 1 for active low
 */
uint8_t ioapic_get_polarity(uint32_t gsi);

/**
 * Get trigger mode for a GSI from MADT overrides.
 *
 * @param gsi Global System Interrupt
 * @return 0 for edge-triggered, 1 for level-triggered
 */
uint8_t ioapic_get_trigger_mode(uint32_t gsi);

/**
 * Initialize the vector allocator (call once at boot).
 * Marks vectors 0-31 as reserved (exceptions), 32-255 available for devices.
 */
void ioapic_vector_allocator_init(void);

/**
 * Allocate the next available interrupt vector.
 * Returns a vector from the available pool (32-255).
 *
 * @return Allocated vector (32-255), or 0xFF if no vectors available
 */
uint8_t ioapic_allocate_vector(void);

/**
 * Free a previously allocated vector back to the pool.
 *
 * @param vector Vector to free (must be previously allocated)
 */
void ioapic_free_vector(uint8_t vector);
