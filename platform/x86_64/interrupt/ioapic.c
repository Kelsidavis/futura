/* ioapic.c - x86_64 IO-APIC implementation
 *
 * Copyright (c) 2025 Futura OS
 * Licensed under the MPL v2.0 — see LICENSE for details.
 */

#include <platform/x86_64/interrupt/ioapic.h>
#include <platform/x86_64/memory/paging.h>
#include <platform/x86_64/memory/pmap.h>
#include <kernel/errno.h>
#include <stddef.h>
#include <stdbool.h>

#include <kernel/kprintf.h>

/* IO-APIC MMIO base address (virtual) */
static volatile uint32_t *ioapic_base = NULL;
static uint32_t ioapic_gsi_base = 0;

/**
 * Check if IO-APIC is initialized and available.
 */
bool ioapic_is_available(void) {
    return ioapic_base != NULL;
}

/**
 * Read IO-APIC register.
 */
static uint32_t ioapic_read(uint8_t reg) {
    if (!ioapic_base) return 0;

    /* Write register index to IOREGSEL */
    ioapic_base[IOAPIC_REGSEL / 4] = reg;

    /* Read value from IOWIN */
    return ioapic_base[IOAPIC_WIN / 4];
}

/**
 * Write IO-APIC register.
 */
static void ioapic_write(uint8_t reg, uint32_t value) {
    if (!ioapic_base) return;

    /* Write register index to IOREGSEL */
    ioapic_base[IOAPIC_REGSEL / 4] = reg;

    /* Write value to IOWIN */
    ioapic_base[IOAPIC_WIN / 4] = value;
}

/**
 * Map IO-APIC MMIO region.
 */
static void *ioapic_map_mmio(uint64_t phys_addr) {
    phys_addr_t phys_base = PAGE_ALIGN_DOWN(phys_addr);
    uint64_t offset = phys_addr - phys_base;
    uintptr_t virt_base = (uintptr_t)pmap_phys_to_virt(phys_base);

    int rc = pmap_map(virt_base,
                      phys_base,
                      PAGE_SIZE,
                      PTE_KERNEL_RW | PTE_CACHE_DISABLE | PTE_WRITE_THROUGH);
    if (rc != 0) {
        fut_printf("[IOAPIC] ERROR: pmap_map failed rc=%d for phys=0x%llx\n",
                   rc, (unsigned long long)phys_base);
        return NULL;
    }

    return (void *)(virt_base + offset);
}

/**
 * Initialize IO-APIC.
 */
int ioapic_init(uint64_t ioapic_phys_base, uint32_t gsi_base) {
    fut_printf("[IOAPIC] Initializing IO-APIC at 0x%llx (GSI base %u)\n",
               ioapic_phys_base, gsi_base);

    /* Map IO-APIC MMIO region */
    ioapic_base = (volatile uint32_t *)ioapic_map_mmio(ioapic_phys_base);
    if (!ioapic_base) {
        fut_printf("[IOAPIC] ERROR: Failed to map IO-APIC MMIO region\n");
        return -EFAULT;
    }

    ioapic_gsi_base = gsi_base;

    /* Read IO-APIC ID and version */
    uint32_t id = ioapic_get_id();
    uint32_t max_entries = 0;
    uint32_t version = ioapic_get_version(&max_entries);

    fut_printf("[IOAPIC] ID: %u, Version: 0x%x, Max IRQs: %u\n",
               id, version, max_entries + 1);

    /* Mask all IRQs initially */
    for (uint32_t i = 0; i <= max_entries; i++) {
        ioapic_mask_irq(i);
    }

    fut_printf("[IOAPIC] Initialization complete (all IRQs masked)\n");
    return 0;
}

/**
 * Get IO-APIC ID.
 */
uint32_t ioapic_get_id(void) {
    uint32_t id_reg = ioapic_read(IOAPIC_REG_ID);
    return (id_reg >> 24) & 0x0F;
}

/**
 * Get IO-APIC version and entry count.
 */
uint32_t ioapic_get_version(uint32_t *max_entries) {
    uint32_t ver_reg = ioapic_read(IOAPIC_REG_VER);
    if (max_entries) {
        *max_entries = (ver_reg >> 16) & 0xFF;
    }
    return ver_reg & 0xFF;
}

/**
 * Read redirection table entry.
 */
uint64_t ioapic_read_redir(uint8_t irq) {
    uint8_t reg = IOAPIC_REG_REDTBL_BASE + (irq * 2);
    uint32_t low = ioapic_read(reg);
    uint32_t high = ioapic_read(reg + 1);
    return ((uint64_t)high << 32) | low;
}

/**
 * Write redirection table entry.
 */
void ioapic_write_redir(uint8_t irq, uint64_t value) {
    uint8_t reg = IOAPIC_REG_REDTBL_BASE + (irq * 2);
    ioapic_write(reg, (uint32_t)(value & 0xFFFFFFFF));
    ioapic_write(reg + 1, (uint32_t)(value >> 32));
}

/**
 * Set redirection entry for an IRQ.
 */
void ioapic_set_irq(uint8_t irq, uint8_t vector, uint8_t dest_apic_id,
                    bool mask, bool trigger_level) {
    uint64_t entry = 0;

    /* Set vector */
    entry |= vector & 0xFF;

    /* Set delivery mode (fixed) */
    entry |= IOAPIC_DELMOD_FIXED;

    /* Set destination mode (physical) */
    /* entry |= IOAPIC_REDIR_DESTMOD; */ /* 0 = physical */

    /* Set interrupt polarity (active high) */
    /* entry |= IOAPIC_REDIR_INTPOL; */ /* 0 = high */

    /* Set trigger mode */
    if (trigger_level) {
        entry |= IOAPIC_REDIR_TRIGGERMOD;
    }

    /* Set mask bit */
    if (mask) {
        entry |= IOAPIC_REDIR_MASK;
    }

    /* Set destination APIC ID (bits 56-63) */
    entry |= ((uint64_t)dest_apic_id) << 56;

    /* Write redirection entry */
    ioapic_write_redir(irq, entry);

    fut_printf("[IOAPIC] IRQ %u -> Vector %u, APIC %u, %s, %s\n",
               irq, vector, dest_apic_id,
               trigger_level ? "level" : "edge",
               mask ? "masked" : "enabled");
}

/**
 * Mask (disable) an IRQ.
 */
void ioapic_mask_irq(uint8_t irq) {
    uint64_t entry = ioapic_read_redir(irq);
    entry |= IOAPIC_REDIR_MASK;
    ioapic_write_redir(irq, entry);
}

/**
 * Unmask (enable) an IRQ.
 */
void ioapic_unmask_irq(uint8_t irq) {
    extern void fut_printf(const char *, ...);
    uint64_t entry = ioapic_read_redir(irq);
    entry &= ~IOAPIC_REDIR_MASK;
    ioapic_write_redir(irq, entry);
    fut_printf("[IOAPIC] Unmasked IRQ %u\n", irq);
}

/* Global storage for MADT interrupt overrides */
static ioapic_override_t ioapic_overrides[IOAPIC_MAX_OVERRIDES];
static int ioapic_override_count = 0;

/**
 * Store a MADT interrupt override for later processing.
 */
void ioapic_store_override(uint8_t bus, uint8_t source, uint32_t gsi, uint16_t flags) {
    if (ioapic_override_count >= IOAPIC_MAX_OVERRIDES) {
        return;  /* Array full, skip */
    }

    ioapic_override_t *override = &ioapic_overrides[ioapic_override_count++];
    override->bus = bus;
    override->source = source;
    override->gsi = gsi;
    override->flags = flags;
    override->valid = true;
}

/**
 * Look up the GSI for an ISA IRQ based on stored overrides.
 * Falls back to default mapping (1:1) if no override found.
 */
uint32_t ioapic_get_gsi_for_isa_irq(uint8_t isa_irq) {
    /* Search for override matching this ISA IRQ */
    for (int i = 0; i < ioapic_override_count; i++) {
        ioapic_override_t *override = &ioapic_overrides[i];
        if (override->valid && override->bus == 0 && override->source == isa_irq) {
            return override->gsi;
        }
    }

    /* Default: ISA IRQ N maps to GSI N (for ISA IRQs 0-15) */
    return isa_irq;
}

/**
 * Get interrupt override information for a GSI.
 */
const ioapic_override_t *ioapic_get_override(uint32_t gsi) {
    for (int i = 0; i < ioapic_override_count; i++) {
        ioapic_override_t *override = &ioapic_overrides[i];
        if (override->valid && override->gsi == gsi) {
            return override;
        }
    }
    return NULL;
}

/**
 * Get polarity from MADT override flags (bits 0-1).
 * Default: 0 = active high (ISA standard)
 */
uint8_t ioapic_get_polarity(uint32_t gsi) {
    const ioapic_override_t *override = ioapic_get_override(gsi);
    if (override) {
        /* Extract polarity field: bits 0-1 */
        uint8_t polarity_field = (override->flags >> 0) & 0x3;

        /* Map MADT polarity to IO-APIC polarity:
         * 00 = Conforms (use default = active high)
         * 01 = Active high
         * 10 = Reserved
         * 11 = Active low
         */
        if (polarity_field == 3) {
            return 1;  /* Active low */
        }
    }
    /* Default for ISA: active high (0) */
    return 0;
}

/**
 * Get trigger mode from MADT override flags (bits 2-3).
 * Default: 0 = edge-triggered (ISA standard)
 */
uint8_t ioapic_get_trigger_mode(uint32_t gsi) {
    const ioapic_override_t *override = ioapic_get_override(gsi);
    if (override) {
        /* Extract trigger mode field: bits 2-3 */
        uint8_t trigger_field = (override->flags >> 2) & 0x3;

        /* Map MADT trigger to IO-APIC trigger:
         * 00 = Conforms (use default = edge)
         * 01 = Edge-triggered
         * 10 = Reserved
         * 11 = Level-triggered
         */
        if (trigger_field == 3) {
            return 1;  /* Level-triggered */
        }
    }
    /* Default for ISA: edge-triggered (0) */
    return 0;
}

/**
 * INTERRUPT VECTOR ALLOCATOR
 * Manages dynamic allocation of interrupt vectors (32-255) for I/O devices.
 * Vectors 0-31 are reserved for CPU exceptions.
 */

/* Bitmap to track allocated vectors: 1 bit per vector (256 vectors total) */
static uint8_t vector_bitmap[32];  /* 256 bits / 8 = 32 bytes */
static bool vector_allocator_initialized = false;

/**
 * Initialize the vector allocator.
 * Marks vectors 0-31 as reserved (CPU exceptions), 32-255 available for devices.
 */
void ioapic_vector_allocator_init(void) {
    if (vector_allocator_initialized) {
        return;  /* Already initialized */
    }

    /* Mark vectors 0-31 as reserved (CPU exceptions) */
    for (int i = 0; i < 4; i++) {
        vector_bitmap[i] = 0xFF;  /* All 8 vectors in this byte are reserved */
    }

    /* Mark vectors 32-255 as available (clear bits) */
    for (int i = 4; i < 32; i++) {
        vector_bitmap[i] = 0x00;
    }

    vector_allocator_initialized = true;
    fut_printf("[IOAPIC] Vector allocator initialized (vectors 32-255 available)\\n");
}

/**
 * Allocate the next available interrupt vector.
 *
 * @return Allocated vector (32-255), or 0xFF if none available
 */
uint8_t ioapic_allocate_vector(void) {
    if (!vector_allocator_initialized) {
        ioapic_vector_allocator_init();
    }

    /* Search for the first available vector (bit = 0) */
    for (int byte_idx = 4; byte_idx < 32; byte_idx++) {
        uint8_t byte_val = vector_bitmap[byte_idx];

        /* If byte is not 0xFF, there's at least one available vector */
        if (byte_val != 0xFF) {
            /* Find the first clear bit in this byte */
            for (int bit = 0; bit < 8; bit++) {
                if ((byte_val & (1 << bit)) == 0) {
                    /* Found an available vector */
                    uint8_t vector = (byte_idx * 8) + bit;
                    vector_bitmap[byte_idx] |= (1 << bit);  /* Mark as allocated */
                    return vector;
                }
            }
        }
    }

    /* No available vectors */
    fut_printf("[IOAPIC] WARNING: No available interrupt vectors!\\n");
    return 0xFF;
}

/**
 * Free a previously allocated vector back to the pool.
 *
 * @param vector Vector to free (must be 32-255)
 */
void ioapic_free_vector(uint8_t vector) {
    /* Only device vectors (32-255) can be freed; cpu exceptions (0-31) cannot */
    if (vector < 32) {
        fut_printf("[IOAPIC] WARNING: Attempt to free reserved vector %u\\n", vector);
        return;
    }

    uint8_t byte_idx = vector / 8;
    uint8_t bit = vector % 8;

    /* Mark as free */
    vector_bitmap[byte_idx] &= ~(1 << bit);
}
