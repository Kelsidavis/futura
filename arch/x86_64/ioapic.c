/* ioapic.c - x86_64 IO-APIC implementation
 *
 * Copyright (c) 2025 Futura OS
 * Licensed under the MPL v2.0 — see LICENSE for details.
 */

#include <arch/x86_64/ioapic.h>
#include <stddef.h>

extern void fut_printf(const char *fmt, ...);

/* IO-APIC MMIO base address (virtual) */
static volatile uint32_t *ioapic_base = NULL;
static uint32_t ioapic_gsi_base = 0;

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
    extern int pmap_map(uint64_t vaddr, uint64_t paddr, uint64_t len, uint64_t prot);

    /* Use a fixed virtual address for IO-APIC */
    const uint64_t ioapic_virt = 0xFFFFFFFFFEC00000ULL;  /* Match physical layout */

    /* PAGE_PRESENT | PAGE_WRITE | PAGE_PCD (Cache Disable) | PAGE_PWT (Write Through) */
    const uint64_t PAGE_PRESENT = 0x001;
    const uint64_t PAGE_WRITE = 0x002;
    const uint64_t PAGE_PCD = 0x010;  /* Cache Disable for MMIO */
    const uint64_t PAGE_PWT = 0x008;  /* Write Through */
    const uint64_t prot = PAGE_PRESENT | PAGE_WRITE | PAGE_PCD | PAGE_PWT;

    /* Map one page (4KB) for IO-APIC registers */
    int ret = pmap_map(ioapic_virt, phys_addr, 4096, prot);
    if (ret != 0) {
        fut_printf("[IOAPIC] ERROR: Failed to map IO-APIC MMIO (error %d)\n", ret);
        return NULL;
    }

    return (void *)ioapic_virt;
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
        return -1;
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
    uint64_t entry = ioapic_read_redir(irq);
    entry &= ~IOAPIC_REDIR_MASK;
    ioapic_write_redir(irq, entry);
}
