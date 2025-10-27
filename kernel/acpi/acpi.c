/* acpi.c - ACPI (Advanced Configuration and Power Interface) implementation
 *
 * Copyright (c) 2025 Futura OS
 * Licensed under the MPL v2.0 — see LICENSE for details.
 */

#include <kernel/acpi.h>
#include <kernel/fut_mm.h>
#include <stddef.h>
#include <string.h>

extern void fut_printf(const char *fmt, ...);

/* ACPI state */
static acpi_rsdp_v2_t *rsdp = NULL;
static acpi_rsdt_t *rsdt = NULL;
static acpi_xsdt_t *xsdt = NULL;
static bool acpi_available = false;

/**
 * Calculate checksum for ACPI table.
 * Sum of all bytes should be 0.
 */
static uint8_t acpi_checksum(const void *data, uint32_t length) {
    const uint8_t *bytes = (const uint8_t *)data;
    uint8_t sum = 0;
    for (uint32_t i = 0; i < length; i++) {
        sum += bytes[i];
    }
    return sum;
}

/**
 * Validate ACPI table checksum.
 */
static bool acpi_validate_checksum(const acpi_sdt_header_t *header) {
    return acpi_checksum(header, header->length) == 0;
}

/**
 * Find RSDP in BIOS memory area.
 * Searches 0xE0000-0xFFFFF for "RSD PTR " signature on 16-byte boundaries.
 */
static acpi_rsdp_v2_t *acpi_find_rsdp(void) {
    /* Map BIOS area to higher-half kernel space */
    const uintptr_t bios_start = 0xE0000;
    const uintptr_t bios_end = 0x100000;
    const uintptr_t kernel_offset = 0xFFFFFFFF80000000ULL;

    for (uintptr_t addr = bios_start; addr < bios_end; addr += 16) {
        acpi_rsdp_t *candidate = (acpi_rsdp_t *)(addr + kernel_offset);

        /* Check signature */
        if (memcmp(candidate->signature, ACPI_SIG_RSDP, 8) != 0) {
            continue;
        }

        /* Validate ACPI 1.0 checksum (first 20 bytes) */
        if (acpi_checksum(candidate, 20) != 0) {
            continue;
        }

        /* Check if this is ACPI 2.0+ */
        if (candidate->revision >= 2) {
            acpi_rsdp_v2_t *v2 = (acpi_rsdp_v2_t *)candidate;

            /* Validate extended checksum */
            if (acpi_checksum(v2, sizeof(acpi_rsdp_v2_t)) != 0) {
                continue;
            }

            fut_printf("[ACPI] Found RSDP v2 at 0x%lx\n", addr);
            return v2;
        } else {
            fut_printf("[ACPI] Found RSDP v1 at 0x%lx\n", addr);
            return (acpi_rsdp_v2_t *)candidate;
        }
    }

    return NULL;
}

/**
 * Map physical address to kernel virtual address.
 * For now, assumes identity mapping in higher half.
 */
static void *acpi_map_table(uint64_t phys_addr) {
    const uintptr_t kernel_offset = 0xFFFFFFFF80000000ULL;
    return (void *)(phys_addr + kernel_offset);
}

/**
 * Initialize ACPI subsystem.
 */
bool acpi_init(void) {
    /* Find RSDP */
    rsdp = acpi_find_rsdp();
    if (!rsdp) {
        fut_printf("[ACPI] RSDP not found\n");
        return false;
    }

    fut_printf("[ACPI] RSDP revision: %u\n", rsdp->v1.revision);
    fut_printf("[ACPI] OEM ID: %c%c%c%c%c%c\n",
               rsdp->v1.oem_id[0], rsdp->v1.oem_id[1], rsdp->v1.oem_id[2],
               rsdp->v1.oem_id[3], rsdp->v1.oem_id[4], rsdp->v1.oem_id[5]);

    /* Parse RSDT or XSDT */
    if (rsdp->v1.revision >= 2 && rsdp->xsdt_address != 0) {
        /* Use XSDT (64-bit) */
        xsdt = (acpi_xsdt_t *)acpi_map_table(rsdp->xsdt_address);
        if (!acpi_validate_checksum(&xsdt->header)) {
            fut_printf("[ACPI] XSDT checksum failed\n");
            return false;
        }

        uint32_t num_entries = (xsdt->header.length - sizeof(acpi_sdt_header_t)) / 8;
        fut_printf("[ACPI] XSDT at 0x%llx, %u tables\n", rsdp->xsdt_address, num_entries);

    } else {
        /* Use RSDT (32-bit) */
        rsdt = (acpi_rsdt_t *)acpi_map_table(rsdp->v1.rsdt_address);
        if (!acpi_validate_checksum(&rsdt->header)) {
            fut_printf("[ACPI] RSDT checksum failed\n");
            return false;
        }

        uint32_t num_entries = (rsdt->header.length - sizeof(acpi_sdt_header_t)) / 4;
        fut_printf("[ACPI] RSDT at 0x%x, %u tables\n", rsdp->v1.rsdt_address, num_entries);
    }

    acpi_available = true;
    return true;
}

/**
 * Find ACPI table by signature.
 */
acpi_sdt_header_t *acpi_find_table(const char *signature) {
    if (!acpi_available) {
        return NULL;
    }

    if (xsdt) {
        /* Search XSDT (64-bit pointers) */
        uint32_t num_entries = (xsdt->header.length - sizeof(acpi_sdt_header_t)) / 8;

        for (uint32_t i = 0; i < num_entries; i++) {
            acpi_sdt_header_t *header = (acpi_sdt_header_t *)acpi_map_table(xsdt->entries[i]);

            if (memcmp(header->signature, signature, 4) == 0) {
                if (acpi_validate_checksum(header)) {
                    return header;
                }
            }
        }
    } else if (rsdt) {
        /* Search RSDT (32-bit pointers) */
        uint32_t num_entries = (rsdt->header.length - sizeof(acpi_sdt_header_t)) / 4;

        for (uint32_t i = 0; i < num_entries; i++) {
            acpi_sdt_header_t *header = (acpi_sdt_header_t *)acpi_map_table(rsdt->entries[i]);

            if (memcmp(header->signature, signature, 4) == 0) {
                if (acpi_validate_checksum(header)) {
                    return header;
                }
            }
        }
    }

    return NULL;
}

/**
 * Get the FADT (Fixed ACPI Description Table).
 */
acpi_fadt_t *acpi_get_fadt(void) {
    return (acpi_fadt_t *)acpi_find_table(ACPI_SIG_FADT);
}

/**
 * Get the MADT (Multiple APIC Description Table).
 */
acpi_madt_t *acpi_get_madt(void) {
    return (acpi_madt_t *)acpi_find_table(ACPI_SIG_MADT);
}

/**
 * Parse MADT to discover CPU topology.
 */
void acpi_parse_madt(void) {
    acpi_madt_t *madt = acpi_get_madt();
    if (!madt) {
        fut_printf("[ACPI] MADT not found\n");
        return;
    }

    fut_printf("[ACPI] MADT found at 0x%p\n", (void *)madt);
    fut_printf("[ACPI] Local APIC address: 0x%x\n", madt->local_apic_address);
    fut_printf("[ACPI] Flags: 0x%x (PC-AT compatible: %s)\n",
               madt->flags,
               (madt->flags & 1) ? "yes" : "no");

    /* Parse MADT entries */
    uint32_t cpu_count = 0;
    uint32_t io_apic_count = 0;
    uint32_t interrupt_override_count = 0;

    uint8_t *entry_ptr = (uint8_t *)(madt + 1);  /* Start after header */
    uint8_t *end = (uint8_t *)madt + madt->header.length;

    while (entry_ptr < end) {
        acpi_madt_entry_header_t *header = (acpi_madt_entry_header_t *)entry_ptr;

        if (header->length == 0) {
            fut_printf("[ACPI] Invalid MADT entry with length 0\n");
            break;
        }

        switch (header->type) {
            case ACPI_MADT_TYPE_LOCAL_APIC: {
                acpi_madt_local_apic_t *lapic = (acpi_madt_local_apic_t *)entry_ptr;
                bool enabled = (lapic->flags & 1);
                bool online_capable = (lapic->flags & 2);

                fut_printf("[ACPI]   CPU #%u: APIC ID %u, Processor ID %u, %s%s\n",
                           cpu_count,
                           lapic->apic_id,
                           lapic->acpi_processor_id,
                           enabled ? "enabled" : "disabled",
                           online_capable ? ", online-capable" : "");

                if (enabled) {
                    cpu_count++;
                }
                break;
            }

            case ACPI_MADT_TYPE_IO_APIC: {
                acpi_madt_io_apic_t *ioapic = (acpi_madt_io_apic_t *)entry_ptr;
                fut_printf("[ACPI]   IO-APIC #%u: ID %u, address 0x%x, GSI base %u\n",
                           io_apic_count,
                           ioapic->io_apic_id,
                           ioapic->io_apic_address,
                           ioapic->global_system_interrupt_base);
                io_apic_count++;
                break;
            }

            case ACPI_MADT_TYPE_INTERRUPT_OVERRIDE: {
                acpi_madt_interrupt_override_t *override = (acpi_madt_interrupt_override_t *)entry_ptr;
                fut_printf("[ACPI]   IRQ Override: bus %u, source %u -> GSI %u, flags 0x%x\n",
                           override->bus,
                           override->source,
                           override->global_system_interrupt,
                           override->flags);
                interrupt_override_count++;
                break;
            }

            default:
                fut_printf("[ACPI]   Unknown MADT entry type: %u\n", header->type);
                break;
        }

        entry_ptr += header->length;
    }

    fut_printf("[ACPI] CPU topology: %u CPUs, %u IO-APICs, %u interrupt overrides\n",
               cpu_count, io_apic_count, interrupt_override_count);
}

/* I/O port operations */
extern void hal_outb(uint16_t port, uint8_t value);
extern uint8_t hal_inb(uint16_t port);
extern void hal_outw(uint16_t port, uint16_t value);
extern uint16_t hal_inw(uint16_t port);

/**
 * Shutdown system via ACPI.
 * Writes SLP_TYPa/SLP_TYPb and SLP_EN to PM1a/PM1b control registers.
 */
void acpi_shutdown(void) {
    acpi_fadt_t *fadt = acpi_get_fadt();
    if (!fadt) {
        fut_printf("[ACPI] Shutdown: FADT not found\n");
        return;
    }

    fut_printf("[ACPI] PM1a_control_block: 0x%x, PM1b_control_block: 0x%x\n",
               fadt->pm1a_control_block, fadt->pm1b_control_block);

    /* For QEMU/BOCHS, S5 sleep state is typically SLP_TYP=5, SLP_EN=1<<13 */
    uint16_t pm1a_val = (5 << 10) | (1 << 13);  /* SLP_TYP=5, SLP_EN=1 */

    if (fadt->pm1a_control_block != 0) {
        fut_printf("[ACPI] Writing shutdown command to PM1a (0x%x)\n", fadt->pm1a_control_block);
        hal_outw(fadt->pm1a_control_block, pm1a_val);
    }

    if (fadt->pm1b_control_block != 0) {
        fut_printf("[ACPI] Writing shutdown command to PM1b (0x%x)\n", fadt->pm1b_control_block);
        hal_outw(fadt->pm1b_control_block, pm1a_val);
    }

    /* If we reach here, shutdown failed */
    fut_printf("[ACPI] Shutdown failed\n");
}

/**
 * Reboot system via ACPI.
 * For now, falls back to keyboard controller reset.
 */
void acpi_reboot(void) {
    fut_printf("[ACPI] Reboot via keyboard controller (port 0x64)\n");

    /* Try keyboard controller reset (8042) */
    hal_outb(0x64, 0xFE);

    /* If that didn't work, try triple fault */
    fut_printf("[ACPI] Keyboard reset failed, attempting triple fault\n");

    /* Disable interrupts and load invalid IDT to cause triple fault */
    __asm__ volatile("cli");
    __asm__ volatile("lidt %0" :: "m"((struct { uint16_t limit; uint64_t base; }){0, 0}));
    __asm__ volatile("int $0x03");  /* Trigger breakpoint, should triple fault */

    /* Should never reach here */
    fut_printf("[ACPI] Reboot failed\n");
}
