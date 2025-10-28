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

    /* Initialize LAPIC for BSP (Bootstrap Processor) */
    extern void lapic_init(uint64_t lapic_base);
    lapic_init(madt->local_apic_address);

    /* Parse MADT entries */
    uint32_t cpu_count = 0;
    uint32_t io_apic_count = 0;
    uint32_t interrupt_override_count = 0;

    /* Store IO-APIC info for initialization */
    uint64_t io_apic_address = 0;
    uint32_t io_apic_gsi_base = 0;

    /* Store APIC IDs for SMP initialization */
    #define MAX_CPUS 256
    static uint32_t apic_ids[MAX_CPUS];
    uint32_t num_apic_ids = 0;

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

                if (enabled && num_apic_ids < MAX_CPUS) {
                    apic_ids[num_apic_ids++] = lapic->apic_id;
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

                /* Store first IO-APIC for initialization */
                if (io_apic_count == 0) {
                    io_apic_address = ioapic->io_apic_address;
                    io_apic_gsi_base = ioapic->global_system_interrupt_base;
                }

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

    /* Initialize IO-APIC if found */
    if (io_apic_address != 0) {
        extern int ioapic_init(uint64_t ioapic_base, uint32_t gsi_base);
        extern void ioapic_set_irq(uint8_t irq, uint8_t vector, uint8_t dest_apic_id,
                                   bool mask, bool trigger_level);

        ioapic_init(io_apic_address, io_apic_gsi_base);

        /* Configure basic IRQs to route to BSP (APIC ID 0) */
        /* IRQ0 = Timer (vector 32), IRQ1 = Keyboard (vector 33) */
        /* Keep them masked for now - will be enabled when drivers request them */

        fut_printf("[ACPI] Configuring IRQ routing to BSP (APIC ID 0)\n");

        /* Timer: ISA IRQ0 is typically remapped to GSI 2 on x86 systems
         * due to the IRQ override in MADT. Configure GSI 2, not IRQ 0. */
        ioapic_set_irq(2, 32, 0, true, false);  /* Timer -> Vector 32, edge-triggered, masked */

        /* Keyboard IRQ1 -> Vector 33 (INT_IRQ1_KEYBOARD) */
        ioapic_set_irq(1, 33, 0, true, false);  /* edge-triggered, masked */

        /* COM2 IRQ3 -> Vector 35 */
        ioapic_set_irq(3, 35, 0, true, false);

        /* COM1 IRQ4 -> Vector 36 */
        ioapic_set_irq(4, 36, 0, true, false);

        /* TODO: Properly parse and apply all interrupt overrides from MADT */
        /* TODO: Enable IRQs when drivers register handlers */
    }

    /* Start Application Processors if we have multiple CPUs */
    if (num_apic_ids > 1) {
        fut_printf("[ACPI] Starting %u Application Processors...\n", num_apic_ids - 1);
        extern void smp_init(uint32_t *apic_ids, uint32_t num_cpus);
        smp_init(apic_ids, num_apic_ids);
    } else {
        fut_printf("[ACPI] Single-processor system, SMP disabled\n");
    }
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
