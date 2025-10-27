/* acpi.h - ACPI (Advanced Configuration and Power Interface) support
 *
 * Copyright (c) 2025 Futura OS
 * Licensed under the MPL v2.0 — see LICENSE for details.
 *
 * Provides ACPI table parsing for hardware discovery and power management.
 */

#pragma once

#include <stdint.h>
#include <stdbool.h>

/* ACPI Table Signatures */
#define ACPI_SIG_RSDP   "RSD PTR "
#define ACPI_SIG_RSDT   "RSDT"
#define ACPI_SIG_XSDT   "XSDT"
#define ACPI_SIG_FADT   "FACP"
#define ACPI_SIG_MADT   "APIC"
#define ACPI_SIG_HPET   "HPET"
#define ACPI_SIG_MCFG   "MCFG"

/* RSDP (Root System Description Pointer) - ACPI 1.0 */
typedef struct {
    char signature[8];       /* "RSD PTR " */
    uint8_t checksum;        /* Checksum of first 20 bytes */
    char oem_id[6];
    uint8_t revision;        /* 0 = ACPI 1.0, 2+ = ACPI 2.0+ */
    uint32_t rsdt_address;   /* 32-bit physical address of RSDT */
} __attribute__((packed)) acpi_rsdp_t;

/* RSDP Extended (ACPI 2.0+) */
typedef struct {
    acpi_rsdp_t v1;
    uint32_t length;
    uint64_t xsdt_address;   /* 64-bit physical address of XSDT */
    uint8_t extended_checksum;
    uint8_t reserved[3];
} __attribute__((packed)) acpi_rsdp_v2_t;

/* SDT (System Description Table) Header */
typedef struct {
    char signature[4];
    uint32_t length;
    uint8_t revision;
    uint8_t checksum;
    char oem_id[6];
    char oem_table_id[8];
    uint32_t oem_revision;
    uint32_t creator_id;
    uint32_t creator_revision;
} __attribute__((packed)) acpi_sdt_header_t;

/* RSDT (Root System Description Table) - uses 32-bit pointers */
typedef struct {
    acpi_sdt_header_t header;
    uint32_t entries[];      /* Variable length array of 32-bit table pointers */
} __attribute__((packed)) acpi_rsdt_t;

/* XSDT (Extended System Description Table) - uses 64-bit pointers */
typedef struct {
    acpi_sdt_header_t header;
    uint64_t entries[];      /* Variable length array of 64-bit table pointers */
} __attribute__((packed)) acpi_xsdt_t;

/* FADT (Fixed ACPI Description Table) - Simplified */
typedef struct {
    acpi_sdt_header_t header;
    uint32_t firmware_ctrl;
    uint32_t dsdt;
    uint8_t reserved1;
    uint8_t preferred_pm_profile;
    uint16_t sci_interrupt;
    uint32_t smi_command_port;
    uint8_t acpi_enable;
    uint8_t acpi_disable;
    uint8_t s4bios_req;
    uint8_t pstate_control;
    uint32_t pm1a_event_block;
    uint32_t pm1b_event_block;
    uint32_t pm1a_control_block;
    uint32_t pm1b_control_block;
    uint32_t pm2_control_block;
    uint32_t pm_timer_block;
    uint32_t gpe0_block;
    uint32_t gpe1_block;
    uint8_t pm1_event_length;
    uint8_t pm1_control_length;
    uint8_t pm2_control_length;
    uint8_t pm_timer_length;
    uint8_t gpe0_length;
    uint8_t gpe1_length;
    uint8_t gpe1_base;
    uint8_t cstate_control;
    uint16_t worst_c2_latency;
    uint16_t worst_c3_latency;
    uint16_t flush_size;
    uint16_t flush_stride;
    uint8_t duty_offset;
    uint8_t duty_width;
    uint8_t day_alarm;
    uint8_t month_alarm;
    uint8_t century;
    uint16_t boot_flags;
    uint8_t reserved2;
    uint32_t flags;
    /* ... more fields for ACPI 2.0+ ... */
} __attribute__((packed)) acpi_fadt_t;

/* MADT (Multiple APIC Description Table) Entry Types */
#define ACPI_MADT_TYPE_LOCAL_APIC       0
#define ACPI_MADT_TYPE_IO_APIC          1
#define ACPI_MADT_TYPE_INTERRUPT_OVERRIDE 2
#define ACPI_MADT_TYPE_NMI              4
#define ACPI_MADT_TYPE_LOCAL_APIC_OVERRIDE 5

/* MADT (Multiple APIC Description Table) */
typedef struct {
    acpi_sdt_header_t header;
    uint32_t local_apic_address;  /* Physical address of local APIC */
    uint32_t flags;                /* PC-AT compatible dual 8259 setup if bit 0 set */
    /* Variable length entries follow */
} __attribute__((packed)) acpi_madt_t;

/* MADT Entry Header */
typedef struct {
    uint8_t type;
    uint8_t length;
} __attribute__((packed)) acpi_madt_entry_header_t;

/* MADT Local APIC Entry (Processor) */
typedef struct {
    acpi_madt_entry_header_t header;
    uint8_t acpi_processor_id;
    uint8_t apic_id;
    uint32_t flags;  /* Bit 0: Processor enabled, Bit 1: Online capable */
} __attribute__((packed)) acpi_madt_local_apic_t;

/* MADT IO APIC Entry */
typedef struct {
    acpi_madt_entry_header_t header;
    uint8_t io_apic_id;
    uint8_t reserved;
    uint32_t io_apic_address;
    uint32_t global_system_interrupt_base;
} __attribute__((packed)) acpi_madt_io_apic_t;

/* MADT Interrupt Source Override */
typedef struct {
    acpi_madt_entry_header_t header;
    uint8_t bus;       /* 0 = ISA */
    uint8_t source;    /* Bus-relative interrupt source (IRQ) */
    uint32_t global_system_interrupt;
    uint16_t flags;    /* MPS INTI flags */
} __attribute__((packed)) acpi_madt_interrupt_override_t;

/**
 * Initialize ACPI subsystem.
 * Locates RSDP, parses RSDT/XSDT, and validates tables.
 *
 * @return true if ACPI is available, false otherwise
 */
bool acpi_init(void);

/**
 * Find an ACPI table by signature.
 *
 * @param signature 4-character table signature (e.g., "APIC", "FACP")
 * @return Pointer to table header, or NULL if not found
 */
acpi_sdt_header_t *acpi_find_table(const char *signature);

/**
 * Get the FADT (Fixed ACPI Description Table).
 *
 * @return Pointer to FADT, or NULL if not found
 */
acpi_fadt_t *acpi_get_fadt(void);

/**
 * Get the MADT (Multiple APIC Description Table).
 *
 * @return Pointer to MADT, or NULL if not found
 */
acpi_madt_t *acpi_get_madt(void);

/**
 * Parse MADT to discover CPU topology.
 * Prints CPU count, APIC IDs, and IO-APIC information.
 */
void acpi_parse_madt(void);

/**
 * Shutdown the system via ACPI (if supported).
 */
void acpi_shutdown(void);

/**
 * Reboot the system via ACPI (if supported).
 */
void acpi_reboot(void);
