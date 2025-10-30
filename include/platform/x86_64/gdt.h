/* gdt.h - Futura OS x86_64 Global Descriptor Table
 *
 * Copyright (c) 2025 Kelsi Davis
 * Licensed under the MPL v2.0 — see LICENSE for details.
 *
 * GDT definitions for x86_64 long mode.
 */

#pragma once

#include <stdint.h>

/* ============================================================
 *   GDT Segment Selectors
 * ============================================================ */

#define GDT_NULL_SEGMENT        0x00
#define GDT_KERNEL_CODE         0x08    /* Ring 0 code segment */
#define GDT_KERNEL_DATA         0x10    /* Ring 0 data segment */
#define GDT_USER_CODE           0x18    /* Ring 3 code segment */
#define GDT_USER_DATA           0x20    /* Ring 3 data segment */
#define GDT_TSS                 0x28    /* Task State Segment */

/* Selector privilege levels */
#define GDT_DPL_KERNEL          0
#define GDT_DPL_USER            3

/* ============================================================
 *   GDT Entry Structure (64-bit)
 * ============================================================ */

/**
 * GDT entry for code/data segments in long mode.
 * Note: In 64-bit mode, most fields are ignored for code/data segments.
 */
typedef struct gdt_entry {
    uint16_t limit_low;         /* Limit bits 0-15 (ignored in 64-bit) */
    uint16_t base_low;          /* Base bits 0-15 (ignored in 64-bit) */
    uint8_t  base_mid;          /* Base bits 16-23 (ignored in 64-bit) */
    uint8_t  access;            /* Access flags */
    uint8_t  granularity;       /* Granularity and limit bits 16-19 */
    uint8_t  base_high;         /* Base bits 24-31 (ignored in 64-bit) */
} __attribute__((packed)) gdt_entry_t;

static_assert(sizeof(gdt_entry_t) == 8, "GDT entry must be 8 bytes");

/**
 * TSS entry in 64-bit mode (16 bytes).
 * System descriptors are 16 bytes in long mode.
 */
typedef struct tss_entry {
    uint16_t limit_low;
    uint16_t base_low;
    uint8_t  base_mid;
    uint8_t  access;
    uint8_t  granularity;
    uint8_t  base_high;
    uint32_t base_upper;        /* Upper 32 bits of base (64-bit only) */
    uint32_t reserved;          /* Must be zero */
} __attribute__((packed)) tss_entry_t;

static_assert(sizeof(tss_entry_t) == 16, "TSS entry must be 16 bytes");

/* ============================================================
 *   GDT Pointer (GDTR)
 * ============================================================ */

typedef struct gdt_ptr {
    uint16_t limit;             /* Size of GDT - 1 */
    uint64_t base;              /* Base address of GDT */
} __attribute__((packed)) gdt_ptr_t;

static_assert(sizeof(gdt_ptr_t) == 10, "GDT pointer must be 10 bytes");

/* ============================================================
 *   Access Byte Flags
 * ============================================================ */

/* Descriptor types */
#define GDT_TYPE_DATA_RO        0x00    /* Data, read-only */
#define GDT_TYPE_DATA_RW        0x02    /* Data, read/write */
#define GDT_TYPE_CODE_EX        0x08    /* Code, execute-only */
#define GDT_TYPE_CODE_RX        0x0A    /* Code, read/execute */

/* Access flags */
#define GDT_ACCESS_PRESENT      0x80    /* Present bit (must be 1) */
#define GDT_ACCESS_DPL0         0x00    /* Ring 0 (kernel) */
#define GDT_ACCESS_DPL3         0x60    /* Ring 3 (user) */
#define GDT_ACCESS_S            0x10    /* Code/Data segment (not system) */
#define GDT_ACCESS_TSS          0x09    /* TSS descriptor (type=9) */

/* Complete access bytes for common segments */
#define GDT_ACCESS_KERNEL_CODE  (GDT_ACCESS_PRESENT | GDT_ACCESS_DPL0 | GDT_ACCESS_S | GDT_TYPE_CODE_RX)
#define GDT_ACCESS_KERNEL_DATA  (GDT_ACCESS_PRESENT | GDT_ACCESS_DPL0 | GDT_ACCESS_S | GDT_TYPE_DATA_RW)
#define GDT_ACCESS_USER_CODE    (GDT_ACCESS_PRESENT | GDT_ACCESS_DPL3 | GDT_ACCESS_S | GDT_TYPE_CODE_RX)
#define GDT_ACCESS_USER_DATA    (GDT_ACCESS_PRESENT | GDT_ACCESS_DPL3 | GDT_ACCESS_S | GDT_TYPE_DATA_RW)
#define GDT_ACCESS_TSS_AVAIL    (GDT_ACCESS_PRESENT | GDT_ACCESS_TSS)

/* ============================================================
 *   Granularity Byte Flags
 * ============================================================ */

#define GDT_GRAN_4K             0x80    /* 4KB granularity */
#define GDT_GRAN_BYTE           0x00    /* Byte granularity */
#define GDT_GRAN_64BIT          0x20    /* 64-bit code segment (L=1) */
#define GDT_GRAN_32BIT          0x40    /* 32-bit code segment (D=1) */

/* Complete granularity bytes for common segments */
#define GDT_GRAN_KERNEL_CODE    (GDT_GRAN_64BIT)                         /* 64-bit, byte granularity */
#define GDT_GRAN_KERNEL_DATA    (0x00)                                   /* Data segment (ignored) */
#define GDT_GRAN_USER_CODE      (GDT_GRAN_64BIT)                         /* 64-bit, byte granularity */
#define GDT_GRAN_USER_DATA      (0x00)                                   /* Data segment (ignored) */

/* ============================================================
 *   Task State Segment (TSS) Structure
 * ============================================================ */

/**
 * TSS for x86_64 (104 bytes).
 * Used primarily for stack switching and I/O permissions.
 */
typedef struct tss {
    uint32_t reserved0;
    uint64_t rsp0;              /* Stack pointer for ring 0 */
    uint64_t rsp1;              /* Stack pointer for ring 1 */
    uint64_t rsp2;              /* Stack pointer for ring 2 */
    uint64_t reserved1;
    uint64_t ist[7];            /* Interrupt Stack Table */
    uint64_t reserved2;
    uint16_t reserved3;
    uint16_t iomap_base;        /* I/O permission bitmap offset */
} __attribute__((packed)) tss_t;

static_assert(sizeof(tss_t) == 104, "TSS must be 104 bytes");

/* ============================================================
 *   GDT Management Functions
 * ============================================================ */

/**
 * Load GDT and reload segment registers.
 * Implemented in gdt_idt.S.
 */
extern void fut_gdt_load(void);

/**
 * Set TSS base address in GDT.
 * @param tss Pointer to TSS structure
 */
void fut_gdt_set_tss(tss_t *tss);

/**
 * Load TSS selector into task register.
 */
static inline void fut_ltr(uint16_t selector) {
    __asm__ volatile("ltr %0" :: "r"(selector));
}

/**
 * Get current code segment selector.
 */
static inline uint16_t fut_get_cs(void) {
    uint16_t cs;
    __asm__ volatile("mov %%cs, %0" : "=r"(cs));
    return cs;
}

/**
 * Get current data segment selector.
 */
static inline uint16_t fut_get_ds(void) {
    uint16_t ds;
    __asm__ volatile("mov %%ds, %0" : "=r"(ds));
    return ds;
}

/**
 * Get current stack segment selector.
 */
static inline uint16_t fut_get_ss(void) {
    uint16_t ss;
    __asm__ volatile("mov %%ss, %0" : "=r"(ss));
    return ss;
}

/**
 * Initialize kernel TSS.
 * Sets up ring 0 stack and loads TSS.
 */
void fut_tss_init(void);

/**
 * Set kernel stack pointer for privilege level transitions.
 * @param rsp0 Stack pointer for ring 0
 */
void fut_tss_set_kernel_stack(uint64_t rsp0);
