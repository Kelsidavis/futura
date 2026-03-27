/* platform/arm64/rpi_mmu.c - Raspberry Pi 4/5 MMU Page Table Setup
 *
 * Copyright (c) 2025 Kelsi Davis
 * Licensed under the MPL v2.0 — see LICENSE for details.
 *
 * Sets up ARM64 page tables for RPi4 (BCM2711) and RPi5 (BCM2712)
 * physical memory layouts. Unlike QEMU virt (which starts DRAM at 0x40000000),
 * RPi starts DRAM at 0x00000000 with peripherals at higher addresses.
 *
 * RPi4 Memory Map:
 *   0x00000000 - 0x3BFFFFFF   DRAM (up to ~960 MB below peripheral window)
 *   0x3C000000 - 0x3FFFFFFF   Reserved / VideoCore
 *   0x40000000 - 0xFBFFFFFF   DRAM (above 1 GB on 2/4/8 GB models)
 *   0xFC000000 - 0xFEFFFFFF   PCIe / peripheral bus
 *   0xFE000000 - 0xFE7FFFFF   ARM peripherals (GPIO, UART, etc.)
 *   0xFF800000 - 0xFFFFFFFF   ARM local peripherals + GIC
 *
 * RPi5 Memory Map:
 *   0x000000000 - 0x0FFFFFFFF  DRAM (up to 4 GB)
 *   0x100000000 - 0x1FFFFFFFF  DRAM (4-8 GB models)
 *   0x107C000000                ARM peripherals
 *   0x107FFF9000                GIC distributor
 *   0x1F00000000                RP1 south bridge (PCIe BAR)
 *
 * Page Table Structure:
 *   L1 (PGD): 512 entries × 1 GB each (39-bit VA with 4 KB granule)
 *   L2 (PMD): 512 entries × 2 MB each (block mappings)
 *   L3 (PTE): 512 entries × 4 KB each (optional fine-grained)
 *
 * We use 2 MB block mappings for simplicity and performance.
 */

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>

/* Page table entry flags (ARMv8-A) */
#define PTE_VALID       (1ULL << 0)
#define PTE_TABLE       (1ULL << 1)  /* L1/L2: points to next-level table */
#define PTE_BLOCK       (0ULL << 1)  /* L1/L2: 1GB/2MB block mapping */
#define PTE_PAGE        (1ULL << 1)  /* L3: 4KB page */
#define PTE_AF          (1ULL << 10) /* Access flag (must be set) */
#define PTE_SH_INNER    (3ULL << 8)  /* Inner shareable */
#define PTE_SH_OUTER    (2ULL << 8)  /* Outer shareable */

/* MAIR attribute indices */
#define PTE_ATTR_NORMAL (0ULL << 2)  /* MAIR index 0: Normal WB cacheable */
#define PTE_ATTR_DEVICE (1ULL << 2)  /* MAIR index 1: Device-nGnRnE */

/* Access permissions */
#define PTE_AP_RW_EL1   (0ULL << 6)  /* EL1 read/write */
#define PTE_AP_RO_EL1   (2ULL << 6)  /* EL1 read-only */

/* Execute never */
#define PTE_UXN         (1ULL << 54) /* User execute never */
#define PTE_PXN         (1ULL << 53) /* Privileged execute never */

/* Standard block flags for different memory types */
#define BLOCK_NORMAL    (PTE_VALID | PTE_BLOCK | PTE_AF | PTE_SH_INNER | PTE_ATTR_NORMAL | PTE_UXN)
#define BLOCK_DEVICE    (PTE_VALID | PTE_BLOCK | PTE_AF | PTE_ATTR_DEVICE | PTE_UXN | PTE_PXN)
#define BLOCK_NORMAL_RO (BLOCK_NORMAL | PTE_AP_RO_EL1)

/* ── Page tables (16 KB aligned) ── */

/* L1: 512 × 8 bytes = 4 KB */
static uint64_t __attribute__((aligned(4096))) rpi_l1_table[512];

/* L2 tables for regions that need finer-grained mapping */
static uint64_t __attribute__((aligned(4096))) rpi_l2_low_dram[512];    /* 0x00000000-0x3FFFFFFF */
static uint64_t __attribute__((aligned(4096))) rpi_l2_periph[512];      /* 0xC0000000-0xFFFFFFFF */

/* ── Public API ── */

/**
 * rpi_mmu_init_tables() — Build page tables for RPi4 physical memory map.
 *
 * Creates identity mapping (VA == PA) suitable for early boot before
 * the high-VA kernel mapping is established:
 *
 *   0x00000000 - 0x3FFFFFFF (1 GB): Normal cacheable (low DRAM)
 *   0x40000000 - 0xBFFFFFFF (2 GB): Normal cacheable (high DRAM, if present)
 *   0xC0000000 - 0xFDFFFFFF: Device memory (PCIe, etc.)
 *   0xFE000000 - 0xFE7FFFFF: Device memory (ARM peripherals)
 *   0xFF800000 - 0xFFFFFFFF: Device memory (ARM local + GIC)
 *
 * @param total_ram_mb: Total system RAM in megabytes (1024, 2048, 4096, 8192)
 */
void rpi_mmu_init_tables(uint32_t total_ram_mb) {
    /* Clear all tables */
    for (int i = 0; i < 512; i++) {
        rpi_l1_table[i] = 0;
        rpi_l2_low_dram[i] = 0;
        rpi_l2_periph[i] = 0;
    }

    /* ── L2: Low DRAM (0x00000000 - 0x3FFFFFFF, 1 GB in 2 MB blocks) ── */
    for (int i = 0; i < 512; i++) {
        uint64_t addr = (uint64_t)i * 0x200000; /* 2 MB per entry */
        if (addr >= 0x3C000000) {
            /* Reserved / VideoCore region — map as device */
            rpi_l2_low_dram[i] = addr | BLOCK_DEVICE;
        } else {
            /* Normal DRAM */
            rpi_l2_low_dram[i] = addr | BLOCK_NORMAL;
        }
    }

    /* ── L2: Peripheral region (0xC0000000 - 0xFFFFFFFF) ── */
    for (int i = 0; i < 512; i++) {
        uint64_t addr = 0xC0000000ULL + (uint64_t)i * 0x200000;
        rpi_l2_periph[i] = addr | BLOCK_DEVICE;
    }

    /* ── L1: 1 GB block mappings ── */

    /* Entry 0 (0x00000000 - 0x3FFFFFFF): L2 table for fine-grained low DRAM */
    rpi_l1_table[0] = ((uint64_t)(uintptr_t)rpi_l2_low_dram) | PTE_VALID | PTE_TABLE;

    /* Entries 1-2 (0x40000000 - 0xBFFFFFFF): 1 GB block normal DRAM each */
    if (total_ram_mb > 1024) {
        rpi_l1_table[1] = 0x40000000ULL | BLOCK_NORMAL; /* 1-2 GB */
    }
    if (total_ram_mb > 2048) {
        rpi_l1_table[2] = 0x80000000ULL | BLOCK_NORMAL; /* 2-3 GB */
    }

    /* Entry 3 (0xC0000000 - 0xFFFFFFFF): L2 table for peripherals */
    rpi_l1_table[3] = ((uint64_t)(uintptr_t)rpi_l2_periph) | PTE_VALID | PTE_TABLE;

    /* For 8 GB Pi4/Pi5: map entries 4-7 as normal DRAM */
    if (total_ram_mb > 4096) {
        for (int i = 4; i < 8 && (uint32_t)(i * 1024) < total_ram_mb; i++) {
            rpi_l1_table[i] = ((uint64_t)i * 0x40000000ULL) | BLOCK_NORMAL;
        }
    }
}

/**
 * rpi_mmu_enable() — Enable the MMU with the RPi page tables.
 * Must be called from EL1 with caches enabled.
 */
void rpi_mmu_enable(void) {
    uint64_t ttbr0 = (uint64_t)(uintptr_t)rpi_l1_table;

    /* Set MAIR_EL1: attr0=Normal WB, attr1=Device-nGnRnE */
    uint64_t mair = 0x00000000000000FFULL | (0x0000000000000000ULL << 8);
    __asm__ volatile("msr mair_el1, %0" :: "r"(mair));

    /* Set TCR_EL1: T0SZ=25 (39-bit VA), 4KB granule, inner shareable */
    uint64_t tcr = (25ULL << 0)   |  /* T0SZ = 25 → 39-bit VA */
                   (0ULL << 14)   |  /* TG0 = 4 KB */
                   (1ULL << 8)    |  /* IRGN0 = Write-Back */
                   (1ULL << 10)   |  /* ORGN0 = Write-Back */
                   (3ULL << 12)   |  /* SH0 = Inner Shareable */
                   (25ULL << 16)  |  /* T1SZ = 25 (for TTBR1, unused here) */
                   (2ULL << 30);     /* TG1 = 4 KB */
    __asm__ volatile("msr tcr_el1, %0" :: "r"(tcr));

    /* Set TTBR0_EL1 (identity mapping) */
    __asm__ volatile("msr ttbr0_el1, %0" :: "r"(ttbr0));

    /* Invalidate TLB */
    __asm__ volatile("tlbi vmalle1is" ::: "memory");
    __asm__ volatile("dsb sy" ::: "memory");
    __asm__ volatile("isb" ::: "memory");

    /* Enable MMU via SCTLR_EL1 */
    uint64_t sctlr;
    __asm__ volatile("mrs %0, sctlr_el1" : "=r"(sctlr));
    sctlr |= (1 << 0);   /* M: MMU enable */
    sctlr |= (1 << 2);   /* C: Data cache enable */
    sctlr |= (1 << 12);  /* I: Instruction cache enable */
    __asm__ volatile("msr sctlr_el1, %0" :: "r"(sctlr));
    __asm__ volatile("isb" ::: "memory");
}

/**
 * rpi_mmu_get_l1_table() — Get physical address of L1 page table.
 * Needed for setting TTBR0_EL1 from assembly.
 */
uint64_t rpi_mmu_get_l1_table(void) {
    return (uint64_t)(uintptr_t)rpi_l1_table;
}
