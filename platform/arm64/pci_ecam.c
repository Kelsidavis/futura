// SPDX-License-Identifier: MPL-2.0
/*
 * pci_ecam.c - ARM64 PCI Express ECAM (Enhanced Configuration Access Mechanism)
 *
 * Provides PCI configuration space access for ARM64 virt machines via MMIO.
 * ECAM maps PCI config space to: base + (bus << 20) + (dev << 15) + (fn << 12) + offset
 */

#include <stddef.h>
#include <stdint.h>
#include <stdbool.h>

/* QEMU virt machine PCIe ECAM base address (from device tree) */
#define PCIE_ECAM_BASE  0x4010000000ULL   /* 256GB + 256MB */
#define PCIE_ECAM_SIZE  0x10000000ULL     /* 256MB */

/* PCIe MMIO window for BAR allocation (from device tree) */
#define PCIE_MMIO_BASE  0x10000000ULL     /* 32-bit MMIO window start */
#define PCIE_MMIO_SIZE  0x2EFF0000ULL     /* ~752MB */

/* Volatile pointer to ECAM base */
static volatile uint8_t *g_pcie_ecam_base = NULL;

/* Current BAR allocation pointer */
static uint64_t g_bar_alloc_next = PCIE_MMIO_BASE;

extern void fut_printf(const char *fmt, ...);

/**
 * Calculate ECAM offset for a given PCI address
 */
static inline uint32_t pcie_ecam_offset(uint8_t bus, uint8_t dev, uint8_t fn, uint16_t reg) {
    return (bus << 20) | (dev << 15) | (fn << 12) | (reg & 0xffc);
}

/**
 * Read 32-bit value from PCI configuration space
 */
uint32_t arm64_pci_read32(uint8_t bus, uint8_t dev, uint8_t fn, uint16_t reg) {
    if (!g_pcie_ecam_base) {
        return 0xFFFFFFFF;
    }

    uint32_t offset = pcie_ecam_offset(bus, dev, fn, reg);
    volatile uint32_t *addr = (volatile uint32_t *)(g_pcie_ecam_base + offset);

    /* ARM64 memory barrier before read */
    __asm__ volatile("dsb sy" ::: "memory");
    uint32_t value = *addr;
    __asm__ volatile("dsb sy" ::: "memory");

    return value;
}

/**
 * Write 32-bit value to PCI configuration space
 */
void arm64_pci_write32(uint8_t bus, uint8_t dev, uint8_t fn, uint16_t reg, uint32_t value) {
    if (!g_pcie_ecam_base) {
        return;
    }

    uint32_t offset = pcie_ecam_offset(bus, dev, fn, reg);
    volatile uint32_t *addr = (volatile uint32_t *)(g_pcie_ecam_base + offset);

    __asm__ volatile("dsb sy" ::: "memory");
    *addr = value;
    __asm__ volatile("dsb sy" ::: "memory");
}

/**
 * Read 16-bit value from PCI configuration space
 */
uint16_t arm64_pci_read16(uint8_t bus, uint8_t dev, uint8_t fn, uint16_t reg) {
    uint32_t val32 = arm64_pci_read32(bus, dev, fn, reg & ~3);
    return (uint16_t)(val32 >> ((reg & 2) * 8));
}

/**
 * Read 8-bit value from PCI configuration space
 */
uint8_t arm64_pci_read8(uint8_t bus, uint8_t dev, uint8_t fn, uint16_t reg) {
    uint32_t val32 = arm64_pci_read32(bus, dev, fn, reg & ~3);
    return (uint8_t)(val32 >> ((reg & 3) * 8));
}

/**
 * Initialize ARM64 PCI ECAM subsystem
 * Must be called after MMU maps the ECAM region
 */
void arm64_pci_init(void) {
    fut_printf("[PCI] ARM64 ECAM initialization\n");
    fut_printf("[PCI] ECAM base: 0x%llx, size: 0x%llx\n",
               (unsigned long long)PCIE_ECAM_BASE,
               (unsigned long long)PCIE_ECAM_SIZE);

    /* Set base pointer - assumes MMU has identity-mapped this region */
    g_pcie_ecam_base = (volatile uint8_t *)PCIE_ECAM_BASE;

    /* Test read - bus 0, device 0, function 0, offset 0 (vendor/device ID) */
    uint32_t test = arm64_pci_read32(0, 0, 0, 0);
    if (test == 0xFFFFFFFF || test == 0) {
        fut_printf("[PCI] Warning: No PCI devices detected or ECAM not mapped\n");
        g_pcie_ecam_base = NULL;
        return;
    }

    fut_printf("[PCI] ECAM access working, host bridge vendor/device: 0x%08x\n", test);
}

/**
 * Scan PCI bus for devices
 * Returns 1 if device found, 0 otherwise
 */
int arm64_pci_scan_device(uint8_t bus, uint8_t dev, uint8_t fn,
                           uint16_t *vendor_id, uint16_t *device_id,
                           uint8_t *class_code, uint8_t *subclass) {
    uint32_t id = arm64_pci_read32(bus, dev, fn, 0x00);

    /* Check for invalid/absent device */
    if (id == 0xFFFFFFFF || id == 0) {
        return 0;
    }

    *vendor_id = id & 0xFFFF;
    *device_id = (id >> 16) & 0xFFFF;

    /* Read class code */
    uint32_t class_reg = arm64_pci_read32(bus, dev, fn, 0x08);
    *class_code = (class_reg >> 24) & 0xFF;
    *subclass = (class_reg >> 16) & 0xFF;

    return 1;
}

/**
 * Get PCI BAR (Base Address Register) value
 */
uint64_t arm64_pci_get_bar(uint8_t bus, uint8_t dev, uint8_t fn, uint8_t bar_num) {
    if (bar_num > 5) {
        return 0;
    }

    uint16_t bar_offset = 0x10 + (bar_num * 4);
    uint32_t bar = arm64_pci_read32(bus, dev, fn, bar_offset);

    fut_printf("[PCI] BAR%d raw value: 0x%08x (type bits: 0x%x)\n",
               bar_num, bar, bar & 0xF);

    /* Check if 64-bit BAR */
    if ((bar & 0x6) == 0x4) {
        uint32_t bar_hi = arm64_pci_read32(bus, dev, fn, bar_offset + 4);
        fut_printf("[PCI] BAR%d is 64-bit, hi=0x%08x\n", bar_num, bar_hi);
        return ((uint64_t)bar_hi << 32) | (bar & ~0xFULL);
    }

    return bar & ~0xFULL;
}

/**
 * Assign a BAR address for a PCI device
 * Returns the assigned address, or 0 on failure
 */
uint64_t arm64_pci_assign_bar(uint8_t bus, uint8_t dev, uint8_t fn, uint8_t bar_num) {
    if (bar_num > 5) {
        return 0;
    }

    uint16_t bar_offset = 0x10 + (bar_num * 4);

    /* Step 1: Write 0xFFFFFFFF to get BAR size */
    arm64_pci_write32(bus, dev, fn, bar_offset, 0xFFFFFFFF);

    /* Step 2: Read back to get size mask */
    uint32_t size_mask = arm64_pci_read32(bus, dev, fn, bar_offset);

    fut_printf("[PCI] BAR%d size probe returned: 0x%08x\n", bar_num, size_mask);

    if (size_mask == 0 || size_mask == 0xFFFFFFFF) {
        fut_printf("[PCI] BAR%d not implemented (mask=0x%08x)\n", bar_num, size_mask);
        return 0;
    }

    /* Check BAR type */
    bool is_io = (size_mask & 0x1);
    bool is_64bit = ((size_mask & 0x6) == 0x4);

    if (is_io) {
        fut_printf("[PCI] BAR%d is I/O space (not supported)\n", bar_num);
        arm64_pci_write32(bus, dev, fn, bar_offset, 0);  /* Clear BAR */
        return 0;
    }

    /* Calculate size: size = ~(size_mask & ~0xF) + 1 */
    uint32_t size_bits = size_mask & ~0xFUL;
    uint32_t size = (~size_bits + 1) & 0xFFFFFFFF;

    fut_printf("[PCI] BAR%d size: %u bytes (%s)\n",
               bar_num, size, is_64bit ? "64-bit" : "32-bit");

    /* Align allocation to BAR size */
    uint64_t aligned_addr = (g_bar_alloc_next + size - 1) & ~((uint64_t)size - 1);

    /* Check if we have space */
    if (aligned_addr + size > PCIE_MMIO_BASE + PCIE_MMIO_SIZE) {
        fut_printf("[PCI] Out of MMIO space for BAR%d\n", bar_num);
        return 0;
    }

    /* Assign the BAR */
    if (is_64bit) {
        arm64_pci_write32(bus, dev, fn, bar_offset, (uint32_t)aligned_addr);
        arm64_pci_write32(bus, dev, fn, bar_offset + 4, (uint32_t)(aligned_addr >> 32));
        fut_printf("[PCI] Assigned BAR%d: 0x%llx\n", bar_num, (unsigned long long)aligned_addr);
    } else {
        arm64_pci_write32(bus, dev, fn, bar_offset, (uint32_t)aligned_addr);
        fut_printf("[PCI] Assigned BAR%d: 0x%08x\n", bar_num, (uint32_t)aligned_addr);
    }

    /* Update allocation pointer */
    g_bar_alloc_next = aligned_addr + size;

    /* Enable Memory Space in Command register */
    uint16_t cmd = arm64_pci_read32(bus, dev, fn, 0x04) & 0xFFFF;
    cmd |= 0x02;  /* Memory Space Enable */
    cmd |= 0x04;  /* Bus Master Enable (for DMA) */
    arm64_pci_write32(bus, dev, fn, 0x04, cmd);

    return aligned_addr;
}
