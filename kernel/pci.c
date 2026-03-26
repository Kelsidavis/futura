/* kernel/pci.c - PCI bus enumeration
 *
 * Copyright (c) 2025 Kelsi Davis
 * Licensed under the MPL v2.0 — see LICENSE for details.
 *
 * Scans PCI configuration space to discover all devices on the bus.
 * Stores device info in a table for use by procfs and lspci.
 */

#include <kernel/pci.h>
#include <kernel/kprintf.h>

static struct pci_device g_pci_devices[PCI_MAX_DEVICES];
static int g_pci_count = 0;

#ifdef __x86_64__

static inline void outl(uint16_t port, uint32_t val) {
    __asm__ volatile("outl %0, %1" :: "a"(val), "Nd"(port));
}

static inline uint32_t inl(uint16_t port) {
    uint32_t val;
    __asm__ volatile("inl %1, %0" : "=a"(val) : "Nd"(port));
    return val;
}

static uint32_t pci_cfg_read32(uint8_t bus, uint8_t dev, uint8_t func, uint8_t offset) {
    uint32_t addr = (1u << 31) |
                    ((uint32_t)bus << 16) |
                    ((uint32_t)(dev & 0x1F) << 11) |
                    ((uint32_t)(func & 0x07) << 8) |
                    ((uint32_t)offset & 0xFC);
    outl(0xCF8, addr);
    return inl(0xCFC);
}

static uint16_t pci_cfg_read16(uint8_t bus, uint8_t dev, uint8_t func, uint8_t offset) {
    uint32_t data = pci_cfg_read32(bus, dev, func, offset);
    return (uint16_t)(data >> ((offset & 2) * 8));
}

static uint8_t pci_cfg_read8(uint8_t bus, uint8_t dev, uint8_t func, uint8_t offset) {
    uint32_t data = pci_cfg_read32(bus, dev, func, offset);
    return (uint8_t)(data >> ((offset & 3) * 8));
}

static void pci_scan_device(uint8_t bus, uint8_t dev, uint8_t func) {
    uint16_t vendor = pci_cfg_read16(bus, dev, func, 0x00);
    if (vendor == 0xFFFF) return;  /* No device */

    if (g_pci_count >= PCI_MAX_DEVICES) return;

    struct pci_device *d = &g_pci_devices[g_pci_count];
    d->bus       = bus;
    d->dev       = dev;
    d->func      = func;
    d->vendor_id = vendor;
    d->device_id = pci_cfg_read16(bus, dev, func, 0x02);

    uint32_t class_reg = pci_cfg_read32(bus, dev, func, 0x08);
    d->class_code = (uint8_t)(class_reg >> 24);
    d->subclass   = (uint8_t)(class_reg >> 16);
    d->prog_if    = (uint8_t)(class_reg >> 8);
    d->revision   = (uint8_t)(class_reg);

    d->header_type  = pci_cfg_read8(bus, dev, func, 0x0E) & 0x7F;
    d->subsys_vendor = pci_cfg_read16(bus, dev, func, 0x2C);
    d->subsys_id     = pci_cfg_read16(bus, dev, func, 0x2E);
    d->irq_line      = pci_cfg_read8(bus, dev, func, 0x3C);

    g_pci_count++;
}

void pci_enumerate(void) {
    g_pci_count = 0;

    for (int bus = 0; bus < 256; bus++) {
        for (int dev = 0; dev < 32; dev++) {
            uint16_t vendor = pci_cfg_read16((uint8_t)bus, (uint8_t)dev, 0, 0x00);
            if (vendor == 0xFFFF) continue;

            uint8_t header = pci_cfg_read8((uint8_t)bus, (uint8_t)dev, 0, 0x0E);
            int max_func = (header & 0x80) ? 8 : 1;  /* Multi-function? */

            for (int func = 0; func < max_func; func++) {
                pci_scan_device((uint8_t)bus, (uint8_t)dev, (uint8_t)func);
            }
        }
    }

    fut_printf("[PCI] Enumerated %d device(s)\n", g_pci_count);
}

#else /* ARM64 */

void pci_enumerate(void) {
    g_pci_count = 0;
    fut_printf("[PCI] PCI enumeration not supported on this platform\n");
}

#endif

int pci_device_count(void) {
    return g_pci_count;
}

const struct pci_device *pci_get_device(int index) {
    if (index < 0 || index >= g_pci_count) return (void*)0;
    return &g_pci_devices[index];
}
