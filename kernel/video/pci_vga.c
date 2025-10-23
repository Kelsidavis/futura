// SPDX-License-Identifier: MPL-2.0
/*
 * pci_vga.c - PCI VGA Device Discovery
 *
 * Enumerate PCI bus to find VGA devices and discover their framebuffer
 * addresses via BAR (Base Address Register) configuration.
 */

#include <kernel/fb.h>
#include <kernel/console.h>
#include <platform/platform.h>
#include <stddef.h>
#include <stdint.h>
#include <stdbool.h>

/* PCI Configuration Space Access */
#define PCI_ADDRESS_PORT 0xCF8
#define PCI_DATA_PORT    0xCFC

/* PCI Device Classes */
#define PCI_CLASS_VGA            0x030000
#define PCI_CLASS_VGA_MASK       0xFF0000

/* Known VGA Vendors */
#define QEMU_VENDOR_ID           0x1013  /* QEMU/Cirrus */
#define BOCHS_VENDOR_ID          0x1234  /* Bochs */
#define REALTEK_VENDOR_ID        0x10EC

/* PCI Config Space Offsets */
#define PCI_VENDOR_ID_OFFSET     0x00
#define PCI_DEVICE_ID_OFFSET     0x02
#define PCI_CLASS_CODE_OFFSET    0x08  /* 3 bytes: class, subclass, interface */
#define PCI_BAR0_OFFSET          0x10
#define PCI_BAR1_OFFSET          0x14

#ifdef __x86_64__
/* I/O Port access macros */
static inline uint32_t inl(uint16_t port) {
    uint32_t result;
    __asm__ volatile("inl %1, %0" : "=a"(result) : "Nd"(port));
    return result;
}

static inline void outl(uint16_t port, uint32_t value) {
    __asm__ volatile("outl %0, %1" : : "a"(value), "Nd"(port));
}
#endif

#ifdef __x86_64__
/**
 * Read a 32-bit value from PCI configuration space
 *
 * @param bus Bus number (0-255)
 * @param slot Slot number (0-31)
 * @param func Function number (0-7)
 * @param offset Offset in configuration space (0-255)
 * @return 32-bit value from PCI config space
 */
static uint32_t pci_read_config(uint8_t bus, uint8_t slot, uint8_t func, uint8_t offset) {
    /* Build PCI address:
     * Bit 31:    Enable bit (1)
     * Bit 30-24: Reserved (0)
     * Bit 23-16: Bus number
     * Bit 15-11: Device number (slot)
     * Bit 10-8:  Function number
     * Bit 7-2:   Register offset
     * Bit 1-0:   Reserved (0)
     */
    uint32_t address = 0x80000000u
        | ((uint32_t)bus << 16)
        | ((uint32_t)slot << 11)
        | ((uint32_t)func << 8)
        | (offset & 0xFC);

    outl(PCI_ADDRESS_PORT, address);
    return inl(PCI_DATA_PORT);
}

/**
 * Scan PCI bus for VGA devices and discover framebuffer
 *
 * @return Physical address of framebuffer, or 0 if not found
 */
uint64_t pci_find_vga_framebuffer(void) {
    uint64_t found_bar_addr = 0;

    /* Scan PCI bus 0 for VGA devices */
    for (uint8_t slot = 0; slot < 32; slot++) {
        /* Check if device exists */
        uint32_t vendor_device = pci_read_config(0, slot, 0, PCI_VENDOR_ID_OFFSET);
        uint16_t vendor_id = vendor_device & 0xFFFF;
        uint16_t device_id = (vendor_device >> 16) & 0xFFFF;

        /* Skip empty slots */
        if (vendor_id == 0xFFFF || vendor_id == 0x0000) {
            continue;
        }

        /* Check device class */
        uint32_t class_code = pci_read_config(0, slot, 0, PCI_CLASS_CODE_OFFSET);
        uint32_t class_id = (class_code >> 8) & 0xFFFFFF;

        fut_printf("[PCI] Slot %d: Vendor 0x%04x Device 0x%04x Class 0x%06x\n",
                   slot, vendor_id, device_id, class_id);

        /* Look for VGA devices */
        if ((class_id & PCI_CLASS_VGA_MASK) == PCI_CLASS_VGA) {
            fut_printf("[PCI] Found VGA device at slot %d (vendor 0x%04x)\n", slot, vendor_id);

            /* Read BAR0 (framebuffer base address) */
            uint32_t bar0 = pci_read_config(0, slot, 0, PCI_BAR0_OFFSET);
            fut_printf("[PCI] BAR0 raw value: 0x%08x\n", bar0);

            if (bar0 == 0xFFFFFFFFu || bar0 == 0) {
                fut_printf("[PCI] BAR0 is invalid, trying BAR1\n");
                bar0 = pci_read_config(0, slot, 0, PCI_BAR1_OFFSET);
                fut_printf("[PCI] BAR1 raw value: 0x%08x\n", bar0);
            }

            if (bar0 != 0 && bar0 != 0xFFFFFFFFu) {
                uint64_t framebuffer_addr;

                /* Check if it's a 64-bit BAR (bit 2 set) */
                if ((bar0 & 0x04) == 0x04) {
                    /* 64-bit BAR: need to read BAR0 and BAR1 */
                    uint32_t bar1 = pci_read_config(0, slot, 0, PCI_BAR1_OFFSET);
                    framebuffer_addr = ((uint64_t)bar1 << 32) | (bar0 & ~0x0FuLL);
                    fut_printf("[PCI] 64-bit BAR: BAR0=0x%08x BAR1=0x%08x -> 0x%llx\n",
                               bar0, bar1, (unsigned long long)framebuffer_addr);
                } else {
                    /* 32-bit BAR */
                    framebuffer_addr = bar0 & ~0x0FuLL;
                    fut_printf("[PCI] 32-bit BAR: 0x%08x -> 0x%llx\n",
                               bar0, (unsigned long long)framebuffer_addr);
                }

                if (framebuffer_addr != 0) {
                    fut_printf("[PCI] VGA Framebuffer at 0x%llx\n",
                               (unsigned long long)framebuffer_addr);
                    found_bar_addr = framebuffer_addr;
                    break;
                }
            }
        }
    }

    /* Use discovered BAR address */
    if (found_bar_addr != 0) {
        fut_printf("[PCI] Using BAR-discovered address 0x%llx\n",
                   (unsigned long long)found_bar_addr);
        return found_bar_addr;
    }

    fut_printf("[PCI] No VGA device found on bus 0\n");
    return 0;
}
#endif

#ifdef __x86_64__
/**
 * Probe for VGA device and use its framebuffer
 * Called early during boot to override hardcoded framebuffer address
 */
int fb_probe_pci_vga(void) {
    uint64_t framebuffer = pci_find_vga_framebuffer();

    if (framebuffer == 0) {
        fut_printf("[FB] PCI VGA probe failed, no device found\n");
        return -1;
    }

    fut_printf("[FB] Using PCI-discovered framebuffer at 0x%llx\n",
               (unsigned long long)framebuffer);
    return 0;
}
#else
/* ARM64 stub - PCI VGA discovery not yet implemented */
int fb_probe_pci_vga(void) {
    fut_printf("[FB] ARM64: PCI VGA probe not yet implemented\n");
    return -1;
}
#endif
