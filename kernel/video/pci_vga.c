// SPDX-License-Identifier: MPL-2.0
/*
 * pci_vga.c - PCI VGA Device Discovery
 *
 * Enumerate PCI bus to find VGA devices and discover their framebuffer
 * addresses via BAR (Base Address Register) configuration.
 */

#include <kernel/fb.h>
#include <kernel/console.h>
#include <kernel/kprintf.h>
#include <kernel/errno.h>
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

/* Bochs VBE DISPI Interface */
#define VBE_DISPI_INDEX_PORT     0x01CE
#define VBE_DISPI_DATA_PORT      0x01CF

#define VBE_DISPI_INDEX_ID       0x0
#define VBE_DISPI_INDEX_XRES     0x1
#define VBE_DISPI_INDEX_YRES     0x2
#define VBE_DISPI_INDEX_BPP      0x3
#define VBE_DISPI_INDEX_ENABLE   0x4
#define VBE_DISPI_INDEX_BANK     0x5
#define VBE_DISPI_INDEX_VIRT_WIDTH  0x6
#define VBE_DISPI_INDEX_VIRT_HEIGHT 0x7
#define VBE_DISPI_INDEX_X_OFFSET 0x8
#define VBE_DISPI_INDEX_Y_OFFSET 0x9

#define VBE_DISPI_DISABLED       0x00
#define VBE_DISPI_ENABLED        0x01
#define VBE_DISPI_LFB_ENABLED    0x40
#define VBE_DISPI_NOCLEARMEM     0x80

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

static inline uint16_t inw(uint16_t port) {
    uint16_t result;
    __asm__ volatile("inw %1, %0" : "=a"(result) : "Nd"(port));
    return result;
}

static inline void outw(uint16_t port, uint16_t value) {
    __asm__ volatile("outw %0, %1" : : "a"(value), "Nd"(port));
}

/**
 * Write to bochs VBE DISPI register
 */
static void bochs_dispi_write(uint16_t index, uint16_t value) {
    outw(VBE_DISPI_INDEX_PORT, index);
    outw(VBE_DISPI_DATA_PORT, value);
}

/**
 * Read from bochs VBE DISPI register
 */
static uint16_t bochs_dispi_read(uint16_t index) {
    outw(VBE_DISPI_INDEX_PORT, index);
    return inw(VBE_DISPI_DATA_PORT);
}

/**
 * Initialize bochs VGA to specified resolution and bit depth
 *
 * @param width Display width in pixels
 * @param height Display height in pixels
 * @param bpp Bits per pixel (typically 32)
 * @return 0 on success, -1 on failure
 */
int bochs_vga_init(uint16_t width, uint16_t height, uint16_t bpp) {
    /* Check if this is a bochs VGA by reading ID register */
    uint16_t id = bochs_dispi_read(VBE_DISPI_INDEX_ID);

    /* ID should be 0xB0C0 - 0xB0C5 for bochs VGA */
    if ((id & 0xFFF0) != 0xB0C0) {
        return -1;
    }

    /* Disable VBE first */
    bochs_dispi_write(VBE_DISPI_INDEX_ENABLE, VBE_DISPI_DISABLED);

    /* Set resolution */
    bochs_dispi_write(VBE_DISPI_INDEX_XRES, width);
    bochs_dispi_write(VBE_DISPI_INDEX_YRES, height);
    bochs_dispi_write(VBE_DISPI_INDEX_BPP, bpp);

    /* Set virtual width/height to match physical */
    bochs_dispi_write(VBE_DISPI_INDEX_VIRT_WIDTH, width);
    bochs_dispi_write(VBE_DISPI_INDEX_VIRT_HEIGHT, height);

    /* Set offsets to 0 */
    bochs_dispi_write(VBE_DISPI_INDEX_X_OFFSET, 0);
    bochs_dispi_write(VBE_DISPI_INDEX_Y_OFFSET, 0);

    /* Set bank to 0 (for LFB mode) */
    bochs_dispi_write(VBE_DISPI_INDEX_BANK, 0);

    /* Enable VBE with linear framebuffer, clear video memory to ensure clean start */
    bochs_dispi_write(VBE_DISPI_INDEX_ENABLE,
                      VBE_DISPI_ENABLED | VBE_DISPI_LFB_ENABLED);

    /* Verify VBE is enabled */
    uint16_t enable = bochs_dispi_read(VBE_DISPI_INDEX_ENABLE);
    if (!(enable & VBE_DISPI_ENABLED)) {
        fut_printf("[BOCHS] ERROR: VBE not enabled!\n");
        return -1;
    }

    fut_printf("[BOCHS] VGA %dx%d @ %dbpp\n", width, height, bpp);
    return 0;
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

        /* Skip empty slots */
        if (vendor_id == 0xFFFF || vendor_id == 0x0000) {
            continue;
        }

        /* Check device class */
        uint32_t class_code = pci_read_config(0, slot, 0, PCI_CLASS_CODE_OFFSET);
        uint32_t class_id = (class_code >> 8) & 0xFFFFFF;

        /* Look for VGA devices */
        if ((class_id & PCI_CLASS_VGA_MASK) == PCI_CLASS_VGA) {
            /* Read BAR0 (framebuffer base address) */
            uint32_t bar0 = pci_read_config(0, slot, 0, PCI_BAR0_OFFSET);

            if (bar0 == 0xFFFFFFFFu || bar0 == 0) {
                bar0 = pci_read_config(0, slot, 0, PCI_BAR1_OFFSET);
            }

            if (bar0 != 0 && bar0 != 0xFFFFFFFFu) {
                uint64_t framebuffer_addr;

                /* Check if it's a 64-bit BAR (bit 2 set) */
                if ((bar0 & 0x04) == 0x04) {
                    /* 64-bit BAR: need to read BAR0 and BAR1 */
                    uint32_t bar1 = pci_read_config(0, slot, 0, PCI_BAR1_OFFSET);
                    framebuffer_addr = ((uint64_t)bar1 << 32) | (bar0 & ~0x0FuLL);
                } else {
                    /* 32-bit BAR */
                    framebuffer_addr = bar0 & ~0x0FuLL;
                }

                if (framebuffer_addr != 0) {
                    fut_printf("[PCI] VGA at slot %d, FB 0x%llx\n",
                               slot, (unsigned long long)framebuffer_addr);
                    found_bar_addr = framebuffer_addr;
                    break;
                }
            }
        }
    }

    return found_bar_addr;
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
        return -ENODEV;
    }

    fut_printf("[FB] Using PCI-discovered framebuffer at 0x%llx\n",
               (unsigned long long)framebuffer);
    return 0;
}
#else
/* ARM64 stub - PCI VGA discovery not yet implemented */
int fb_probe_pci_vga(void) {
    fut_printf("[FB] ARM64: PCI VGA probe not yet implemented\n");
    return -ENOSYS;
}
#endif
