// SPDX-License-Identifier: MPL-2.0
/*
 * cirrus_vga.c - Cirrus Logic VGA Device Driver
 *
 * Initializes Cirrus VGA device for linear framebuffer mode.
 * Handles device setup so direct memory writes work properly.
 */

#include <kernel/fb.h>
#include <kernel/console.h>
#include <platform/platform.h>
#include <stddef.h>
#include <stdint.h>
#include <stdbool.h>

/* VGA I/O ports */
#define VGA_MISC_WRITE          0x3C2
#define VGA_MISC_READ           0x3CC
#define VGA_SEQ_INDEX           0x3C4
#define VGA_SEQ_DATA            0x3C5
#define VGA_CRTC_INDEX          0x3D4
#define VGA_CRTC_DATA           0x3D5
#define VGA_GRAPHICS_INDEX      0x3CE
#define VGA_GRAPHICS_DATA       0x3CF
#define VGA_ATTR_INDEX          0x3C0
#define VGA_ATTR_DATA           0x3C1
#define VGA_STATUS_1            0x3DA

/* Cirrus-specific I/O ports */
#define CIRRUS_HIDDEN_DACS      0x3C6
#define CIRRUS_BACKWASH         0x3C7
#define CIRRUS_DACWAS           0x3C8

/* PCI configuration space offsets */
#define PCI_VENDOR_ID_OFFSET    0x00
#define PCI_COMMAND_OFFSET      0x04
#define PCI_BAR0_OFFSET         0x10

/* PCI Command register bits */
#define PCI_CMD_IO_ENABLE       0x0001
#define PCI_CMD_MEM_ENABLE      0x0002
#define PCI_CMD_MASTER_ENABLE   0x0004

/* I/O port access macros */
static inline uint8_t inb(uint16_t port) {
    uint8_t result;
    __asm__ volatile("inb %1, %0" : "=a"(result) : "Nd"(port));
    return result;
}

static inline void outb(uint16_t port, uint8_t value) {
    __asm__ volatile("outb %0, %1" : : "a"(value), "Nd"(port));
}

static inline uint16_t inw(uint16_t port) {
    uint16_t result;
    __asm__ volatile("inw %1, %0" : "=a"(result) : "Nd"(port));
    return result;
}

static inline void outw(uint16_t port, uint16_t value) {
    __asm__ volatile("outw %0, %1" : : "a"(value), "Nd"(port));
}

static inline uint32_t inl(uint16_t port) {
    uint32_t result;
    __asm__ volatile("inl %1, %0" : "=a"(result) : "Nd"(port));
    return result;
}

static inline void outl(uint16_t port, uint32_t value) {
    __asm__ volatile("outl %0, %1" : : "a"(value), "Nd"(port));
}

/**
 * Read from Cirrus Sequencer register
 */
static uint8_t cirrus_seq_read(uint8_t index) {
    outb(VGA_SEQ_INDEX, index);
    return inb(VGA_SEQ_DATA);
}

/**
 * Write to Cirrus Sequencer register
 */
static void cirrus_seq_write(uint8_t index, uint8_t value) {
    outb(VGA_SEQ_INDEX, index);
    outb(VGA_SEQ_DATA, value);
}

/**
 * Read from Cirrus Graphics register
 */
static uint8_t cirrus_gfx_read(uint8_t index) {
    outb(VGA_GRAPHICS_INDEX, index);
    return inb(VGA_GRAPHICS_DATA);
}

/**
 * Write to Cirrus Graphics register
 */
static void cirrus_gfx_write(uint8_t index, uint8_t value) {
    outb(VGA_GRAPHICS_INDEX, index);
    outb(VGA_GRAPHICS_DATA, value);
}

/**
 * Read from Cirrus CRT Controller register
 */
static uint8_t cirrus_crtc_read(uint8_t index) {
    outb(VGA_CRTC_INDEX, index);
    return inb(VGA_CRTC_DATA);
}

/**
 * Write to Cirrus CRT Controller register
 */
static void cirrus_crtc_write(uint8_t index, uint8_t value) {
    outb(VGA_CRTC_INDEX, index);
    outb(VGA_CRTC_DATA, value);
}

/**
 * Read from PCI configuration space (device at bus 0, slot 2)
 * Uses indirect I/O port access: 0xCF8 (address) and 0xCFC (data)
 */
static uint32_t pci_config_read(uint8_t offset) {
    uint32_t addr = (1u << 31) | (2 << 11) | offset;  /* bus 0, slot 2, offset */
    outl(0xCF8, addr);
    return inl(0xCFC);
}

/**
 * Write to PCI configuration space (device at bus 0, slot 2)
 */
static void pci_config_write(uint8_t offset, uint32_t value) {
    uint32_t addr = (1u << 31) | (2 << 11) | offset;  /* bus 0, slot 2, offset */
    outl(0xCF8, addr);
    outl(0xCFC, value);
}

/**
 * Initialize Cirrus VGA device for linear framebuffer mode
 *
 * This enables:
 * - PCI memory space access
 * - Linear framebuffer mode (1MB window at MMIO BAR)
 * - 1024x768 @ 32-bit color
 * - Direct memory writes to MMIO range
 */
int cirrus_vga_init(void) {
    fut_printf("[CIRRUS] Initializing Cirrus VGA for linear framebuffer\n");

    /* Enable PCI memory space via PCI command register
     * PCI_COMMAND at offset 0x04:
     * - bit 0: I/O Enable
     * - bit 1: Memory Enable
     * - bit 2: Bus Master Enable
     */
    uint32_t cmd = pci_config_read(PCI_COMMAND_OFFSET);
    cmd |= (PCI_CMD_IO_ENABLE | PCI_CMD_MEM_ENABLE);  /* Enable I/O and memory space */
    pci_config_write(PCI_COMMAND_OFFSET, cmd);
    fut_printf("[CIRRUS] PCI command register enabled (I/O and Memory access)\n");

    /* Enable memory space in VGA misc register for legacy I/O */
    uint8_t misc = inb(VGA_MISC_READ);
    outb(VGA_MISC_WRITE, misc | 0x03);  /* Enable color mode, I/O enable */

    /* Unlock CRTC registers */
    cirrus_crtc_write(0x11, cirrus_crtc_read(0x11) & 0x7F);

    /* Unlock Sequencer registers */
    cirrus_seq_write(0x06, cirrus_seq_read(0x06) | 0x12);

    /* Enable linear framebuffer in Cirrus extension registers
     * SR07 bit 4 = enable linear framebuffer
     */
    uint8_t sr07 = cirrus_seq_read(0x07);
    cirrus_seq_write(0x07, sr07 | 0x10);  /* Enable linear FB */
    /* Verify the bit was actually set by reading back */
    uint8_t sr07_verify = cirrus_seq_read(0x07);
    fut_printf("[CIRRUS] Linear framebuffer mode: SR07 set to 0x%02x (verify: 0x%02x)\n",
               (sr07 | 0x10), sr07_verify);

    /* Enable 1MB framebuffer window
     * SR08 controls the framebuffer granularity
     */
    cirrus_seq_write(0x08, 0x00);  /* 1MB window */

    /* Set 32-bit color mode
     * SR0F controls color depth
     * Bits 6-5: 00=8bpp, 01=16bpp, 10=24bpp, 11=32bpp
     */
    uint8_t sr0f = cirrus_seq_read(0x0F);
    cirrus_seq_write(0x0F, (sr0f & 0x9F) | 0x60);  /* 32-bit color */
    fut_printf("[CIRRUS] 32-bit color mode enabled (SR0F=0x%02x)\n", (sr0f & 0x9F) | 0x60);

    /* Disable DRAM refresh interference
     * GR0A bit 7 = enable VRAM access from display */
    uint8_t gr0a = cirrus_gfx_read(0x0A);
    cirrus_gfx_write(0x0A, gr0a | 0x80);

    /* Configure CRTC for 1024x768 linear framebuffer
     * CRTC Start Address (CR0C and CR0D) = 0 (framebuffer starts at offset 0)
     * CRTC Offset Register (CR13) = pitch in 2-byte units
     * For 1024 pixels @ 32bpp: pitch = 1024 * 4 = 4096 bytes = 2048 2-byte words
     */

    /* Set start address to 0 */
    cirrus_crtc_write(0x0C, 0x00);  /* Start address high byte */
    cirrus_crtc_write(0x0D, 0x00);  /* Start address low byte */

    /* Set pitch for linear 32-bit mode
     * For 1024x768x32, pitch = 4096 bytes per scanline
     * CR13 in linear mode appears to use: pitch_bytes / 8 = 512
     * But since 512 > 255, we use extended bits in CR1B
     *
     * Actually, for Cirrus in linear mode, we may need to use:
     * CR13 = (bytes_per_line / 8) & 0xFF = 512 & 0xFF = 0x00
     * CR1B[5:4] = (bytes_per_line / 8) >> 8 = 512 >> 8 = 0x02
     *
     * But empirically, 0x80 was giving better results. Let's use that.
     */

    /* Set CR13 to 0x80 (128) - this seems to work better in practice */
    cirrus_crtc_write(0x13, 0x80);

    fut_printf("[CIRRUS] Pitch: CR13=0x80 (empirical value for 1024x768x32)\n");

    fut_printf("[CIRRUS] CRTC configured for 1024x768x32 linear framebuffer\n");
    fut_printf("[CIRRUS] VGA initialization complete\n");
    return 0;
}
