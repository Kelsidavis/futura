// SPDX-License-Identifier: MPL-2.0
/*
 * cirrus_vga.c - Cirrus Logic VGA Device Driver
 *
 * Initializes Cirrus VGA device for linear framebuffer mode.
 * Handles device setup so direct memory writes work properly.
 */

#include <kernel/fb.h>
#include <kernel/console.h>
#include <kernel/kprintf.h>
#include <kernel/errno.h>
#include <platform/platform.h>
#include <stddef.h>
#include <stdint.h>
#include <stdbool.h>

#ifdef __x86_64__
#include <platform/x86_64/memory/pmap.h>
#endif

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
#ifdef __x86_64__
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
#endif /* __x86_64__ */

#ifdef __x86_64__
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
 * Read from PCI configuration space
 * Proper PCI address format: (1<<31) | (bus<<16) | (slot<<11) | (func<<8) | (offset & 0xFC)
 */
static uint32_t pci_config_read_bdf(uint8_t bus, uint8_t slot, uint8_t func, uint8_t offset) {
    uint32_t addr = (1u << 31)
                  | ((uint32_t)bus << 16)
                  | ((uint32_t)slot << 11)
                  | ((uint32_t)func << 8)
                  | ((uint32_t)offset & 0xFC);
    outl(0xCF8, addr);
    return inl(0xCFC);
}

/**
 * Write to PCI configuration space
 */
static void pci_config_write_bdf(uint8_t bus, uint8_t slot, uint8_t func, uint8_t offset, uint32_t value) {
    uint32_t addr = (1u << 31)
                  | ((uint32_t)bus << 16)
                  | ((uint32_t)slot << 11)
                  | ((uint32_t)func << 8)
                  | ((uint32_t)offset & 0xFC);
    outl(0xCF8, addr);
    outl(0xCFC, value);
}

/**
 * Diagnostic: dump all PCI BARs for this device
 */
static void cirrus_dump_pci_bars(uint8_t bus, uint8_t slot, uint8_t func) {
    uint32_t vdid = pci_config_read_bdf(bus, slot, func, 0x00);
    uint16_t vendor = (uint16_t)(vdid & 0xFFFF);
    uint16_t device = (uint16_t)((vdid >> 16) & 0xFFFF);
    fut_printf("[CIRRUS-DIAG] BDF %u:%u.%u vendor=0x%04x device=0x%04x\n",
               bus, slot, func, vendor, device);

    for (int i = 0; i < 6; ++i) {
        uint32_t off = 0x10 + i*4;
        uint32_t bar = pci_config_read_bdf(bus, slot, func, off);
        fut_printf("[CIRRUS-DIAG] BAR%d raw=0x%08x\n", i, bar);
    }
}

/**
 * Diagnostic: dump relevant CRTC and Sequencer registers
 */
static void cirrus_dump_regs(void) {
    uint8_t sr07 = cirrus_seq_read(0x07);
    uint8_t sr0f = cirrus_seq_read(0x0F);
    uint8_t cr13 = cirrus_crtc_read(0x13);
    uint8_t cr1b = cirrus_crtc_read(0x1B);
    uint8_t cr0c = cirrus_crtc_read(0x0C);
    uint8_t cr0d = cirrus_crtc_read(0x0D);
    fut_printf("[CIRRUS-DIAG] SR07=0x%02x SR0F=0x%02x CR13=0x%02x CR1B=0x%02x CR0C=0x%02x CR0D=0x%02x\n",
               sr07, sr0f, cr13, cr1b, cr0c, cr0d);
}

/**
 * Quick diagnostic: dump PCI BARs and CRTC registers
 */
static void cirrus_run_diagnostics(void) {
    fut_printf("\n[CIRRUS-DRUN] QUICK DIAGNOSTIC\n");
    cirrus_dump_pci_bars(0, 2, 0);
    cirrus_dump_regs();
    fut_printf("[CIRRUS-DRUN] DIAGNOSTIC COMPLETE\n\n");
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

    /* Verify we're accessing the correct PCI device (Cirrus at bus 0, slot 2, func 0) */
    uint32_t vdid = pci_config_read_bdf(0, 2, 0, 0x00);
    uint16_t vendor = (uint16_t)(vdid & 0xFFFF);
    uint16_t device = (uint16_t)((vdid >> 16) & 0xFFFF);
    fut_printf("[CIRRUS] PCI vendor=0x%04x device=0x%04x\n", vendor, device);

    if (vendor != 0x1013 || device != 0x00B8) {
        fut_printf("[CIRRUS] ERROR: Cirrus device not found at 0:2.0\n");
        return -ENODEV;
    }

    /* Enable PCI memory space via PCI command register */
    uint32_t cmd = pci_config_read_bdf(0, 2, 0, PCI_COMMAND_OFFSET);
    cmd |= (PCI_CMD_IO_ENABLE | PCI_CMD_MEM_ENABLE);
    pci_config_write_bdf(0, 2, 0, PCI_COMMAND_OFFSET, cmd);

    /* Verify the write */
    uint32_t cmd_verify = pci_config_read_bdf(0, 2, 0, PCI_COMMAND_OFFSET);
    fut_printf("[CIRRUS] PCI command: set=0x%08x verify=0x%08x\n", cmd, cmd_verify);

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

    /* Enable linear addressing in Sequencer Memory Mode (SR04)
     * Bit 3 = enable chain 4 mode (required for linear 32-bit mode)
     */
    uint8_t sr04 = cirrus_seq_read(0x04);
    cirrus_seq_write(0x04, sr04 | 0x08);  /* Set bit 3 for chain-4 linear mode */
    fut_printf("[CIRRUS] Linear addressing enabled (SR04=0x%02x)\n", sr04 | 0x08);

    /* CRITICAL: Disable text mode and enable graphics mode
     * GR05 Mode Register controls text vs graphics
     * Bit 0 = graphics mode enable (1 = graphics, 0 = text)
     * Bit 1 = reserved
     * Bit 4 = read mode (0 = read map select, 1 = color compare)
     * Bit 5 = shift register interleave mode
     */
    cirrus_gfx_write(0x05, 0x41);  /* 0x41 = bit0 set for graphics mode + shift256 mode */
    fut_printf("[CIRRUS] Graphics mode enabled (GR05=0x41, graphics mode fully active)\n");

    /* Set GR04 read map select to plane 0 */
    cirrus_gfx_write(0x04, 0x00);

    /* Disable all graphics planes initially (GR01 = 0)
     * GR01 = Set/Reset Enable - which planes get affected by set/reset
     */
    cirrus_gfx_write(0x01, 0x00);

    /* Disable DRAM refresh interference
     * GR0A bit 7 = enable VRAM access from display */
    uint8_t gr0a = cirrus_gfx_read(0x0A);
    cirrus_gfx_write(0x0A, gr0a | 0x80);

    /* Configure CRTC for 1024x768 linear framebuffer
     * CRTC Start Address (CR0C and CR0D) = 0 (framebuffer starts at offset 0)
     * CRTC Offset Register (CR13) = pitch in 2-byte units
     * For 1024 pixels @ 32bpp: pitch = 1024 * 4 = 4096 bytes = 2048 2-byte words
     */

    /* Set CRTC timing for 1024x768@60Hz display mode
     * These are standard VGA timing parameters needed for the device to actually
     * display the correct resolution. Without these, the display controller won't
     * show the framebuffer at the resolution we're writing to.
     */
    cirrus_crtc_write(0x00, 0xA3);  /* Horizontal Total */
    cirrus_crtc_write(0x01, 0x7F);  /* Horizontal Display End (1024-1 = 1023 = 0x3FF, in chars) */
    cirrus_crtc_write(0x02, 0x80);  /* Horizontal Blank Start */
    cirrus_crtc_write(0x03, 0x1C);  /* Horizontal Blank End */
    cirrus_crtc_write(0x04, 0x88);  /* Horizontal Sync Start */
    cirrus_crtc_write(0x05, 0x02);  /* Horizontal Sync End + Blank End bits */
    cirrus_crtc_write(0x06, 0x23);  /* Vertical Total Low (769-2 = 767 = 0x2FF) */
    cirrus_crtc_write(0x07, 0xB9);  /* Overflow (contains extended vertical bits) */
    cirrus_crtc_write(0x09, 0x00);  /* Maximum Scan Line (31 for single height) */
    cirrus_crtc_write(0x10, 0x04);  /* Vertical Sync Start */
    cirrus_crtc_write(0x11, 0x80);  /* Vertical Sync End (0x80 = disable int + 0 width) */
    cirrus_crtc_write(0x12, 0xFF);  /* Vertical Display End Low (768-1 = 767, low byte = 0xFF) */
    cirrus_crtc_write(0x15, 0xFF);  /* Vertical Blank Start (0xFF) */
    cirrus_crtc_write(0x16, 0x28);  /* Vertical Blank End (0x28) */
    cirrus_crtc_write(0x17, 0xC3);  /* CRTC Mode Control (enable refresh, no wrap) */

    fut_printf("[CIRRUS] Display timing set for 1024x768@60Hz\n");

    /* Set start address to 0 */
    cirrus_crtc_write(0x0C, 0x00);  /* Start address high byte */
    cirrus_crtc_write(0x0D, 0x00);  /* Start address low byte */

    /* Set pitch for linear 32-bit mode
     * For 1024x768x32, pitch = 4096 bytes per scanline
     * The pitch register expects bytes_per_line / 8 (logical units)
     * CR13 holds low 8 bits, CR1B[5:4] holds high 2 bits
     * bytes_per_line / 8 = 4096 / 8 = 512 = 0x200
     * So CR13 = 0x00, CR1B[5:4] = 0x02
     */
    uint32_t bytes_per_line = 1024 * 4;  /* 4096 */
    uint32_t lp = bytes_per_line / 8;    /* 512 */

    uint8_t cr13 = lp & 0xFF;            /* low 8 bits = 0x00 */
    uint8_t cr1b = cirrus_crtc_read(0x1B);
    cr1b &= ~0x30;                       /* clear bits 5:4 */
    cr1b |= ((lp >> 8) & 0x03) << 4;    /* place high 2 bits into bits 5:4 */

    cirrus_crtc_write(0x13, cr13);
    cirrus_crtc_write(0x1B, cr1b);

    fut_printf("[CIRRUS] Pitch: CR13=0x%02x CR1B=0x%02x (lp=%u bytes_per_line=%u)\n",
               cr13, cr1b, lp, bytes_per_line);

    fut_printf("[CIRRUS] CRTC configured for 1024x768x32 linear framebuffer\n");
    fut_printf("[CIRRUS] VGA initialization complete\n");

    /* Try to set the mode via Cirrus VBE (Bochs extension)
     * VBE port 0x1CE = index, 0x1CF = data
     * VBE register 0x04 = Enable (0xc0c3 enables VBE mode)
     * VBE registers 0x01, 0x02, 0x03 = X, Y resolution
     * VBE register 0x05 = Bits per pixel (0x20 = 32-bit)
     */
    outw(0x1CE, 0x04);  /* Select enable register */
    uint16_t vbe_enable = inw(0x1CF);
    outw(0x1CE, 0x04);
    outw(0x1CF, (vbe_enable | 0xc0c0));  /* Enable VBE with LFB */
    fut_printf("[CIRRUS] VBE enable attempted (VBE04=0x%04x)\n", vbe_enable | 0xc0c0);

    /* Run comprehensive diagnostics to identify root cause of display issues */
    cirrus_run_diagnostics();

    return 0;
}
#else /* !__x86_64__ */
/**
 * ARM64 stub - Cirrus VGA driver not supported
 */
int cirrus_vga_init(void) {
    return -ENOSYS;
}
#endif /* __x86_64__ */
