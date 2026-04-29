// SPDX-License-Identifier: MPL-2.0
/*
 * fb_console.c - Framebuffer-based console driver
 *
 * Provides text output directly to framebuffer memory without requiring
 * a serial console. Useful for embedded systems (RPi5) and headless QEMU.
 *
 * Character rendering: Simple 8x8 pixel monospace characters
 * Scrolling: Vertical scrolling when reaching bottom
 */

#include <kernel/fb_console.h>
#include <kernel/fb.h>
#include <kernel/errno.h>
#include <platform/platform.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>

/* ============================================================
 *   Simple 8x8 Bitmap Font
 * ============================================================ */

/* ASCII characters 32-126 as 8x8 pixel bitmaps */
static const uint8_t g_font_8x8[95][8] = {
    /* 32: space */ {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00},
    /* 33: ! */ {0x18, 0x3C, 0x3C, 0x18, 0x18, 0x00, 0x18, 0x00},
    /* 34: " */ {0x66, 0x66, 0x44, 0x00, 0x00, 0x00, 0x00, 0x00},
    /* 35: # */ {0x36, 0x36, 0x7F, 0x36, 0x7F, 0x36, 0x36, 0x00},
    /* 36: $ */ {0x0C, 0x3E, 0x60, 0x3C, 0x06, 0x7C, 0x18, 0x00},
    /* 37: % */ {0x62, 0x66, 0x0C, 0x18, 0x30, 0x66, 0x46, 0x00},
    /* 38: & */ {0x3C, 0x66, 0x3C, 0x38, 0x67, 0x66, 0x3F, 0x00},
    /* 39: ' */ {0x18, 0x18, 0x30, 0x00, 0x00, 0x00, 0x00, 0x00},
    /* 40: ( */ {0x0C, 0x18, 0x30, 0x30, 0x30, 0x18, 0x0C, 0x00},
    /* 41: ) */ {0x30, 0x18, 0x0C, 0x0C, 0x0C, 0x18, 0x30, 0x00},
    /* 42: * */ {0x00, 0x18, 0x7E, 0x3C, 0x7E, 0x18, 0x00, 0x00},
    /* 43: + */ {0x00, 0x18, 0x18, 0x7E, 0x18, 0x18, 0x00, 0x00},
    /* 44: , */ {0x00, 0x00, 0x00, 0x00, 0x00, 0x18, 0x18, 0x30},
    /* 45: - */ {0x00, 0x00, 0x00, 0x7E, 0x00, 0x00, 0x00, 0x00},
    /* 46: . */ {0x00, 0x00, 0x00, 0x00, 0x00, 0x18, 0x18, 0x00},
    /* 47: / */ {0x06, 0x0C, 0x18, 0x30, 0x60, 0xC0, 0x80, 0x00},
    /* 48: 0 */ {0x3C, 0x66, 0x6E, 0x7E, 0x76, 0x66, 0x3C, 0x00},
    /* 49: 1 */ {0x18, 0x38, 0x18, 0x18, 0x18, 0x18, 0x7E, 0x00},
    /* 50: 2 */ {0x3C, 0x66, 0x06, 0x0C, 0x18, 0x30, 0x7E, 0x00},
    /* 51: 3 */ {0x3C, 0x66, 0x06, 0x1C, 0x06, 0x66, 0x3C, 0x00},
    /* 52: 4 */ {0x0C, 0x1C, 0x3C, 0x6C, 0x7E, 0x0C, 0x0C, 0x00},
    /* 53: 5 */ {0x7E, 0x60, 0x7C, 0x06, 0x06, 0x66, 0x3C, 0x00},
    /* 54: 6 */ {0x1C, 0x30, 0x60, 0x7C, 0x66, 0x66, 0x3C, 0x00},
    /* 55: 7 */ {0x7E, 0x06, 0x0C, 0x18, 0x30, 0x60, 0x60, 0x00},
    /* 56: 8 */ {0x3C, 0x66, 0x66, 0x3C, 0x66, 0x66, 0x3C, 0x00},
    /* 57: 9 */ {0x3C, 0x66, 0x66, 0x3E, 0x06, 0x0C, 0x38, 0x00},
    /* 58: : */ {0x00, 0x18, 0x18, 0x00, 0x18, 0x18, 0x00, 0x00},
    /* 59: ; */ {0x00, 0x18, 0x18, 0x00, 0x18, 0x18, 0x30, 0x00},
    /* 60: < */ {0x0C, 0x18, 0x30, 0x60, 0x30, 0x18, 0x0C, 0x00},
    /* 61: = */ {0x00, 0x00, 0x7E, 0x00, 0x7E, 0x00, 0x00, 0x00},
    /* 62: > */ {0x30, 0x18, 0x0C, 0x06, 0x0C, 0x18, 0x30, 0x00},
    /* 63: ? */ {0x3C, 0x66, 0x06, 0x0C, 0x18, 0x00, 0x18, 0x00},
    /* 64: @ */ {0x3C, 0x66, 0x6E, 0x6E, 0x60, 0x62, 0x3C, 0x00},
    /* 65: A */ {0x18, 0x3C, 0x66, 0x7E, 0x66, 0x66, 0x66, 0x00},
    /* 66: B */ {0x7C, 0x66, 0x66, 0x7C, 0x66, 0x66, 0x7C, 0x00},
    /* 67: C */ {0x3C, 0x66, 0x60, 0x60, 0x60, 0x66, 0x3C, 0x00},
    /* 68: D */ {0x78, 0x6C, 0x66, 0x66, 0x66, 0x6C, 0x78, 0x00},
    /* 69: E */ {0x7E, 0x60, 0x60, 0x7C, 0x60, 0x60, 0x7E, 0x00},
    /* 70: F */ {0x7E, 0x60, 0x60, 0x7C, 0x60, 0x60, 0x60, 0x00},
    /* 71: G */ {0x3C, 0x66, 0x60, 0x6E, 0x66, 0x66, 0x3C, 0x00},
    /* 72: H */ {0x66, 0x66, 0x66, 0x7E, 0x66, 0x66, 0x66, 0x00},
    /* 73: I */ {0x7E, 0x18, 0x18, 0x18, 0x18, 0x18, 0x7E, 0x00},
    /* 74: J */ {0x06, 0x06, 0x06, 0x06, 0x66, 0x66, 0x3C, 0x00},
    /* 75: K */ {0x66, 0x6C, 0x78, 0x70, 0x78, 0x6C, 0x66, 0x00},
    /* 76: L */ {0x60, 0x60, 0x60, 0x60, 0x60, 0x60, 0x7E, 0x00},
    /* 77: M */ {0x63, 0x77, 0x7F, 0x6B, 0x63, 0x63, 0x63, 0x00},
    /* 78: N */ {0x66, 0x76, 0x7E, 0x7E, 0x6E, 0x66, 0x66, 0x00},
    /* 79: O */ {0x3C, 0x66, 0x66, 0x66, 0x66, 0x66, 0x3C, 0x00},
    /* 80: P */ {0x7C, 0x66, 0x66, 0x7C, 0x60, 0x60, 0x60, 0x00},
    /* 81: Q */ {0x3C, 0x66, 0x66, 0x66, 0x6E, 0x3C, 0x0E, 0x00},
    /* 82: R */ {0x7C, 0x66, 0x66, 0x7C, 0x78, 0x6C, 0x66, 0x00},
    /* 83: S */ {0x3C, 0x66, 0x60, 0x3C, 0x06, 0x66, 0x3C, 0x00},
    /* 84: T */ {0x7E, 0x18, 0x18, 0x18, 0x18, 0x18, 0x18, 0x00},
    /* 85: U */ {0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x3C, 0x00},
    /* 86: V */ {0x66, 0x66, 0x66, 0x66, 0x66, 0x3C, 0x18, 0x00},
    /* 87: W */ {0x63, 0x63, 0x63, 0x6B, 0x7F, 0x77, 0x63, 0x00},
    /* 88: X */ {0x66, 0x66, 0x3C, 0x18, 0x3C, 0x66, 0x66, 0x00},
    /* 89: Y */ {0x66, 0x66, 0x66, 0x3C, 0x18, 0x18, 0x18, 0x00},
    /* 90: Z */ {0x7E, 0x06, 0x0C, 0x18, 0x30, 0x60, 0x7E, 0x00},
    /* 91: [ */ {0x3C, 0x30, 0x30, 0x30, 0x30, 0x30, 0x3C, 0x00},
    /* 92: \ */ {0x80, 0xC0, 0x60, 0x30, 0x18, 0x0C, 0x06, 0x00},
    /* 93: ] */ {0x3C, 0x0C, 0x0C, 0x0C, 0x0C, 0x0C, 0x3C, 0x00},
    /* 94: ^ */ {0x10, 0x38, 0x6C, 0x00, 0x00, 0x00, 0x00, 0x00},
    /* 95: _ */ {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xFF},
    /* 96: ` */ {0x60, 0x30, 0x18, 0x00, 0x00, 0x00, 0x00, 0x00},
    /* 97: a */ {0x00, 0x00, 0x3C, 0x06, 0x3E, 0x66, 0x3E, 0x00},
    /* 98: b */ {0x60, 0x60, 0x7C, 0x66, 0x66, 0x66, 0x7C, 0x00},
    /* 99: c */ {0x00, 0x00, 0x3C, 0x60, 0x60, 0x60, 0x3C, 0x00},
    /* 100: d */ {0x06, 0x06, 0x3E, 0x66, 0x66, 0x66, 0x3E, 0x00},
    /* 101: e */ {0x00, 0x00, 0x3C, 0x66, 0x7E, 0x60, 0x3C, 0x00},
    /* 102: f */ {0x1C, 0x30, 0x30, 0x7C, 0x30, 0x30, 0x30, 0x00},
    /* 103: g */ {0x00, 0x00, 0x3E, 0x66, 0x66, 0x3E, 0x06, 0x3C},
    /* 104: h */ {0x60, 0x60, 0x7C, 0x66, 0x66, 0x66, 0x66, 0x00},
    /* 105: i */ {0x18, 0x00, 0x38, 0x18, 0x18, 0x18, 0x3C, 0x00},
    /* 106: j */ {0x0C, 0x00, 0x0C, 0x0C, 0x0C, 0x0C, 0x6C, 0x38},
    /* 107: k */ {0x60, 0x60, 0x66, 0x6C, 0x78, 0x6C, 0x66, 0x00},
    /* 108: l */ {0x38, 0x18, 0x18, 0x18, 0x18, 0x18, 0x3C, 0x00},
    /* 109: m */ {0x00, 0x00, 0x6C, 0x7F, 0x6B, 0x6B, 0x6B, 0x00},
    /* 110: n */ {0x00, 0x00, 0x7C, 0x66, 0x66, 0x66, 0x66, 0x00},
    /* 111: o */ {0x00, 0x00, 0x3C, 0x66, 0x66, 0x66, 0x3C, 0x00},
    /* 112: p */ {0x00, 0x00, 0x7C, 0x66, 0x66, 0x7C, 0x60, 0x60},
    /* 113: q */ {0x00, 0x00, 0x3E, 0x66, 0x66, 0x3E, 0x06, 0x06},
    /* 114: r */ {0x00, 0x00, 0x7C, 0x66, 0x60, 0x60, 0x60, 0x00},
    /* 115: s */ {0x00, 0x00, 0x3C, 0x60, 0x3C, 0x06, 0x3C, 0x00},
    /* 116: t */ {0x30, 0x30, 0x7C, 0x30, 0x30, 0x30, 0x1C, 0x00},
    /* 117: u */ {0x00, 0x00, 0x66, 0x66, 0x66, 0x66, 0x3E, 0x00},
    /* 118: v */ {0x00, 0x00, 0x66, 0x66, 0x66, 0x3C, 0x18, 0x00},
    /* 119: w */ {0x00, 0x00, 0x6B, 0x6B, 0x6B, 0x7F, 0x6B, 0x00},
    /* 120: x */ {0x00, 0x00, 0x66, 0x3C, 0x18, 0x3C, 0x66, 0x00},
    /* 121: y */ {0x00, 0x00, 0x66, 0x66, 0x66, 0x3E, 0x06, 0x3C},
    /* 122: z */ {0x00, 0x00, 0x7E, 0x0C, 0x18, 0x30, 0x7E, 0x00},
    /* 123: { */ {0x0E, 0x18, 0x18, 0x70, 0x18, 0x18, 0x0E, 0x00},
    /* 124: | */ {0x18, 0x18, 0x18, 0x18, 0x18, 0x18, 0x18, 0x00},
    /* 125: } */ {0x70, 0x18, 0x18, 0x0E, 0x18, 0x18, 0x70, 0x00},
    /* 126: ~ */ {0x7C, 0x36, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00},
};

/* ============================================================
 *   Framebuffer Console State
 * ============================================================ */

/* ANSI/VT escape parser state. Userland (the shell) drives the console
 * with ECMA-48 sequences (color, cursor moves, clears) — without a tiny
 * parser those sequences land on the framebuffer as literal '?[33m' etc.
 * and turn the screen into garbage. We don't need to render colors yet
 * (the font is mono-white-on-black), but stripping the sequences lets
 * actual text show through cleanly. */
typedef enum {
    ANSI_NORMAL = 0,
    ANSI_ESC,        /* saw ESC (0x1B), waiting for '[' or single-char  */
    ANSI_CSI         /* in CSI body, swallowing until final byte 0x40-0x7E */
} ansi_state_t;

struct fb_console_state {
    volatile uint8_t *fb_mem;        /* Framebuffer memory pointer */
    uint32_t width;                  /* Framebuffer width in pixels */
    uint32_t height;                 /* Framebuffer height in pixels */
    uint32_t pitch;                  /* Bytes per scanline */
    uint32_t bpp;                    /* Bits per pixel (32 for RGBA) */
    int cursor_x;                    /* Current cursor X (in characters) */
    int cursor_y;                    /* Current cursor Y (in characters) */
    int char_width;                  /* Character width in pixels (8) */
    int char_height;                 /* Character height in pixels (8) */
    int cols;                        /* Number of columns */
    int rows;                        /* Number of rows */
    int protected_x_start;           /* Start column of protected region (logo area) */
    int protected_y_end;             /* End row of protected region (logo area) */
    int initialized;                 /* Has been initialized */
    int disabled;                    /* Disabled for GUI mode */
    ansi_state_t ansi;               /* Escape-sequence parser state */
};

static struct fb_console_state g_fb_console = {0};

/* ============================================================
 *   Helper Functions
 * ============================================================ */

static inline uint32_t make_color(uint8_t r, uint8_t g, uint8_t b, uint8_t a) {
    return ((uint32_t)a << 24) | ((uint32_t)r << 16) | ((uint32_t)g << 8) | (uint32_t)b;
}

static void fb_console_draw_pixel(int x, int y, uint32_t color) {
    struct fb_console_state *cons = &g_fb_console;

    if (x < 0 || x >= (int)cons->width || y < 0 || y >= (int)cons->height) {
        return;
    }

    uint8_t *fb = (uint8_t *)cons->fb_mem;

    /* Sanity check: fb_mem must be a kernel-half virtual address.
     * Per-arch threshold — same root cause as the matching check in
     * fb_console_scroll: the hard-coded x86 base (0xFFFFFFFF80000000)
     * is far above any valid ARM64 fb_mem (TTBR1 base is
     * 0xFFFF800000000000), so on ARM64 the check tripped on every
     * single pixel and EVERY draw was silently skipped — the actual
     * cause of the QEMU-window-stays-black symptom even after the
     * phys→virt mapping and virtio-gpu flush were correct. */
#if defined(__aarch64__)
    if ((uintptr_t)fb < 0xFFFF800000000000ULL) {
#else
    if ((uintptr_t)fb < 0xFFFFFFFF80000000ULL) {
#endif
        return;  /* Skip draw - fb_mem corrupted */
    }

    uint32_t offset = (y * cons->pitch) + (x * 4);
    if (cons->bpp == 32) {
        *(volatile uint32_t *)(fb + offset) = color;
    } else if (cons->bpp == 24) {
        fb[offset + 0] = (color >> 16) & 0xFF;
        fb[offset + 1] = (color >> 8) & 0xFF;
        fb[offset + 2] = color & 0xFF;
    }
}

static void fb_console_draw_char(int char_x, int char_y, char c, uint32_t fg_color, uint32_t bg_color) {
    struct fb_console_state *cons = &g_fb_console;

    if (c < 32 || c > 126) {
        c = '?';
    }

    const uint8_t *glyph = g_font_8x8[c - 32];
    int pixel_x = char_x * cons->char_width;
    int pixel_y = char_y * cons->char_height;

    for (int row = 0; row < cons->char_height; row++) {
        uint8_t bits = glyph[row];
        for (int col = 0; col < cons->char_width; col++) {
            uint32_t color = (bits & (1 << (7 - col))) ? fg_color : bg_color;
            fb_console_draw_pixel(pixel_x + col, pixel_y + row, color);
        }
    }
}

static void fb_console_scroll(void) {
    struct fb_console_state *cons = &g_fb_console;

    uint8_t *fb = (uint8_t *)cons->fb_mem;

    /* Sanity check: fb_mem must be a kernel-half virtual address.
     * The threshold differs per arch — x86_64 puts the kernel half at
     * 0xFFFFFFFF80000000 (negative-2 GiB), ARM64 at 0xFFFF800000000000
     * (TTBR1 base). The previous hard-coded x86 value was always
     * larger than any valid ARM64 fb_mem (e.g. 0xFFFFFF8042c02000), so
     * the check tripped on every scroll → the early 'return' meant the
     * ARM64 console NEVER scrolled. Once the screen filled, the cursor
     * stuck on the last row and every new character overwrote the
     * previous one, hiding the bottom of the boot log and the shell
     * prompt under itself. */
#if defined(__aarch64__)
    if ((uintptr_t)fb < 0xFFFF800000000000ULL) {
#else
    if ((uintptr_t)fb < 0xFFFFFFFF80000000ULL) {
#endif
        return;  /* Skip scroll to avoid crash - corruption detected */
    }

    /* Calculate protected region pixel boundaries */
    int protected_x_pixels = cons->protected_x_start * cons->char_width * 4; /* In bytes */

    /* Move all lines up by one character height, but avoid the logo area */
    for (int y = 0; y < (cons->rows - 1) * cons->char_height; y++) {
        uint32_t src_offset = (y + cons->char_height) * cons->pitch;
        uint32_t dst_offset = y * cons->pitch;

        /* Only scroll the text area (left side), not the logo area (right side) */
        for (uint32_t x = 0; x < (uint32_t)protected_x_pixels; x++) {
            fb[dst_offset + x] = fb[src_offset + x];
        }
    }

    /* Clear the bottom CHARACTER row — that's char_height pixel rows,
     * not just one. The previous code wrote bg_color to a single pixel
     * row at the start of the last char row, leaving the other 7 rows
     * full of whatever was there before scroll. New characters drawn on
     * top of those stale pixels look visibly overprinted on the prior
     * line — visible on the QEMU display as garbled / overlapping text
     * at the bottom of the screen during boot. */
    uint32_t bg_color = make_color(0, 0, 0, 255);
    for (int row = 0; row < cons->char_height; row++) {
        uint32_t row_offset = ((cons->rows - 1) * cons->char_height + row) * cons->pitch;
        uint32_t *fb_word = (uint32_t *)(fb + row_offset);
        for (uint32_t i = 0; i < (uint32_t)(protected_x_pixels / 4); i++) {
            fb_word[i] = bg_color;
        }
    }
}

/* ============================================================
 *   Public API
 * ============================================================ */

int fb_console_init(void) {
    struct fb_console_state *cons = &g_fb_console;

    if (cons->initialized) {
        return 0;
    }

    /* Get framebuffer from global framebuffer info */
    extern int fb_get_info(struct fut_fb_hwinfo *out);
    struct fut_fb_hwinfo hw_info = {0};

    if (fb_get_info(&hw_info) != 0) {
        fut_printf("[FB_CONSOLE] No framebuffer available\n");
        return -ENODEV;
    }

    if (hw_info.info.width == 0 || hw_info.info.height == 0) {
        fut_printf("[FB_CONSOLE] Invalid framebuffer dimensions\n");
        return -EINVAL;
    }

    cons->width = hw_info.info.width;
    cons->height = hw_info.info.height;
    cons->pitch = hw_info.info.pitch;
    cons->bpp = hw_info.info.bpp;

#ifdef __x86_64__
    /* Get the virtual address of the framebuffer (already mapped by fb_boot_splash) */
    extern void *fb_get_virt_addr(void);
    cons->fb_mem = (volatile uint8_t *)fb_get_virt_addr();
    if (!cons->fb_mem) {
        fut_printf("[FB_CONSOLE] Failed to get framebuffer virtual address\n");
        return -EFAULT;
    }
#elif defined(__aarch64__)
    /* On ARM64, convert framebuffer physical address to kernel virtual.
     *
     * The framebuffer that virtio-gpu (MMIO transport) hands us lives
     * in DRAM (allocated via PMM), not in the peripheral region. The
     * kernel-half mapping for DRAM uses KERN_VA_BASE/KERN_PA_BASE with
     * an offset of 0xFFFFFF7FFFE00000 (NOT 0xFFFFFF8000000000 — that's
     * 2 MiB too high because the kernel loads at PA 0x40200000, not
     * 0x40000000). Writing to the wrong virt address produced silent
     * 'black screen' behavior: the kernel happily wrote characters to
     * an unmapped or wrongly-mapped page and the actual framebuffer
     * stayed all-zero.
     *
     * Use pmap_phys_to_virt so this stays in lock-step with the kernel
     * memory map. */
    extern void *pmap_phys_to_virt(uint64_t pa);
    cons->fb_mem = (volatile uint8_t *)pmap_phys_to_virt((uint64_t)hw_info.phys);
#else
    cons->fb_mem = (volatile uint8_t *)hw_info.phys;
#endif

    cons->char_width = 8;
    cons->char_height = 8;

    /* Reserve space for Rory logo in top-right corner */
    /* Logo is 100 pixels wide + 20px margin = 120 pixels, that's 15 columns */
    int logo_cols = 15;
    int logo_rows = 15;  /* Logo height 100 pixels + 20px margin = 120 pixels / 8 = 15 rows */

    cons->cols = (cons->width / cons->char_width) - logo_cols;
    cons->rows = cons->height / cons->char_height;
    cons->cursor_x = 0;
    cons->cursor_y = 0;

    /* Store protected region info for the logo */
    cons->protected_x_start = cons->cols;  /* Start of protected columns */
    cons->protected_y_end = logo_rows;     /* End of protected rows */
    cons->initialized = 1;

    fut_printf("[FB_CONSOLE] Initialized: %ux%u, %u cols x %u rows\n",
               cons->width, cons->height, cons->cols, cons->rows);

    fb_console_clear();

    return 0;
}

void fb_console_clear(void) {
    struct fb_console_state *cons = &g_fb_console;

    if (!cons->initialized) {
        return;
    }

    /* Fill with opaque black (0xFF000000 in ARGB) - don't use memset(0)
     * because 0x00000000 may not display as black on all hardware */
    uint32_t *fb32 = (uint32_t *)cons->fb_mem;
    size_t pixel_count = (cons->pitch * cons->height) / 4;
    uint32_t black = 0xFF000000;  /* Opaque black */
    for (size_t i = 0; i < pixel_count; i++) {
        fb32[i] = black;
    }

    cons->cursor_x = 0;
    cons->cursor_y = 0;
}

/* Push the dirty framebuffer region to the display. virtio-gpu (both
 * MMIO and PCI transports) keeps the host-side resource separate from
 * the guest backing pages and only refreshes on TRANSFER_TO_HOST_2D +
 * RESOURCE_FLUSH. Without this, fb_console_putc draws into guest DRAM
 * and the QEMU window stays black even though the pixels are correct.
 *
 * Two protection mechanisms working together:
 * 1) Disable IRQs across the flush so no kernel printf from an IRQ
 *    handler can preempt us mid-flush. submit_gpu_command in the
 *    virtio-gpu driver isn't reentrant — desc[0]/desc[1] are reused on
 *    every call — so a nested fb_console_putc → flush would corrupt
 *    the in-flight descriptor and the device would stop processing.
 * 2) An additional same-CPU re-entrancy guard for the case where the
 *    outer flush itself somehow recurses (e.g. fut_serial_putc inside
 *    the GPU driver), to keep behavior bounded.
 *
 * A previous version of this code only had the busy guard. That
 * dropped most flushes (every IRQ-context printf was a candidate for
 * coming in mid-flush) and the display stopped updating after the
 * first line. Disabling IRQs eliminates the race entirely.
 *
 * Resolved at runtime so this driver builds on platforms without
 * virtio-gpu (the symbol is just absent → the weak ref is NULL → no-op). */
static volatile int fb_console_present_busy = 0;
static void fb_console_present(void) {
    extern uint64_t fut_save_and_disable_interrupts(void) __attribute__((weak));
    extern void fut_restore_interrupts(uint64_t state) __attribute__((weak));

    uint64_t irq_state = 0;
    if (fut_save_and_disable_interrupts) {
        irq_state = fut_save_and_disable_interrupts();
    }

    if (__atomic_exchange_n(&fb_console_present_busy, 1, __ATOMIC_ACQ_REL) == 0) {
#if defined(__aarch64__)
        extern void virtio_gpu_flush_display_mmio(void) __attribute__((weak));
        if (virtio_gpu_flush_display_mmio) {
            virtio_gpu_flush_display_mmio();
        }
#else
        extern void virtio_gpu_flush_display(void) __attribute__((weak));
        if (virtio_gpu_flush_display) {
            virtio_gpu_flush_display();
        }
#endif
        __atomic_store_n(&fb_console_present_busy, 0, __ATOMIC_RELEASE);
    }

    if (fut_restore_interrupts) {
        fut_restore_interrupts(irq_state);
    }
}

void fb_console_putc(char c) {
    struct fb_console_state *cons = &g_fb_console;

    if (!cons->initialized || cons->disabled) {
        return;
    }

    /* Strip ANSI/VT escape sequences. Without this the shell's color
     * codes ('\033[36m', '\033[1m', '\033[0m', etc.) print as literal
     * '?[36m' garbage all over the framebuffer. We don't render colors
     * yet — just consume the sequence and drop it on the floor.
     *
     *   Single-char escapes:   ESC X         (X in 0x40-0x5F except '[')
     *   CSI sequences:         ESC [ params final-byte (0x40-0x7E)
     *
     * Anything we don't recognize is consumed up through the final byte
     * to avoid leaking control bytes onto the screen. */
    if (cons->ansi == ANSI_ESC) {
        if ((unsigned char)c == '[') {
            cons->ansi = ANSI_CSI;
        } else {
            /* Single-char ESC sequence (or noise) — done */
            cons->ansi = ANSI_NORMAL;
        }
        return;
    }
    if (cons->ansi == ANSI_CSI) {
        /* CSI body consumes parameter bytes 0x20-0x3F until the final
         * byte 0x40-0x7E. */
        if ((unsigned char)c >= 0x40 && (unsigned char)c <= 0x7E) {
            cons->ansi = ANSI_NORMAL;
        }
        return;
    }
    if ((unsigned char)c == 0x1B) {  /* ESC */
        cons->ansi = ANSI_ESC;
        return;
    }
    if ((unsigned char)c == 0x07) {  /* BEL — just drop */
        return;
    }
    if ((unsigned char)c == 0x08) {  /* BS */
        if (cons->cursor_x > 0) cons->cursor_x--;
        return;
    }

    uint32_t fg_color = make_color(255, 255, 255, 255);
    uint32_t bg_color = make_color(0, 0, 0, 255);

    if (c == '\n') {
        cons->cursor_x = 0;
        cons->cursor_y++;
        if (cons->cursor_y >= cons->rows) {
            fb_console_scroll();
            cons->cursor_y = cons->rows - 1;
        }
        /* Throttle GPU flushes — flushing on every newline is too
         * aggressive (the boot log has ~100 lines, each flush sends
         * TRANSFER_TO_HOST_2D + RESOURCE_FLUSH and polls for both
         * with IRQs off; the device queue can't drain fast enough
         * and we hit '[virtio-gpu-mmio] Command timeout' and the
         * display freezes again). Flushing every 8 newlines cuts
         * GPU pressure ~8x while still keeping per-screen latency
         * sub-second at boot rates. The trailing data is still
         * visible because fb_console_putc on a column wrap also
         * presents (handles the shell prompt sitting on a partial
         * line at the bottom). */
        static unsigned int newlines_since_flush = 0;
        if (++newlines_since_flush >= 8) {
            newlines_since_flush = 0;
            fb_console_present();
        }
    } else if (c == '\r') {
        cons->cursor_x = 0;
    } else if (c == '\t') {
        cons->cursor_x += 4;
        if (cons->cursor_x >= cons->cols) {
            cons->cursor_x = 0;
            cons->cursor_y++;
            if (cons->cursor_y >= cons->rows) {
                fb_console_scroll();
                cons->cursor_y = cons->rows - 1;
            }
        }
    } else {
        fb_console_draw_char(cons->cursor_x, cons->cursor_y, c, fg_color, bg_color);
        cons->cursor_x++;
        if (cons->cursor_x >= cons->cols) {
            cons->cursor_x = 0;
            cons->cursor_y++;
            if (cons->cursor_y >= cons->rows) {
                fb_console_scroll();
                cons->cursor_y = cons->rows - 1;
            }
            /* Flush on wrap too — long lines without newlines (e.g.
             * shell prompt waiting for input on the same row) still
             * appear without depending on a trailing '\n'. */
            fb_console_present();
        }
    }
}

void fb_console_write(const char *str, size_t len) {
    for (size_t i = 0; i < len; i++) {
        fb_console_putc(str[i]);
    }
}

void fb_console_putc_at(int x, int y, char c) {
    struct fb_console_state *cons = &g_fb_console;

    if (!cons->initialized || x < 0 || x >= cons->cols || y < 0 || y >= cons->rows) {
        return;
    }

    uint32_t fg_color = make_color(255, 255, 255, 255);
    uint32_t bg_color = make_color(0, 0, 0, 255);
    fb_console_draw_char(x, y, c, fg_color, bg_color);
}

void fb_console_get_dimensions(int *width, int *height) {
    struct fb_console_state *cons = &g_fb_console;

    if (width) {
        *width = cons->initialized ? cons->cols : 0;
    }
    if (height) {
        *height = cons->initialized ? cons->rows : 0;
    }
}

void fb_console_disable(void) {
    g_fb_console.disabled = 1;
}
