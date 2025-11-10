// SPDX-License-Identifier: MPL-2.0
/*
 * arm64_uidemo - ARM64 UI capabilities demonstration
 *
 * Demonstrates advanced framebuffer rendering:
 * - Filled rectangles with multiple colors
 * - Checkerboard pattern
 * - Border drawing
 * - Color gradients in regions
 *
 * Uses hardcoded 1024x768x32 framebuffer parameters.
 */

#include <user/sys.h>

/* Syscall numbers */
#define SYS_write 1
#define SYS_open 2
#define SYS_close 3
#define SYS_mmap 9
#define SYS_exit 60

/* File flags */
#define O_RDWR 0x0002

/* mmap flags */
#define PROT_READ  0x1
#define PROT_WRITE 0x2
#define MAP_SHARED 0x1

/* Framebuffer geometry */
#define FB_WIDTH  1024
#define FB_HEIGHT 768
#define FB_BPP    32
#define FB_PITCH  (FB_WIDTH * (FB_BPP / 8))
#define FB_SIZE   (FB_PITCH * FB_HEIGHT)

/* Color definitions (ARGB format) */
#define COLOR_BLACK   0xFF000000
#define COLOR_WHITE   0xFFFFFFFF
#define COLOR_RED     0xFFFF0000
#define COLOR_GREEN   0xFF00FF00
#define COLOR_BLUE    0xFF0000FF
#define COLOR_YELLOW  0xFFFFFF00
#define COLOR_CYAN    0xFF00FFFF
#define COLOR_MAGENTA 0xFFFF00FF
#define COLOR_GRAY    0xFF808080
#define COLOR_ORANGE  0xFFFF8800

/* Helper to set a pixel */
static inline void set_pixel(unsigned int *fb, unsigned int x, unsigned int y, unsigned int color) {
    if (x < FB_WIDTH && y < FB_HEIGHT) {
        fb[y * FB_WIDTH + x] = color;
    }
}

/* Draw a filled rectangle */
static void draw_rect(unsigned int *fb, unsigned int x, unsigned int y,
                      unsigned int w, unsigned int h, unsigned int color) {
    for (unsigned int dy = 0; dy < h; dy++) {
        for (unsigned int dx = 0; dx < w; dx++) {
            set_pixel(fb, x + dx, y + dy, color);
        }
    }
}

/* Draw a horizontal line */
static void draw_hline(unsigned int *fb, unsigned int x, unsigned int y,
                       unsigned int w, unsigned int color) {
    for (unsigned int dx = 0; dx < w; dx++) {
        set_pixel(fb, x + dx, y, color);
    }
}

/* Draw a vertical line */
static void draw_vline(unsigned int *fb, unsigned int x, unsigned int y,
                       unsigned int h, unsigned int color) {
    for (unsigned int dy = 0; dy < h; dy++) {
        set_pixel(fb, x, y + dy, color);
    }
}

/* Draw a rectangle outline */
static void draw_border(unsigned int *fb, unsigned int x, unsigned int y,
                        unsigned int w, unsigned int h, unsigned int thickness,
                        unsigned int color) {
    /* Top and bottom borders */
    for (unsigned int t = 0; t < thickness; t++) {
        draw_hline(fb, x, y + t, w, color);
        draw_hline(fb, x, y + h - 1 - t, w, color);
    }
    /* Left and right borders */
    for (unsigned int t = 0; t < thickness; t++) {
        draw_vline(fb, x + t, y, h, color);
        draw_vline(fb, x + w - 1 - t, y, h, color);
    }
}

/* Draw a checkerboard pattern */
static void draw_checkerboard(unsigned int *fb, unsigned int x, unsigned int y,
                              unsigned int w, unsigned int h, unsigned int square_size,
                              unsigned int color1, unsigned int color2) {
    for (unsigned int dy = 0; dy < h; dy++) {
        for (unsigned int dx = 0; dx < w; dx++) {
            unsigned int square_x = dx / square_size;
            unsigned int square_y = dy / square_size;
            unsigned int color = ((square_x + square_y) % 2 == 0) ? color1 : color2;
            set_pixel(fb, x + dx, y + dy, color);
        }
    }
}

/* Draw a gradient rectangle (horizontal) */
static void draw_gradient_h(unsigned int *fb, unsigned int x, unsigned int y,
                            unsigned int w, unsigned int h,
                            unsigned int color_start, unsigned int color_end) {
    for (unsigned int dy = 0; dy < h; dy++) {
        for (unsigned int dx = 0; dx < w; dx++) {
            /* Interpolate between start and end colors */
            unsigned int r1 = (color_start >> 16) & 0xFF;
            unsigned int g1 = (color_start >> 8) & 0xFF;
            unsigned int b1 = color_start & 0xFF;

            unsigned int r2 = (color_end >> 16) & 0xFF;
            unsigned int g2 = (color_end >> 8) & 0xFF;
            unsigned int b2 = color_end & 0xFF;

            unsigned int r = r1 + ((r2 - r1) * dx) / w;
            unsigned int g = g1 + ((g2 - g1) * dx) / w;
            unsigned int b = b1 + ((b2 - b1) * dx) / w;

            unsigned int color = 0xFF000000 | (r << 16) | (g << 8) | b;
            set_pixel(fb, x + dx, y + dy, color);
        }
    }
}

int main(void) {
    /* Open /dev/fb0 */
    long fd = sys_open("/dev/fb0", O_RDWR, 0);
    if (fd < 0) {
        sys_exit(1);
    }

    /* Map framebuffer */
    void *fb = (void *)sys_mmap(NULL, FB_SIZE, PROT_WRITE, MAP_SHARED, (int)fd, 0);
    if ((long)fb < 0 && (long)fb > -4096) {
        sys_close((int)fd);
        sys_exit(2);
    }

    unsigned int *pixels = (unsigned int *)fb;

    /* Clear to dark gray background */
    draw_rect(pixels, 0, 0, FB_WIDTH, FB_HEIGHT, 0xFF202020);

    /* Draw title bar */
    draw_rect(pixels, 0, 0, FB_WIDTH, 40, COLOR_BLUE);
    draw_border(pixels, 0, 0, FB_WIDTH, 40, 2, COLOR_CYAN);

    /* Draw some colored panels */
    unsigned int panel_w = 200;
    unsigned int panel_h = 150;
    unsigned int margin = 20;
    unsigned int start_y = 60;

    /* Row 1: Primary colors */
    draw_rect(pixels, margin, start_y, panel_w, panel_h, COLOR_RED);
    draw_border(pixels, margin, start_y, panel_w, panel_h, 3, COLOR_WHITE);

    draw_rect(pixels, margin + panel_w + 20, start_y, panel_w, panel_h, COLOR_GREEN);
    draw_border(pixels, margin + panel_w + 20, start_y, panel_w, panel_h, 3, COLOR_WHITE);

    draw_rect(pixels, margin + 2*(panel_w + 20), start_y, panel_w, panel_h, COLOR_BLUE);
    draw_border(pixels, margin + 2*(panel_w + 20), start_y, panel_w, panel_h, 3, COLOR_WHITE);

    draw_rect(pixels, margin + 3*(panel_w + 20), start_y, panel_w, panel_h, COLOR_YELLOW);
    draw_border(pixels, margin + 3*(panel_w + 20), start_y, panel_w, panel_h, 3, COLOR_WHITE);

    /* Row 2: Secondary colors */
    start_y += panel_h + 20;

    draw_rect(pixels, margin, start_y, panel_w, panel_h, COLOR_CYAN);
    draw_border(pixels, margin, start_y, panel_w, panel_h, 3, COLOR_BLACK);

    draw_rect(pixels, margin + panel_w + 20, start_y, panel_w, panel_h, COLOR_MAGENTA);
    draw_border(pixels, margin + panel_w + 20, start_y, panel_w, panel_h, 3, COLOR_BLACK);

    draw_rect(pixels, margin + 2*(panel_w + 20), start_y, panel_w, panel_h, COLOR_ORANGE);
    draw_border(pixels, margin + 2*(panel_w + 20), start_y, panel_w, panel_h, 3, COLOR_BLACK);

    draw_rect(pixels, margin + 3*(panel_w + 20), start_y, panel_w, panel_h, COLOR_WHITE);
    draw_border(pixels, margin + 3*(panel_w + 20), start_y, panel_w, panel_h, 3, COLOR_BLACK);

    /* Row 3: Patterns */
    start_y += panel_h + 20;

    /* Checkerboard pattern */
    draw_checkerboard(pixels, margin, start_y, panel_w, panel_h, 20,
                      COLOR_BLACK, COLOR_WHITE);
    draw_border(pixels, margin, start_y, panel_w, panel_h, 3, COLOR_RED);

    /* Gradient */
    draw_gradient_h(pixels, margin + panel_w + 20, start_y, panel_w, panel_h,
                    COLOR_BLUE, COLOR_RED);
    draw_border(pixels, margin + panel_w + 20, start_y, panel_w, panel_h, 3, COLOR_WHITE);

    /* Another gradient */
    draw_gradient_h(pixels, margin + 2*(panel_w + 20), start_y, panel_w, panel_h,
                    COLOR_GREEN, COLOR_YELLOW);
    draw_border(pixels, margin + 2*(panel_w + 20), start_y, panel_w, panel_h, 3, COLOR_BLACK);

    /* Fine checkerboard */
    draw_checkerboard(pixels, margin + 3*(panel_w + 20), start_y, panel_w, panel_h, 8,
                      COLOR_BLUE, COLOR_CYAN);
    draw_border(pixels, margin + 3*(panel_w + 20), start_y, panel_w, panel_h, 3, COLOR_YELLOW);

    /* Bottom status bar */
    draw_rect(pixels, 0, FB_HEIGHT - 30, FB_WIDTH, 30, 0xFF404040);
    draw_border(pixels, 0, FB_HEIGHT - 30, FB_WIDTH, 30, 2, COLOR_GRAY);

    /* Success */
    sys_close((int)fd);
    sys_exit(0);
}
