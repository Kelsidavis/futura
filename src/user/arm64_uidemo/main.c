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
#define COLOR_WHITE   0xFFFFFFFF

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

    /* Fill entire screen with bright WHITE
     * Yield periodically to share CPU in cooperative scheduler */
    for (unsigned int i = 0; i < (FB_WIDTH * FB_HEIGHT); i++) {
        pixels[i] = 0xFFFFFFFF;

        /* Yield every 10,000 pixels to allow other processes to run */
        if ((i % 10000) == 0 && i > 0) {
            sys_sched_yield();
        }
    }

    /* Flush framebuffer to display via ioctl */
    #define FBIOFLUSH 0x4603
    sys_ioctl((int)fd, FBIOFLUSH, 0);

    /* Success */
    sys_close((int)fd);
    sys_exit(0);
}
