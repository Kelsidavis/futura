// SPDX-License-Identifier: MPL-2.0
/*
 * arm64_gfxtest - Minimal ARM64 graphics validation
 *
 * Tests framebuffer mmap and write access without ioctl dependencies.
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

/* Hardcoded framebuffer geometry (standard 1024x768x32) */
#define FB_WIDTH  1024
#define FB_HEIGHT 768
#define FB_BPP    32
#define FB_PITCH  (FB_WIDTH * (FB_BPP / 8))
#define FB_SIZE   (FB_PITCH * FB_HEIGHT)

int main(void) {
    /* Open /dev/fb0 */
    long fd = sys_open("/dev/fb0", O_RDWR, 0);
    if (fd < 0) {
        sys_exit(1);
    }

    /* Map framebuffer - kernel allocates virtual address */
    void *fb = (void *)sys_mmap(NULL, FB_SIZE, PROT_WRITE, MAP_SHARED, (int)fd, 0);
    if ((long)fb < 0 && (long)fb > -4096) {
        sys_close((int)fd);
        sys_exit(2);
    }

    /* Write test pattern: gradient fill */
    unsigned int *pixels = (unsigned int *)fb;
    for (unsigned int y = 0; y < FB_HEIGHT; y++) {
        for (unsigned int x = 0; x < FB_WIDTH; x++) {
            /* Create color gradient: R=x G=y B=128 */
            unsigned int r = (x * 255) / FB_WIDTH;
            unsigned int g = (y * 255) / FB_HEIGHT;
            unsigned int b = 128;
            pixels[y * FB_WIDTH + x] = (0xFF000000 | (r << 16) | (g << 8) | b);
        }
    }

    /* Success */
    sys_close((int)fd);
    sys_exit(0);
}
