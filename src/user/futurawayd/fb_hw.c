// SPDX-License-Identifier: MPL-2.0
/*
 * fb_hw.c - Futuraway hardware framebuffer backend
 *
 * Attempts to open the real kernel-provided framebuffer (/dev/fb0).
 * Falls back to the host-memory shim when the device is not present.
 */

#define _POSIX_C_SOURCE 200809L

#include "fb_hw.h"

#include <kernel/fb.h>

#include <errno.h>
#include <fcntl.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <unistd.h>

int fb_hw_open(struct fw_framebuffer *fb) {
    if (!fb) {
        return -EINVAL;
    }

    int fd = open("/dev/fb0", O_RDWR | O_CLOEXEC);
    if (fd < 0) {
        return -errno;
    }

    struct fut_fb_info info;
    if (ioctl(fd, FUT_FB_IOCTL_GET_INFO, &info) < 0) {
        int err = -errno;
        close(fd);
        return err;
    }

    if (info.width == 0u || info.height == 0u || info.pitch == 0u) {
        close(fd);
        return -EINVAL;
    }

    size_t size = (size_t)info.pitch * (size_t)info.height;
    void *pixels = mmap(NULL, size, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
    if (pixels == MAP_FAILED) {
        int err = -errno;
        close(fd);
        return err;
    }

    memset(fb, 0, sizeof(*fb));
    fb->width = info.width;
    fb->height = info.height;
    fb->stride_bytes = info.pitch;
    fb->pixels = (uint8_t *)pixels;
    fb->size_bytes = size;
    fb->hw_fd = fd;
    fb->is_hw = 1;
    return 0;
}

void fb_hw_close(struct fw_framebuffer *fb) {
    if (!fb || !fb->is_hw) {
        return;
    }
    if (fb->pixels && fb->size_bytes) {
        munmap(fb->pixels, fb->size_bytes);
    }
    if (fb->hw_fd >= 0) {
        close(fb->hw_fd);
    }
    memset(fb, 0, sizeof(*fb));
}
