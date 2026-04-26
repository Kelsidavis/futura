/* fb_host.c - Memory-backed framebuffer shim for futurawayd
 *
 * Copyright (c) 2025 Kelsi Davis
 * Licensed under the MPL v2.0 — see LICENSE for details.
 */

#define _POSIX_C_SOURCE 200809L

#include "fb_host.h"

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int fw_framebuffer_create(uint32_t width, uint32_t height, struct fw_framebuffer *fb_out) {
    if (!fb_out || width == 0 || height == 0) {
        return -EINVAL;
    }

    memset(fb_out, 0, sizeof(*fb_out));

    /* Overflow-safe pixel buffer sizing. Without these checks,
     * width >= 2^30 wraps stride to 0 and the eventual calloc(1, 0)
     * gives a near-empty allocation — subsequent indexing using the
     * un-wrapped width/height (e.g. in fw_framebuffer_clear) walks
     * past the heap allocation. We additionally cap to a 16K x 16K
     * sanity limit which is well past any real display. */
    if (width > 16384u || height > 16384u) {
        return -EINVAL;
    }
    size_t stride;
    if (__builtin_mul_overflow((size_t)width, (size_t)4u, &stride)) {
        return -EOVERFLOW;
    }
    size_t total;
    if (__builtin_mul_overflow(stride, (size_t)height, &total)) {
        return -EOVERFLOW;
    }
    uint8_t *pixels = (uint8_t *)calloc(1, total);
    if (!pixels) {
        return -ENOMEM;
    }

    fb_out->width = width;
    fb_out->height = height;
    fb_out->stride_bytes = (uint32_t)stride;
    fb_out->pixels = pixels;
    fb_out->size_bytes = total;
    fb_out->hw_fd = -1;
    fb_out->is_hw = 0;
    return 0;
}

void fw_framebuffer_destroy(struct fw_framebuffer *fb) {
    if (!fb) {
        return;
    }
    if (!fb->is_hw) {
        free(fb->pixels);
    }
    memset(fb, 0, sizeof(*fb));
}

void fw_framebuffer_clear(struct fw_framebuffer *fb, uint32_t argb) {
    if (!fb || !fb->pixels) {
        return;
    }
    uint32_t *dst = (uint32_t *)fb->pixels;
    size_t count = ((size_t)fb->stride_bytes / sizeof(uint32_t)) * (size_t)fb->height;
    for (size_t i = 0; i < count; ++i) {
        dst[i] = argb;
    }
}

static int write_ppm(FILE *file, const struct fw_framebuffer *fb) {
    if (fprintf(file, "P6\n%u %u\n255\n", fb->width, fb->height) < 0) {
        return -EIO;
    }

    const uint32_t *src = (const uint32_t *)fb->pixels;
    for (uint32_t y = 0; y < fb->height; ++y) {
        for (uint32_t x = 0; x < fb->width; ++x) {
            uint32_t argb = src[(size_t)y * (fb->stride_bytes / 4u) + x];
            uint8_t rgb[3] = {
                (uint8_t)((argb >> 16) & 0xFFu),
                (uint8_t)((argb >> 8) & 0xFFu),
                (uint8_t)(argb & 0xFFu)
            };
            if (fwrite(rgb, sizeof(rgb), 1, file) != 1) {
                return -EIO;
            }
        }
    }
    return 0;
}

int fw_framebuffer_dump_ppm(const struct fw_framebuffer *fb, const char *path) {
    if (!fb || !fb->pixels || !path) {
        return -EINVAL;
    }

    FILE *file = fopen(path, "wb");
    if (!file) {
        return -errno;
    }

    int rc = write_ppm(file, fb);
    if (fclose(file) != 0) {
        rc = -errno;
    }
    return rc;
}
