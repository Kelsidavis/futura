/* fb_host.h - Memory-backed framebuffer shim for futurawayd
 *
 * Copyright (c) 2025 Kelsi Davis
 * Licensed under the MPL v2.0 — see LICENSE for details.
 */

#pragma once

#include <stddef.h>
#include <stdint.h>

struct fw_framebuffer {
    uint32_t width;
    uint32_t height;
    uint32_t stride_bytes;
    uint8_t *pixels;
    size_t size_bytes;
    int hw_fd;
    int is_hw;
};

int fw_framebuffer_create(uint32_t width, uint32_t height, struct fw_framebuffer *fb_out);
void fw_framebuffer_destroy(struct fw_framebuffer *fb);
void fw_framebuffer_clear(struct fw_framebuffer *fb, uint32_t argb);
int fw_framebuffer_dump_ppm(const struct fw_framebuffer *fb, const char *path);
