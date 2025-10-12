// SPDX-License-Identifier: MPL-2.0
/*
 * fb_mmio.c - Linear framebuffer discovery via Multiboot2
 *
 * NOTE: This is a skeleton implementation. We parse the multiboot tag
 * for the framebuffer and cache its geometry, but userland plumbing
 * (ioctl/mmap/device nodes) is still a TODO.
 */

#include <kernel/fb.h>
#include <stddef.h>
#include <stdint.h>

struct fut_fb_state {
    struct fut_fb_info info;
    int available;
};

static struct fut_fb_state g_fb_state = {0};

/* Multiboot2 tag IDs */
#define MB2_TAG_FRAMEBUFFER 8

struct multiboot_tag {
    uint32_t type;
    uint32_t size;
};

struct multiboot_tag_framebuffer {
    uint32_t type;
    uint32_t size;
    uint64_t framebuffer_addr;
    uint32_t framebuffer_pitch;
    uint32_t framebuffer_width;
    uint32_t framebuffer_height;
    uint8_t framebuffer_bpp;
    uint8_t framebuffer_type;
    uint16_t reserved;
};

static const void *mb2_next_tag(const struct multiboot_tag *tag) {
    uintptr_t addr = (uintptr_t)tag;
    addr += (tag->size + 7u) & ~7u;
    return (const void *)addr;
}

int fb_probe_from_multiboot(const void *mb_info) {
    if (!mb_info) {
        return -1;
    }

    const struct multiboot_tag *tag =
        (const struct multiboot_tag *)((const uint8_t *)mb_info + 8);

    while (tag && tag->type != 0) {
        if (tag->type == MB2_TAG_FRAMEBUFFER &&
            tag->size >= sizeof(struct multiboot_tag_framebuffer)) {
            const struct multiboot_tag_framebuffer *fbtag =
                (const struct multiboot_tag_framebuffer *)tag;

            g_fb_state.info.phys = fbtag->framebuffer_addr;
            g_fb_state.info.width = fbtag->framebuffer_width;
            g_fb_state.info.height = fbtag->framebuffer_height;
            g_fb_state.info.pitch = fbtag->framebuffer_pitch;
            g_fb_state.info.bpp = fbtag->framebuffer_bpp;
            g_fb_state.available = 1;
            return 0;
        }

        tag = (const struct multiboot_tag *)mb2_next_tag(tag);
    }

    return -1;
}

int fb_get_info(struct fut_fb_info *out) {
    if (!out || !g_fb_state.available) {
        return -1;
    }
    *out = g_fb_state.info;
    return 0;
}
