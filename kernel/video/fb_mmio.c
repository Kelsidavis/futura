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
#include <stdbool.h>
#ifdef __x86_64__
#include <arch/x86_64/paging.h>
#include <arch/x86_64/pmap.h>
#endif
#include <platform/platform.h>

static struct fut_fb_info g_fb_info = {0};
static bool g_fb_available = false;
#ifdef __x86_64__
static volatile uint8_t *g_fb_virt = NULL;
static bool g_fb_splash_drawn = false;
#endif

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

static void fb_splash_fill(uint32_t color) {
#if defined(__x86_64__)
    if (!g_fb_available || g_fb_info.bpp != 32u || g_fb_splash_drawn) {
        return;
    }

    size_t fb_size = (size_t)g_fb_info.pitch * (size_t)g_fb_info.height;
    if (fb_size == 0) {
        return;
    }

    if (!g_fb_virt) {
        uint64_t phys_base = PAGE_ALIGN_DOWN(g_fb_info.phys);
        uint64_t offset = g_fb_info.phys - phys_base;
        uint64_t map_size = fb_size + offset;
        uintptr_t virt_base = pmap_phys_to_virt(phys_base);

        if (pmap_map((uint64_t)virt_base,
                     phys_base,
                     map_size,
                     PTE_KERNEL_RW | PTE_WRITE_THROUGH | PTE_CACHE_DISABLE) != 0) {
            fut_printf("[FB] map_range failed (phys=0x%llx size=0x%llx)\n",
                       (unsigned long long)phys_base,
                       (unsigned long long)map_size);
            return;
        }
        g_fb_virt = (volatile uint8_t *)(uintptr_t)(virt_base + offset);
    }

    volatile uint8_t *fb = g_fb_virt;
    uint32_t stride = g_fb_info.pitch;
    for (uint32_t y = 0; y < g_fb_info.height; ++y) {
        volatile uint32_t *row = (volatile uint32_t *)(fb + (size_t)y * stride);
        for (uint32_t x = 0; x < g_fb_info.width; ++x) {
            row[x] = color;
        }
    }
    g_fb_splash_drawn = true;
#else
    (void)color;
#endif
}

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

            g_fb_info.phys = fbtag->framebuffer_addr;
            g_fb_info.width = fbtag->framebuffer_width;
            g_fb_info.height = fbtag->framebuffer_height;
            g_fb_info.pitch = fbtag->framebuffer_pitch;
            g_fb_info.bpp = fbtag->framebuffer_bpp;
            g_fb_available = true;
            return 0;
        }

        tag = (const struct multiboot_tag *)mb2_next_tag(tag);
    }

    return -1;
}

int fb_get_info(struct fut_fb_info *out) {
    if (!out || !g_fb_available) {
        return -1;
    }
    *out = g_fb_info;
    return 0;
}

void fb_boot_splash(void) {
    fb_splash_fill(0xFF20252Eu);
}
