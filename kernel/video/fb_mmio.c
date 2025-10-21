// SPDX-License-Identifier: MPL-2.0
/*
 * fb_mmio.c - Linear framebuffer discovery via Multiboot2 or PCI
 *
 * NOTE: This is a skeleton implementation. We parse the multiboot tag
 * for the framebuffer and cache its geometry, but userland plumbing
 * (ioctl/mmap/device nodes) is still a TODO.
 *
 * Probe strategy:
 * 1. Try Multiboot2 framebuffer tag
 * 2. Fall back to PCI VGA device discovery
 * 3. Use hardcoded fallback if both fail
 */

#include <kernel/fb.h>
#include <kernel/boot_args.h>
#include <kernel/video/pci_vga.h>
#include <platform/platform.h>

#include <stddef.h>
#include <stdint.h>
#include <stdbool.h>

#ifdef __x86_64__
#include <arch/x86_64/paging.h>
#include <arch/x86_64/pmap.h>
#endif

static struct fut_fb_hwinfo g_fb_hw = {0};
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
    if (!g_fb_available || g_fb_hw.info.bpp != 32u || g_fb_splash_drawn) {
        return;
    }

    size_t fb_size = (size_t)g_fb_hw.info.pitch * (size_t)g_fb_hw.info.height;
    if (fb_size == 0 || !g_fb_hw.phys) {
        return;
    }

    if (!g_fb_virt) {
        uint64_t phys_base = PAGE_ALIGN_DOWN(g_fb_hw.phys);
        uint64_t offset = g_fb_hw.phys - phys_base;
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
        g_fb_hw.length = map_size;
    }

    volatile uint8_t *fb = g_fb_virt;
    uint32_t stride = g_fb_hw.info.pitch;
    for (uint32_t y = 0; y < g_fb_hw.info.height; ++y) {
        volatile uint32_t *row = (volatile uint32_t *)(fb + (size_t)y * stride);
        for (uint32_t x = 0; x < g_fb_hw.info.width; ++x) {
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
    fut_printf("[FB] fb_probe_from_multiboot called, mb_info=%p\n", mb_info);
    if (!mb_info) {
        fut_printf("[FB] No multiboot info provided, checking if QEMU is providing it anyway\n");
        /* Even with mb_info NULL, the bootloader might have set up memory-based structures */
    }

    const struct multiboot_tag *tag =
        (const struct multiboot_tag *)((const uint8_t *)mb_info + 8);

    int tag_count = 0;
    while (tag && tag->type != 0) {
        tag_count++;
        fut_printf("[FB] tag #%d: type=%u size=%u\n",
                   tag_count, (unsigned)tag->type, (unsigned)tag->size);
        if (tag->type == MB2_TAG_FRAMEBUFFER &&
            tag->size >= sizeof(struct multiboot_tag_framebuffer)) {
            const struct multiboot_tag_framebuffer *fbtag =
                (const struct multiboot_tag_framebuffer *)tag;

            fut_printf("[FB] fb tag found: addr=0x%llx %ux%u bpp=%u pitch=%u type=%u\n",
                       (unsigned long long)fbtag->framebuffer_addr,
                       fbtag->framebuffer_width,
                       fbtag->framebuffer_height,
                       fbtag->framebuffer_bpp,
                       fbtag->framebuffer_pitch,
                       (unsigned)fbtag->framebuffer_type);
            g_fb_hw.phys = fbtag->framebuffer_addr;
            g_fb_hw.info.width = fbtag->framebuffer_width;
            g_fb_hw.info.height = fbtag->framebuffer_height;
            g_fb_hw.info.pitch = fbtag->framebuffer_pitch;
            g_fb_hw.info.bpp = fbtag->framebuffer_bpp;
            g_fb_hw.info.flags = FB_FLAG_LINEAR;
            g_fb_available = true;
            return 0;
        }

        tag = (const struct multiboot_tag *)mb2_next_tag(tag);
    }
    fut_printf("[FB] parsed %d tags, no framebuffer tag found\n", tag_count);

    /* Fallback for boot loaders that did not supply a framebuffer tag.
     *
     * With direct kernel boot (-kernel flag), QEMU doesn't provide multiboot info.
     * We fall back to PCI discovery + hardcoded address.
     */
#ifdef WAYLAND_INTERACTIVE_MODE
    /* When interactive mode (headful) is enabled at compile time,
     * always enable framebuffer fallback with PCI discovery since:
     * 1. Direct kernel boot doesn't provide multiboot info
     * 2. Command line args aren't available in multiboot structure */
    bool fb_fallback = true;
    fut_printf("[FB] Auto-enabling fallback for headful mode (WAYLAND_INTERACTIVE_MODE=%d)\n",
               WAYLAND_INTERACTIVE_MODE);
#else
    bool fb_fallback = fut_boot_arg_flag("fb-fallback");
#endif

    fut_printf("[FB] fb-fallback flag: %d\n", fb_fallback ? 1 : 0);
    if (!fb_fallback) {
        fut_printf("[FB] fallback disabled, returning\n");
        return -1;
    }
    fut_printf("[FB] enabling fallback geometry (fb-fallback=1)\n");

    /* Try to discover VGA device via PCI */
    fut_printf("[FB] Attempting PCI VGA device discovery...\n");
    uint64_t pci_framebuffer = pci_find_vga_framebuffer();

    if (pci_framebuffer != 0) {
        /* Successfully discovered via PCI */
        g_fb_hw.phys = pci_framebuffer;
        fut_printf("[FB] Using PCI-discovered framebuffer at 0x%llx\n",
                   (unsigned long long)g_fb_hw.phys);
    } else {
        /* Fall back to safe address in RAM */
        fut_printf("[FB] PCI discovery failed, using hardcoded fallback address\n");
        /* Use 0x4000000 (64MB) - safe position in physical RAM
         * Well within 128MB boot mapping, doesn't conflict with kernel/heap/processes */
        g_fb_hw.phys = 0x4000000ULL;
        fut_printf("[FB] Using fallback address 0x%llx\n",
                   (unsigned long long)g_fb_hw.phys);
    }

    g_fb_hw.info.width = 1024;
    g_fb_hw.info.height = 768;
    g_fb_hw.info.pitch = g_fb_hw.info.width * 4u;
    g_fb_hw.info.bpp = 32;
    g_fb_hw.info.flags = FB_FLAG_LINEAR;
    g_fb_available = true;
    fut_printf("[FB] using geometry 1024x768x32 phys=0x%llx\n",
               (unsigned long long)g_fb_hw.phys);
    return 0;
}

int fb_get_info(struct fut_fb_hwinfo *out) {
    if (!out || !g_fb_available) {
        return -1;
    }
    *out = g_fb_hw;
    return 0;
}

bool fb_is_available(void) {
    return g_fb_available;
}

void fb_boot_splash(void) {
    /* NOTE: Framebuffer rendering disabled pending driver implementation.
     * Direct linear framebuffer writes don't work with QEMU's VGA devices
     * (cirrus, bochs, vmware, std). Devices either:
     * - Don't provide a real linear framebuffer (need protocol/MMIO registers)
     * - Report wrong BAR addresses
     * - Require driver initialization before framebuffer is accessible
     *
     * Solution: Implement proper VGA/Cirrus driver with device init,
     * or switch to virtio-gpu which has better driver support.
     */
    /* fb_splash_fill(0xFF20252Eu); */
}
