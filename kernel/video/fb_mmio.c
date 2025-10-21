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
#include <kernel/video/cirrus_vga.h>
#include <kernel/video/virtio_gpu.h>
#include <platform/platform.h>

#include <stddef.h>
#include <stdint.h>
#include <stdbool.h>

/* PCI I/O port helpers for vendor detection */
static inline void outl(uint16_t port, uint32_t value) {
    __asm__ volatile("outl %0, %1" : : "a"(value), "Nd"(port));
}

static inline uint32_t inl(uint16_t port) {
    uint32_t result;
    __asm__ volatile("inl %1, %0" : "=a"(result) : "Nd"(port));
    return result;
}

static inline uint32_t pci_config_read_bdf(uint8_t bus, uint8_t slot, uint8_t func, uint8_t offset) {
    uint32_t addr = (1u << 31)
                  | ((uint32_t)bus << 16)
                  | ((uint32_t)slot << 11)
                  | ((uint32_t)func << 8)
                  | ((uint32_t)offset & 0xFC);
    outl(0xCF8, addr);
    return inl(0xCFC);
}

#ifdef __x86_64__
#include <arch/x86_64/paging.h>
#include <arch/x86_64/pmap.h>
#endif

static struct fut_fb_hwinfo g_fb_hw = {0};
static bool g_fb_available = false;
#ifdef __x86_64__
static volatile uint8_t *g_fb_virt = NULL;
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
    /* Attempt to initialize device-specific drivers if applicable */
    /* For virtio-gpu (vendor 0x1af4), initialize VIRTIO GPU device */
    /* For Cirrus (vendor 0x1013), run full VGA init sequence */

    /* Check device at slot 2 and slot 3 for graphics devices */
    uint32_t vdid_slot2 = pci_config_read_bdf(0, 2, 0, 0x00);
    uint16_t vendor_slot2 = (uint16_t)(vdid_slot2 & 0xFFFF);

    uint32_t vdid_slot3 = pci_config_read_bdf(0, 3, 0, 0x00);
    uint16_t vendor_slot3 = (uint16_t)(vdid_slot3 & 0xFFFF);

    if (vendor_slot3 == 0x1af4) {
        /* virtio-gpu detected at slot 3 - initialize VIRTIO GPU device */
        fut_printf("[FB] virtio-gpu detected at slot 3, initializing VIRTIO GPU\n");
        if (virtio_gpu_init(g_fb_hw.phys, g_fb_hw.info.width, g_fb_hw.info.height) == 0) {
            fut_printf("[FB] VIRTIO GPU initialized successfully\n");
            return;
        } else {
            fut_printf("[FB] VIRTIO GPU init failed, continuing with fallback\n");
        }
    } else if (vendor_slot2 == 0x1013) {
        /* Cirrus VGA detected at slot 2 - initialize properly */
        if (cirrus_vga_init() != 0) {
            fut_printf("[FB] Cirrus VGA init failed, skipping splash\n");
            return;
        }
    } else {
        fut_printf("[FB] Slot 2 vendor 0x%04x, Slot 3 vendor 0x%04x, proceeding\n",
                   vendor_slot2, vendor_slot3);
    }

    /* Try multiple addresses in order:
     * 1. Discovered BAR address (most reliable - what PCI config says)
     * 2. Standard QEMU Cirrus address (fallback)
     * 3. Legacy/fallback addresses
     */
    uint64_t addresses[] = { g_fb_hw.phys, 0xF0000000ULL, 0xE0000000ULL };
    uint64_t test_addr = 0;

    for (int attempt = 0; attempt < 3; attempt++) {
        test_addr = addresses[attempt];
        if (attempt == 0) {
            fut_printf("[FB] Primary attempt: standard QEMU address 0x%llx\n",
                       (unsigned long long)test_addr);
        } else {
            fut_printf("[FB] Fallback attempt %d: 0x%llx\n",
                       attempt,
                       (unsigned long long)test_addr);
        }

        uint64_t phys_base = PAGE_ALIGN_DOWN(test_addr);
        uint64_t offset = test_addr - phys_base;
        uint64_t fb_size = (size_t)g_fb_hw.info.pitch * (size_t)g_fb_hw.info.height;
        uint64_t map_size = fb_size + offset;
        uintptr_t virt_base = pmap_phys_to_virt(phys_base);

        fut_printf("[FB] Map attempt %d: phys=0x%llx size=0x%llx\n",
                   attempt + 1,
                   (unsigned long long)phys_base,
                   (unsigned long long)map_size);

        if (pmap_map((uint64_t)virt_base,
                     phys_base,
                     map_size,
                     PTE_KERNEL_RW | PTE_WRITE_THROUGH | PTE_CACHE_DISABLE) != 0) {
            fut_printf("[FB] Mapping failed\n");
            continue;
        }

        g_fb_virt = (volatile uint8_t *)(uintptr_t)(virt_base + offset);
        g_fb_hw.length = map_size;

        /* Write solid GREEN across entire framebuffer for diagnostic */
        volatile uint32_t *fb = (volatile uint32_t *)g_fb_virt;

        fut_printf("[FB] Filling entire screen with solid GREEN\n");

        /* Fill all pixels with pure green */
        size_t total_pixels = (g_fb_hw.info.width * g_fb_hw.info.height);
        for (size_t i = 0; i < total_pixels; ++i) {
            fb[i] = 0xFF00FF00;  /* Should be GREEN */
        }

        fut_printf("[FB] Screen fill complete\n");
        fut_printf("[FB] If entire screen is bright green, framebuffer is working!\n");
        return;
    }

    fut_printf("[FB] All mapping attempts failed\n");
}
