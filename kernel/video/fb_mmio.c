// SPDX-License-Identifier: MPL-2.0
/*
 * fb_mmio.c - Linear framebuffer discovery via Multiboot2 or PCI
 *
 * Discovers and caches framebuffer geometry from Multiboot2 or via PCI VGA
 * device probing. Userland access is provided through /dev/fb0 character
 * device implemented in drivers/video/fb.c with full ioctl/mmap support.
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
#include <kernel/video/virtio_gpu_mmio.h>
#include <platform/platform.h>
#include <kernel/boot_logo.h>

#include <stddef.h>
#include <stdint.h>
#include <stdbool.h>

#ifdef __x86_64__
/* PCI configuration space I/O ports */
#define PCI_CONFIG_ADDRESS  0xCF8   /* PCI configuration address port */
#define PCI_CONFIG_DATA     0xCFC   /* PCI configuration data port */
#define PCI_CONFIG_ENABLE   (1u << 31)  /* Enable bit for config access */

/* PCI vendor IDs for graphics devices */
#define PCI_VENDOR_VIRTIO   0x1AF4  /* Red Hat / VirtIO */
#define PCI_VENDOR_CIRRUS   0x1013  /* Cirrus Logic */

/* Legacy framebuffer physical addresses (fallback when PCI discovery fails) */
#define FB_PHYS_QEMU_CIRRUS 0xF0000000ULL  /* Standard QEMU Cirrus address */
#define FB_PHYS_LEGACY      0xE0000000ULL  /* Legacy VGA address */
#define FB_PHYS_FALLBACK    0x4000000ULL   /* Safe position in RAM (64MB) */

/* Default framebuffer geometry */
#define FB_DEFAULT_WIDTH    1024
#define FB_DEFAULT_HEIGHT   768
#define FB_DEFAULT_BPP      32

/* ARGB color values */
#define ARGB_BLACK          0xFF000000

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
    uint32_t addr = PCI_CONFIG_ENABLE
                  | ((uint32_t)bus << 16)
                  | ((uint32_t)slot << 11)
                  | ((uint32_t)func << 8)
                  | ((uint32_t)offset & 0xFC);
    outl(PCI_CONFIG_ADDRESS, addr);
    return inl(PCI_CONFIG_DATA);
}
#endif

#ifdef __x86_64__
#include <platform/x86_64/memory/paging.h>
#include <platform/x86_64/memory/pmap.h>
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
        fut_printf("[FB] No multiboot info provided, skipping tag parsing and using fallback\n");
        goto fallback;
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

fallback:
    /* Fallback for boot loaders that did not supply a framebuffer tag.
     *
     * With direct kernel boot (-kernel flag), QEMU doesn't provide multiboot info.
     * We fall back to PCI discovery + hardcoded address.
     */
#if defined(WAYLAND_INTERACTIVE_MODE) || defined(__aarch64__)
    bool fb_fallback = true;
#ifdef WAYLAND_INTERACTIVE_MODE
    fut_printf("[FB] Auto-enabling fallback for interactive/direct boot (WAYLAND_INTERACTIVE_MODE=%d)\n",
               WAYLAND_INTERACTIVE_MODE);
#else
    fut_printf("[FB] Auto-enabling fallback for ARM64 direct boot\n");
#endif
#else
    /* Boot arguments may not be parsed yet when this runs. Direct kernel boot
     * (without a Multiboot framebuffer) therefore defaults to the fallback,
     * but users can opt-out later via the fb=0 boot flag. */
    bool fb_fallback = true;
#endif

    fut_printf("[FB] fb-fallback flag: %d\n", fb_fallback ? 1 : 0);
    if (!fb_fallback) {
        fut_printf("[FB] fallback disabled, returning\n");
        return -1;
    }
    fut_printf("[FB] enabling fallback geometry (fb-fallback=1)\n");

#ifdef __x86_64__
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
        /* Use FB_PHYS_FALLBACK (64MB) - safe position in physical RAM
         * Well within 128MB boot mapping, doesn't conflict with kernel/heap/processes */
        g_fb_hw.phys = FB_PHYS_FALLBACK;
        fut_printf("[FB] Using fallback address 0x%llx\n",
                   (unsigned long long)g_fb_hw.phys);
    }
#else
    /* ARM64: No PCI discovery yet, use fallback address */
    fut_printf("[FB] ARM64: skipping PCI VGA discovery, using fallback address\n");
    g_fb_hw.phys = FB_PHYS_FALLBACK;
    fut_printf("[FB] Using fallback address 0x%llx\n",
               (unsigned long long)g_fb_hw.phys);
#endif

    g_fb_hw.info.width = FB_DEFAULT_WIDTH;
    g_fb_hw.info.height = FB_DEFAULT_HEIGHT;
    g_fb_hw.info.pitch = g_fb_hw.info.width * (FB_DEFAULT_BPP / 8);
    g_fb_hw.info.bpp = FB_DEFAULT_BPP;
    g_fb_hw.info.flags = FB_FLAG_LINEAR;
    g_fb_available = true;
    fut_printf("[FB] using geometry %ux%ux%u phys=0x%llx\n",
               FB_DEFAULT_WIDTH, FB_DEFAULT_HEIGHT, FB_DEFAULT_BPP,
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

#ifdef __x86_64__
void *fb_get_virt_addr(void) {
    return (void *)g_fb_virt;
}
#endif

#ifdef __x86_64__
void fb_boot_splash(void) {
    /* Attempt to initialize device-specific drivers if applicable */
    /* For virtio-gpu (vendor 0x1af4), initialize VIRTIO GPU device */
    /* For Cirrus (vendor 0x1013), run full VGA init sequence */

    /* Check device at slot 2 and slot 3 for graphics devices */
    uint32_t vdid_slot2 = pci_config_read_bdf(0, 2, 0, 0x00);
    uint16_t vendor_slot2 = (uint16_t)(vdid_slot2 & 0xFFFF);

    uint32_t vdid_slot3 = pci_config_read_bdf(0, 3, 0, 0x00);
    uint16_t vendor_slot3 = (uint16_t)(vdid_slot3 & 0xFFFF);

    if (vendor_slot3 == PCI_VENDOR_VIRTIO) {
        /* virtio-gpu detected at slot 3 - initialize with BAR4 */
        fut_printf("[FB] virtio-gpu detected at slot 3, initializing with modern interface\n");
        uint64_t virtio_fb_phys = 0;
        if (virtio_gpu_init(&virtio_fb_phys, g_fb_hw.info.width, g_fb_hw.info.height) == 0) {
            fut_printf("[FB] VIRTIO GPU initialized successfully\n");
            /* Update the framebuffer address to the virtio guest framebuffer */
            g_fb_hw.phys = virtio_fb_phys;
            fut_printf("[FB] Updated framebuffer address to virtio guest FB: 0x%llx\n",
                       (unsigned long long)g_fb_hw.phys);

            /* Map the virtio guest framebuffer and write test pattern */
            uint64_t phys_base = PAGE_ALIGN_DOWN(virtio_fb_phys);
            uint64_t offset = virtio_fb_phys - phys_base;
            uint64_t fb_size = (size_t)g_fb_hw.info.pitch * (size_t)g_fb_hw.info.height;
            uint64_t map_size = fb_size + offset;
            uintptr_t virt_base = (uintptr_t)pmap_phys_to_virt(phys_base);

            fut_printf("[FB] Mapping virtio guest FB: phys=0x%llx size=0x%llx\n",
                       (unsigned long long)phys_base,
                       (unsigned long long)map_size);

            if (pmap_map((uint64_t)virt_base,
                         phys_base,
                         map_size,
                         PTE_KERNEL_RW | PTE_WRITE_THROUGH | PTE_CACHE_DISABLE) != 0) {
                fut_printf("[FB] Failed to map virtio guest framebuffer\n");
                return;
            }

            g_fb_virt = (volatile uint8_t *)(uintptr_t)(virt_base + offset);
            g_fb_hw.length = map_size;

            /* Initialize framebuffer with black screen - compositor will take over */
            volatile uint32_t *fb = (volatile uint32_t *)g_fb_virt;
            fut_printf("[FB] Clearing virtio framebuffer for compositor\n");

            /* Clear screen to black */
            for (uint32_t y = 0; y < g_fb_hw.info.height; ++y) {
                for (uint32_t x = 0; x < g_fb_hw.info.width; ++x) {
                    fb[y * g_fb_hw.info.width + x] = ARGB_BLACK;
                }
            }

            fut_printf("[FB] Framebuffer cleared, flushing display...\n");
            virtio_gpu_flush_display();
            fut_printf("[FB] Framebuffer ready for compositor\n");
            return;
        } else {
            fut_printf("[FB] VIRTIO GPU init failed, continuing with fallback\n");
        }
    } else if (vendor_slot2 == PCI_VENDOR_CIRRUS) {
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
    uint64_t addresses[] = { g_fb_hw.phys, FB_PHYS_QEMU_CIRRUS, FB_PHYS_LEGACY };
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
        uintptr_t virt_base = (uintptr_t)pmap_phys_to_virt(phys_base);

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
        g_fb_available = true;

        /* Green screen fill disabled - init will launch fbtest GUI instead */

        /* Initialize framebuffer console for text output */
        extern int fb_console_init(void);
        fb_console_init();
        fut_printf("[FB] Framebuffer console initialized\n");

        /* Display Futura banner on framebuffer */
        fut_printf("\n");
        fut_printf("-------------------------------\n");
        fut_printf("   ____     __                 \n");
        fut_printf("  / __/_ __/ /___ _________ _  \n");
        fut_printf(" / _// // / __/ // / __/ _ `/  \n");
        fut_printf("/_/  \\_,_/\\__\\_,_/_/  \\_,_/   \n");
        fut_printf("-------------------------------\n");
        fut_printf(" Futura OS\n");
        fut_printf("-------------------------------\n");
        fut_printf("\n");

        /* Draw Rory the Ouroboros logo from BMP in top-right corner */
        volatile uint32_t *fb = (volatile uint32_t *)g_fb_virt;
        uint32_t w = g_fb_hw.info.width;
        uint32_t h = g_fb_hw.info.height;

        /* Parse BMP header */
        const unsigned char *bmp = boot_bmp;
        uint32_t pixel_offset = bmp[10] | (bmp[11] << 8) | (bmp[12] << 16) | (bmp[13] << 24);
        uint32_t bmp_width = bmp[18] | (bmp[19] << 8) | (bmp[20] << 16) | (bmp[21] << 24);
        uint32_t bmp_height = bmp[22] | (bmp[23] << 8) | (bmp[24] << 16) | (bmp[25] << 24);
        uint16_t bpp = bmp[28] | (bmp[29] << 8);

        if (bpp != 24) {
            fut_printf("[FB] BMP logo must be 24-bit color\n");
            return;
        }

        /* Position in top-right corner with margin */
        int margin = 20;
        int logo_x = w - margin - bmp_width;
        int logo_y = margin;

        /* BMP rows are padded to 4-byte boundary */
        uint32_t row_size = ((bmp_width * 3 + 3) / 4) * 4;

        /* Render BMP (BMPs are stored bottom-to-top, BGR format) */
        for (uint32_t y = 0; y < bmp_height; y++) {
            for (uint32_t x = 0; x < bmp_width; x++) {
                /* BMP is bottom-to-top, so invert y */
                uint32_t bmp_y = bmp_height - 1 - y;
                uint32_t pixel_idx = pixel_offset + (bmp_y * row_size) + (x * 3);

                /* Read BGR pixel */
                uint8_t b = bmp[pixel_idx + 0];
                uint8_t g = bmp[pixel_idx + 1];
                uint8_t r = bmp[pixel_idx + 2];

                /* Skip transparent pixels (black background) */
                if (r == 0 && g == 0 && b == 0) {
                    continue;
                }

                /* Convert to ARGB */
                uint32_t color = 0xFF000000 | (r << 16) | (g << 8) | b;

                /* Write to framebuffer */
                int fb_x = logo_x + x;
                int fb_y = logo_y + y;
                if (fb_x >= 0 && fb_x < (int)w && fb_y >= 0 && fb_y < (int)h) {
                    fb[fb_y * w + fb_x] = color;
                }
            }
        }

        return;
    }

    fut_printf("[FB] All mapping attempts failed\n");
}
#else
/* ARM64 - virtio-mmio based graphics initialization */

/* Default framebuffer geometry for ARM64 */
#define FB_DEFAULT_WIDTH    1024
#define FB_DEFAULT_HEIGHT   768
#define FB_DEFAULT_BPP      32
#define FB_PHYS_FALLBACK    0x4000000ULL

void fb_boot_splash(void) {
    fut_printf("[FB] ARM64: Initializing framebuffer via virtio-gpu (MMIO)...\n");

    /* Try virtio-gpu MMIO driver */
    uint64_t fb_phys = 0;
    g_fb_hw.info.width = FB_DEFAULT_WIDTH;
    g_fb_hw.info.height = FB_DEFAULT_HEIGHT;
    g_fb_hw.info.pitch = g_fb_hw.info.width * (FB_DEFAULT_BPP / 8);
    g_fb_hw.info.bpp = FB_DEFAULT_BPP;
    g_fb_hw.info.flags = FB_FLAG_LINEAR;

    int rc = virtio_gpu_init_mmio(&fb_phys, g_fb_hw.info.width, g_fb_hw.info.height);

    if (rc == 0 && fb_phys != 0) {
        fut_printf("[FB] ARM64: virtio-gpu-mmio initialized, framebuffer at phys=0x%llx\n",
                   (unsigned long long)fb_phys);
        g_fb_hw.phys = fb_phys;
        g_fb_hw.length = (size_t)g_fb_hw.info.pitch * (size_t)g_fb_hw.info.height;
        g_fb_available = true;
        fut_printf("[FB] ARM64: Display ready (%ux%ux%u)\n",
                   g_fb_hw.info.width, g_fb_hw.info.height, g_fb_hw.info.bpp);
        return;
    }

    fut_printf("[FB] ARM64: virtio-gpu-mmio initialization failed (rc=%d), using fallback\n", rc);

    /* Fall back to hardcoded framebuffer address */
    g_fb_hw.phys = FB_PHYS_FALLBACK;
    g_fb_hw.length = (size_t)g_fb_hw.info.pitch * (size_t)g_fb_hw.info.height;
    g_fb_available = true;
    fut_printf("[FB] ARM64: Fallback framebuffer at phys=0x%llx (%ux%ux%u)\n",
               (unsigned long long)g_fb_hw.phys,
               FB_DEFAULT_WIDTH, FB_DEFAULT_HEIGHT, FB_DEFAULT_BPP);
}
#endif
