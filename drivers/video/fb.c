// SPDX-License-Identifier: MPL-2.0
/*
 * fb.c - Minimal /dev/fb0 character device
 */

#include <kernel/chrdev.h>
#include <kernel/devfs.h>
#include <kernel/uaccess.h>
#include <kernel/errno.h>
#include <kernel/fb.h>
#include <kernel/fb_console.h>
#include <kernel/fut_mm.h>
#include <platform/platform.h>
#include <futura/fb_ioctl.h>

#ifdef __x86_64__
#include <platform/x86_64/memory/pmap.h>
#include <platform/x86_64/memory/pat.h>
#elif defined(__aarch64__)
#include <platform/arm64/memory/pmap.h>
#endif

#include <stddef.h>
#include <stdint.h>

#define FB_MAJOR 29u
#define FB_MINOR 0u

#ifdef DEBUG_FB
#define FB_DBG(fmt, ...) fut_printf("[FB] " fmt, ##__VA_ARGS__)
#else
#define FB_DBG(fmt, ...) do { (void)sizeof(fmt); } while (0)
#endif

struct fb_device {
    struct fut_fb_hwinfo hw;
    void *kva;
    uint32_t vsync_ms;
    uint32_t open_count;
    int mapped;
};

static struct fb_device g_fb_dev = {0};

static int fb_ensure_mapped(struct fb_device *fb) {
    if (fb->mapped) {
        return 0;
    }

    uintptr_t phys_base = PAGE_ALIGN_DOWN(fb->hw.phys);
    uintptr_t virt_base = (uintptr_t)pmap_phys_to_virt(phys_base);
    size_t offset = (size_t)(fb->hw.phys - phys_base);
    size_t length = fb->hw.info.pitch * fb->hw.info.height + offset;
    length = PAGE_ALIGN_UP(length);

#ifdef __x86_64__
    uint64_t flags = PTE_PRESENT | PTE_WRITABLE | pat_choose_page_attr_wc();
    int rc = pmap_map(virt_base,
                      phys_base,
                      length,
                      flags);
    if (rc != 0) {
        return rc;
    }
#else
    /* ARM64: Framebuffer is in RAM with identity mapping, pmap_phys_to_virt already
     * gives us valid kernel VA. Don't call pmap_map for RAM regions. */
#endif

    fb->kva = (void *)(virt_base + offset);
    fb->hw.length = length;
    fb->mapped = 1;
    FB_DBG("mapped phys=0x%llx len=%zu -> kva=%p\n",
           (unsigned long long)fb->hw.phys, length, fb->kva);
    return 0;
}

static int fb_open(void *inode, int flags, void **private_data) {
    (void)flags;
    struct fb_device *fb = (struct fb_device *)inode;
    if (!fb) {
        return -ENODEV;
    }
    fb->open_count++;
    FB_DBG("fb_open: count=%u\n", fb->open_count);

    /* Disable kernel console when GUI takes over framebuffer */
    if (fb->open_count == 1) {
        fb_console_disable();
    }

    if (private_data) {
        *private_data = fb;
    }
    return 0;
}

static int fb_ioctl(void *inode, void *private_data,
                    unsigned long req, unsigned long arg) {
    struct fb_device *fb = private_data ? (struct fb_device *)private_data
                                        : (struct fb_device *)inode;
    if (!fb) {
        return -ENODEV;
    }

    switch (req) {
    case FBIOGET_INFO: {
        struct fut_fb_info info = fb->hw.info;
        return fut_copy_to_user((void *)arg, &info, sizeof(info));
    }
    case FBIOSET_VSYNC_MS: {
        uint32_t value = 0;
        int rc = fut_copy_from_user(&value, (const void *)arg, sizeof(value));
        if (rc != 0) {
            return rc;
        }
        fb->vsync_ms = value;
        return 0;
    }
    case FBIOFLUSH: {

#ifdef __aarch64__
        /* ARM64: Flush CPU cache for framebuffer region to ensure GPU sees writes */
        /* Ensure kernel has framebuffer mapped */
        int rc = fb_ensure_mapped(fb);
        fut_printf("[FB-CHAR] fb_ensure_mapped returned: %d (kva=%p)\n", rc, fb->kva);

        if (rc == 0 && fb->kva && fb->hw.length > 0) {
            uint64_t fb_ptr = (uint64_t)fb->kva;
            uint64_t fb_size = fb->hw.length;

            fut_printf("[FB-CHAR] Flushing cache for kernel FB at 0x%llx size=%llu bytes\n",
                       (unsigned long long)fb_ptr, (unsigned long long)fb_size);

            /* Clean AND invalidate D-cache for framebuffer memory (dc civac by VA)
             * This is necessary because user-space may have cached the same physical
             * memory under a different virtual address. We need both clean (flush to RAM)
             * and invalidate (remove from cache) to ensure GPU sees fresh data. */
            for (uint64_t addr = fb_ptr; addr < fb_ptr + fb_size; addr += 64) {
                __asm__ volatile("dc civac, %0" : : "r"(addr));
            }
            __asm__ volatile("dsb sy" ::: "memory");  /* Data sync barrier */
            fut_printf("[FB-CHAR] ✓ Cache flush complete (cleaned and invalidated)\n");

            /* Diagnostic: Read back first and last pixels to verify they were written */
            if (fb->kva) {
                uint32_t *fb_pixels = (uint32_t *)fb->kva;
                uint32_t first_pixel = fb_pixels[0];
                uint32_t last_pixel = fb_pixels[(1024 * 768) - 1];
                fut_printf("[FB-CHAR] Framebuffer content check: first=0x%x last=0x%x (expect 0xFFFFFFFF for white)\n",
                           (unsigned int)first_pixel, (unsigned int)last_pixel);
            }
        } else {
            fut_printf("[FB-CHAR] WARNING: Could not map framebuffer for cache flush (rc=%d kva=%p)\n", rc, fb->kva);
            /* Still issue DSB as a fallback */
            __asm__ volatile("dsb sy" ::: "memory");
        }
#endif

        extern void virtio_gpu_flush_display(void);
        virtio_gpu_flush_display();
        return 0;
    }
    default:
        fut_printf("[FB-CHAR] fb_ioctl unknown req=0x%lx\n", req);
        break;
    }

    return -ENOTTY;
}

static ssize_t fb_write(void *inode, void *private_data,
                        const void *u_buf, size_t n, off_t *pos) {
    struct fb_device *fb = private_data ? (struct fb_device *)private_data
                                        : (struct fb_device *)inode;
    if (!fb) {
        return -ENODEV;
    }

    int rc = fb_ensure_mapped(fb);
    if (rc != 0) {
        return rc;
    }

    size_t fb_size = (size_t)fb->hw.info.pitch * fb->hw.info.height;
    size_t offset = (size_t)(*pos);
    if (offset >= fb_size) {
        return 0;
    }

    size_t remaining = fb_size - offset;
    if (n > remaining) {
        n = remaining;
    }

    rc = fut_copy_from_user((uint8_t *)fb->kva + offset, u_buf, n);
    if (rc != 0) {
        return rc;
    }

    *pos += (off_t)n;
    return (ssize_t)n;
}

static void *fb_mmap(void *inode, void *private_data, void *u_addr, size_t len,
                     off_t off, int prot, int flags) {
    (void)inode;
    (void)flags;

    struct fb_device *fb = private_data ? (struct fb_device *)private_data
                                        : (struct fb_device *)inode;
    if (!fb) {
        return (void *)(intptr_t)(-ENODEV);
    }

    FB_DBG("mmap: len=%zu off=%ld\n", len, (long)off);

    size_t fb_size = (size_t)fb->hw.info.pitch * fb->hw.info.height;
    if ((off & (PAGE_SIZE - 1)) != 0) {
        return (void *)(intptr_t)(-EINVAL);
    }
    if (len == 0 || off >= (off_t)fb_size) {
        return (void *)(intptr_t)(-EINVAL);
    }

    if (off + (off_t)len > (off_t)fb_size) {
        len = fb_size - (size_t)off;
    }

    /* Allocate virtual address if NULL was passed (standard mmap behavior) */
    uint64_t user_addr;
    if (u_addr == NULL) {
        extern uint64_t fut_task_alloc_mmap_addr(size_t);
        size_t map_len = (len + PAGE_SIZE - 1) & ~(size_t)(PAGE_SIZE - 1);
        user_addr = fut_task_alloc_mmap_addr(map_len);
        if ((int64_t)user_addr < 0) {
            return (void *)(intptr_t)user_addr;
        }
    } else {
        user_addr = (uint64_t)u_addr;
    }

    uint64_t phys_addr = (fb->hw.phys + (uint64_t)off) & ~(uint64_t)(PAGE_SIZE - 1);
    size_t map_len = (len + PAGE_SIZE - 1) & ~(size_t)(PAGE_SIZE - 1);

#ifdef __x86_64__
    uint64_t prot_flags = PTE_PRESENT | PTE_USER | pat_choose_page_attr_wc();
#else
    uint64_t prot_flags = PTE_VALID | PTE_AF_BIT | PTE_AP_RW_ALL | PTE_ATTR_NORMAL | PTE_SH_OUTER;
#endif
    if (prot & 0x2) {
        prot_flags |= PTE_WRITABLE;
    }

    fut_vmem_context_t *ctx = fut_mm_context(fut_mm_current());
    int rc = pmap_map_user(ctx, user_addr, phys_addr, map_len, prot_flags);
    if (rc != 0) {
        return (void *)(intptr_t)rc;
    }

    return (void *)(uintptr_t)user_addr;
}

/* Framebuffer file operations - initialized at runtime to avoid ARM64 relocation issues */
static struct fut_file_ops fb_fops;

void fb_char_init(void) {
    fb_fops.open = fb_open;
    fb_fops.release = NULL;
    fb_fops.read = NULL;
    fb_fops.write = fb_write;
    fb_fops.ioctl = fb_ioctl;
    fb_fops.mmap = fb_mmap;

    if (fb_get_info(&g_fb_dev.hw) != 0) {
        return;
    }

    g_fb_dev.kva = NULL;
    g_fb_dev.mapped = 0;
    g_fb_dev.vsync_ms = 0;
    g_fb_dev.open_count = 0;

    chrdev_register(FB_MAJOR, FB_MINOR, &fb_fops, "fb0", &g_fb_dev);
    devfs_create_chr("/dev/fb0", FB_MAJOR, FB_MINOR);
}
