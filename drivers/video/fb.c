// SPDX-License-Identifier: MPL-2.0
/*
 * fb.c - Minimal /dev/fb0 character device
 */

#include <kernel/chrdev.h>
#include <kernel/devfs.h>
#include <kernel/uaccess.h>
#include <kernel/errno.h>
#include <kernel/fb.h>
#include <kernel/fut_mm.h>
#include <platform/platform.h>
#include <futura/fb_ioctl.h>

#include <arch/x86_64/pmap.h>
#include <arch/x86_64/pat.h>

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
    uintptr_t virt_base = pmap_phys_to_virt(phys_base);
    size_t offset = (size_t)(fb->hw.phys - phys_base);
    size_t length = fb->hw.info.pitch * fb->hw.info.height + offset;
    length = PAGE_ALIGN_UP(length);

    uint64_t flags = PTE_PRESENT | PTE_WRITABLE | pat_choose_page_attr_wc();
    int rc = pmap_map(virt_base,
                      phys_base,
                      length,
                      flags);
    if (rc != 0) {
        return rc;
    }

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
        FB_DBG("set vsync hint=%u ms\n", value);
        return 0;
    }
    default:
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

    uint64_t user_addr = (uint64_t)u_addr;
    uint64_t phys_addr = (fb->hw.phys + (uint64_t)off) & ~(uint64_t)(PAGE_SIZE - 1);
    size_t map_len = (len + PAGE_SIZE - 1) & ~(size_t)(PAGE_SIZE - 1);

    uint64_t prot_flags = PTE_PRESENT | PTE_USER | pat_choose_page_attr_wc();
    if (prot & 0x2) { /* PROT_WRITE */
        prot_flags |= PTE_WRITABLE;
    }

    fut_vmem_context_t *ctx = fut_mm_context(fut_mm_current());
    int rc = pmap_map_user(ctx, user_addr, phys_addr, map_len, prot_flags);
    if (rc != 0) {
        return (void *)(intptr_t)rc;
    }

    return u_addr;
}

static const struct fut_file_ops fb_fops = {
    .open = fb_open,
    .release = NULL,
    .read = NULL,
    .write = fb_write,
    .ioctl = fb_ioctl,
    .mmap = fb_mmap,
};

void fb_char_init(void) {
    if (fb_get_info(&g_fb_dev.hw) != 0) {
        return;
    }

    FB_DBG("probe %ux%u pitch=%u bpp=%u phys=0x%llx\n",
           g_fb_dev.hw.info.width,
           g_fb_dev.hw.info.height,
           g_fb_dev.hw.info.pitch,
           g_fb_dev.hw.info.bpp,
           (unsigned long long)g_fb_dev.hw.phys);

    g_fb_dev.kva = NULL;
    g_fb_dev.mapped = 0;
    g_fb_dev.vsync_ms = 0;
    g_fb_dev.open_count = 0;

    (void)chrdev_register(FB_MAJOR, FB_MINOR, &fb_fops, "fb0", &g_fb_dev);
    (void)devfs_create_chr("/dev/fb0", FB_MAJOR, FB_MINOR);
}
