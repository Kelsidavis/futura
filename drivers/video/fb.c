// SPDX-License-Identifier: MPL-2.0
/*
 * fb.c - Minimal /dev/fb0 character device
 */

#include <kernel/chrdev.h>
#include <kernel/devfs.h>
#include <kernel/uaccess.h>
#include <kernel/errno.h>
#include <kernel/fb.h>
#include <kernel/fb_ioctl.h>

#include <arch/x86_64/pmap.h>

#include <stddef.h>
#include <stdint.h>

#define FB_MAJOR 29u
#define FB_MINOR 0u

struct fb_device {
    struct fut_fb_info info;
    void *kva;
    int mapped;
};

static struct fb_device g_fb_dev = {0};

static int fb_ensure_mapped(struct fb_device *fb) {
    if (fb->mapped) {
        return 0;
    }

    uintptr_t phys_base = PAGE_ALIGN_DOWN(fb->info.phys);
    uintptr_t virt_base = pmap_phys_to_virt(phys_base);
    size_t offset = (size_t)(fb->info.phys - phys_base);
    size_t length = fb->info.pitch * fb->info.height + offset;
    length = PAGE_ALIGN_UP(length);

    int rc = pmap_map(virt_base,
                      phys_base,
                      length,
                      PTE_PRESENT | PTE_WRITABLE | PTE_WRITE_THROUGH | PTE_CACHE_DISABLE);
    if (rc != 0) {
        return rc;
    }

    fb->kva = (void *)(virt_base + offset);
    fb->mapped = 1;
    return 0;
}

static int fb_open(void *inode, void **private_data) {
    if (private_data) {
        *private_data = inode;
    }
    return 0;
}

static int fb_ioctl(void *inode, void *private_data,
                    unsigned long req, unsigned long arg) {
    (void)inode;

    struct fb_device *fb = (struct fb_device *)private_data;
    if (!fb) {
        return -ENODEV;
    }

    if (req == FBIOGET_FSCREENINFO) {
        struct fb_fix_screeninfo info = {
            .smem_start = fb->info.phys,
            .line_length = fb->info.pitch,
            .smem_len = fb->info.pitch * fb->info.height,
        };
        return fut_copy_to_user((void *)arg, &info, sizeof info);
    }

    if (req == FBIOGET_VSCREENINFO) {
        struct fb_var_screeninfo info = {
            .xres = fb->info.width,
            .yres = fb->info.height,
            .bits_per_pixel = fb->info.bpp,
        };
        return fut_copy_to_user((void *)arg, &info, sizeof info);
    }

    return -ENOTTY;
}

static ssize_t fb_write(void *inode, void *private_data,
                        const void *u_buf, size_t n, off_t *pos) {
    (void)inode;
    struct fb_device *fb = (struct fb_device *)private_data;
    if (!fb) {
        return -ENODEV;
    }

    int rc = fb_ensure_mapped(fb);
    if (rc != 0) {
        return rc;
    }

    size_t offset = (size_t)(*pos);
    if (offset >= fb->info.pitch * fb->info.height) {
        return 0;
    }

    size_t remaining = fb->info.pitch * fb->info.height - offset;
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

    struct fb_device *fb = (struct fb_device *)private_data;
    if (!fb) {
        return (void *)(intptr_t)(-ENODEV);
    }

    size_t fb_size = (size_t)fb->info.pitch * fb->info.height;
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
    uint64_t phys_addr = (fb->info.phys + (uint64_t)off) & ~(uint64_t)(PAGE_SIZE - 1);
    size_t map_len = (len + PAGE_SIZE - 1) & ~(size_t)(PAGE_SIZE - 1);

    uint64_t prot_flags = PTE_PRESENT | PTE_USER;
    if (prot & 0x2) {
        prot_flags |= PTE_WRITABLE;
    }

    int rc = pmap_map_user(NULL, user_addr, phys_addr, map_len, prot_flags);
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
    if (fb_get_info(&g_fb_dev.info) != 0) {
        return;
    }

    g_fb_dev.kva = NULL;
    g_fb_dev.mapped = 0;

    chrdev_register(FB_MAJOR, FB_MINOR, &fb_fops, "fb0", &g_fb_dev);
    devfs_create_chr("/dev/fb0", FB_MAJOR, FB_MINOR);
}
