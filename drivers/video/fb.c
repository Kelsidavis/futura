// SPDX-License-Identifier: MPL-2.0
/*
 * fb.c - Minimal /dev/fb0 character device
 */

#include <kernel/chrdev.h>
#include <kernel/uaccess.h>
#include <kernel/errno.h>
#include <kernel/fb.h>

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

static const struct fut_file_ops fb_fops = {
    .open = fb_open,
    .release = NULL,
    .read = NULL,
    .write = fb_write,
    .ioctl = NULL,
    .mmap = NULL,
};

void fb_char_init(void) {
    if (fb_get_info(&g_fb_dev.info) != 0) {
        return;
    }

    g_fb_dev.kva = NULL;
    g_fb_dev.mapped = 0;

    chrdev_register(FB_MAJOR, FB_MINOR, &fb_fops, "fb0", &g_fb_dev);
}
