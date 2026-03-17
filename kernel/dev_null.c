/* kernel/dev_null.c - /dev/null and /dev/zero character devices
 *
 * Copyright (c) 2025 Kelsi Davis
 * Licensed under the MPL v2.0 — see LICENSE for details.
 *
 * /dev/null: write discards all data, read returns EOF (0 bytes)
 * /dev/zero: write discards all data, read returns zero bytes
 *
 * These are essential pseudo-devices used by virtually all Unix programs.
 */

#include <kernel/chrdev.h>
#include <kernel/devfs.h>
#include <kernel/errno.h>
#include <kernel/kprintf.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>

/* /dev/null: read returns 0 (EOF), write succeeds */
static ssize_t null_read(void *inode, void *priv, void *buf, size_t n, off_t *pos) {
    (void)inode; (void)priv; (void)buf; (void)n; (void)pos;
    return 0;  /* EOF */
}

static ssize_t null_write(void *inode, void *priv, const void *buf, size_t n, off_t *pos) {
    (void)inode; (void)priv; (void)buf; (void)pos;
    return (ssize_t)n;  /* Accept and discard all data */
}

static const struct fut_file_ops null_fops = {
    .read = null_read,
    .write = null_write,
    .open = NULL,
    .release = NULL,
    .ioctl = NULL,
    .mmap = NULL,
};

/* /dev/zero: read returns zero bytes, write succeeds */
static ssize_t zero_read(void *inode, void *priv, void *buf, size_t n, off_t *pos) {
    (void)inode; (void)priv; (void)pos;
    memset(buf, 0, n);
    return (ssize_t)n;
}

static const struct fut_file_ops zero_fops = {
    .read = zero_read,
    .write = null_write,  /* Same as /dev/null — discard */
    .open = NULL,
    .release = NULL,
    .ioctl = NULL,
    .mmap = NULL,
};

/**
 * Initialize /dev/null and /dev/zero devices.
 * Call from kernel_main during boot.
 */
void dev_null_init(void) {
    /* Linux device numbers: /dev/null = (1,3), /dev/zero = (1,5) */
    chrdev_register(1, 3, &null_fops, "null", NULL);
    devfs_create_chr("/dev/null", 1, 3);

    chrdev_register(1, 5, &zero_fops, "zero", NULL);
    devfs_create_chr("/dev/zero", 1, 5);

    fut_printf("[DEV] /dev/null and /dev/zero registered\n");
}
