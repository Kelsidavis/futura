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
#include <kernel/fut_mm.h>
#include <kernel/fut_task.h>
#include <kernel/kprintf.h>
#include <sys/mman.h>
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

/* /dev/zero mmap: create an anonymous mapping backed by zeroed pages.
 * This allows programs to use open("/dev/zero") + mmap() as an alternative
 * to MAP_ANONYMOUS for creating zero-filled private or shared mappings.
 * Offset is ignored (all of /dev/zero appears as zeroed infinite storage). */
static void *zero_mmap_op(void *inode, void *priv, void *u_addr, size_t len,
                           off_t off, int prot, int flags) {
    (void)inode; (void)priv; (void)off;
    fut_task_t *task = fut_task_current();
    if (!task) return (void *)(intptr_t)(-ESRCH);

    fut_mm_t *mm = fut_task_get_mm(task);
    if (!mm) mm = fut_mm_current();
    if (!mm) return (void *)(intptr_t)(-ENOMEM);

    /* Force MAP_ANONYMOUS: /dev/zero is equivalent to an anonymous mapping */
    int anon_flags = flags | MAP_ANONYMOUS;
    return fut_mm_map_anonymous(mm, (uintptr_t)u_addr, len, prot, anon_flags);
}

static const struct fut_file_ops zero_fops = {
    .read = zero_read,
    .write = null_write,  /* Same as /dev/null — discard */
    .open = NULL,
    .release = NULL,
    .ioctl = NULL,
    .mmap = zero_mmap_op,
};

/* /dev/urandom: read returns random bytes (from getrandom), write succeeds */
static ssize_t urandom_read(void *inode, void *priv, void *buf, size_t n, off_t *pos) {
    (void)inode; (void)priv; (void)pos;
    extern long sys_getrandom(void *buf, size_t buflen, unsigned int flags);
    long ret = sys_getrandom(buf, n, 0);
    return (ret < 0) ? ret : (ssize_t)ret;
}

static const struct fut_file_ops urandom_fops = {
    .read = urandom_read,
    .write = null_write,  /* Accept and discard (seeds entropy pool) */
    .open = NULL,
    .release = NULL,
    .ioctl = NULL,
    .mmap = NULL,
};

/* /dev/full: read returns zero bytes (like /dev/zero), write returns ENOSPC */
static ssize_t full_write(void *inode, void *priv, const void *buf, size_t n, off_t *pos) {
    (void)inode; (void)priv; (void)buf; (void)n; (void)pos;
    return -28;  /* -ENOSPC: No space left on device */
}

static const struct fut_file_ops full_fops = {
    .read = zero_read,     /* Same as /dev/zero — returns zeroes */
    .write = full_write,
    .open = NULL,
    .release = NULL,
    .ioctl = NULL,
    .mmap = NULL,
};

/**
 * Initialize /dev/null, /dev/zero, /dev/full, and /dev/urandom devices.
 * Call from kernel_main during boot.
 */
void dev_null_init(void) {
    /* Linux device numbers: /dev/null = (1,3), /dev/zero = (1,5) */
    chrdev_register(1, 3, &null_fops, "null", NULL);
    devfs_create_chr("/dev/null", 1, 3);

    chrdev_register(1, 5, &zero_fops, "zero", NULL);
    devfs_create_chr("/dev/zero", 1, 5);

    /* /dev/full = (1,7): like /dev/zero but write returns ENOSPC */
    chrdev_register(1, 7, &full_fops, "full", NULL);
    devfs_create_chr("/dev/full", 1, 7);

    /* /dev/urandom = (1,9), /dev/random = (1,8) — both use same PRNG */
    chrdev_register(1, 9, &urandom_fops, "urandom", NULL);
    devfs_create_chr("/dev/urandom", 1, 9);

    chrdev_register(1, 8, &urandom_fops, "random", NULL);
    devfs_create_chr("/dev/random", 1, 8);

    fut_printf("[DEV] /dev/null, /dev/zero, /dev/full, /dev/urandom, /dev/random registered\n");
}
