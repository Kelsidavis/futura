/* include/kernel/chrdev.h - Character device registration interface
 *
 * Copyright (c) 2025 Kelsi Davis
 * Licensed under the MPL v2.0 — see LICENSE for details.
 *
 * Defines the character device driver interface and registration functions.
 */

#pragma once

#include <stddef.h>
#include <stdint.h>

#ifndef _SSIZE_T_DEFINED
#define _SSIZE_T_DEFINED
typedef long ssize_t;
#endif

#ifndef _OFF_T_DEFINED
#define _OFF_T_DEFINED
typedef long off_t;
#endif

struct fut_file_ops {
    int     (*open)(void *inode, int flags, void **private_data);
    int     (*release)(void *inode, void *private_data);
    ssize_t (*read)(void *inode, void *private_data, void *u_buf, size_t n, off_t *pos);
    ssize_t (*write)(void *inode, void *private_data, const void *u_buf, size_t n, off_t *pos);
    int     (*ioctl)(void *inode, void *private_data, unsigned long req, unsigned long arg);
    void   *(*mmap)(void *inode, void *private_data, void *u_addr, size_t len, off_t off, int prot, int flags);
};

int  chrdev_register(unsigned major, unsigned minor, const struct fut_file_ops *fops,
                     const char *name, void *driver_data);
const struct fut_file_ops *chrdev_lookup(unsigned major, unsigned minor, void **out_drv);
int  chrdev_alloc_fd(const struct fut_file_ops *ops, void *inode, void *priv);
