// SPDX-License-Identifier: MPL-2.0
/*
 * futfs.h - FuturaFS v0 public interface
 *
 * Minimal log-structured filesystem exposing capability-aware handles
 * for the kernel. The implementation lives in subsystems/futura_fs/futfs.c
 * and is intended to be linked into the kernel build.
 */

#pragma once

#include <stddef.h>
#include <stdint.h>

#include <futura/blkdev.h>
#include <kernel/fut_vfs.h>

#ifdef __cplusplus
extern "C" {
#endif

#define FUTFS_SUPER_MAGIC 0x46554653u /* "FUFS" */

enum futfs_inode_type {
    FUTFS_INODE_REG = 1,
    FUTFS_INODE_DIR = 2,
};

enum futfs_rights_bits {
    FUTFS_RIGHT_READ  = 1u << 0,
    FUTFS_RIGHT_WRITE = 1u << 1,
    FUTFS_RIGHT_ADMIN = 1u << 2,
};

typedef struct futfs_handle futfs_handle_t;

/// Mount the filesystem on the provided block device capability.
fut_status_t futfs_mount(fut_handle_t dev);

/// Unmount the active filesystem, flushing outstanding data.
fut_status_t futfs_unmount(void);

/// Create a new file (only absolute paths rooted at "/" are currently supported).
fut_status_t futfs_create(const char *path, fut_handle_t *out);

/// Read from a file handle. Updates *out with bytes read.
fut_status_t futfs_read(fut_handle_t h, void *buf, size_t len, size_t *out);

/// Write to a file handle (full overwrite semantics in v0).
fut_status_t futfs_write(fut_handle_t h, const void *buf, size_t len);

/// Flush file and filesystem state to the underlying block device.
fut_status_t futfs_sync(fut_handle_t h);

/// Query file metadata.
fut_status_t futfs_stat(fut_handle_t h, struct fut_stat *out);

/// Close and release a capability handle returned by futfs_create().
fut_status_t futfs_close(fut_handle_t h);

#ifdef __cplusplus
}
#endif
