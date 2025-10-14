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

#ifdef DEBUG_FUTFS
extern void fut_printf(const char *fmt, ...);
#define FSDBG(...) fut_printf(__VA_ARGS__)
#else
#define FSDBG(...) do { } while (0)
#endif

#define FUTFS_SUPER_MAGIC 0x46554653u /* "FUFS" */
#define FUTFS_NAME_MAX   64u

#define FUTFS_FEATURE_LOG_STRUCTURED  (1ull << 0)
#define FUTFS_FEATURE_TOMBSTONES      (1ull << 1)
#define FUTFS_FEATURE_DIR_COMPACTION  (1ull << 2)

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

typedef struct futfs_dirent {
    uint64_t ino;
    uint32_t type;
    char name[FUTFS_NAME_MAX + 1];
} futfs_dirent_t;

struct futfs_gc_stats {
    uint64_t tombstones_before;
    uint64_t tombstones_after;
    size_t bytes_before;
    size_t bytes_after;
};

/// Mount the filesystem on the provided block device capability.
fut_status_t futfs_mount(fut_handle_t dev);

/// Unmount the active filesystem, flushing outstanding data.
fut_status_t futfs_unmount(void);

/// Create a new file (only absolute paths rooted at "/" are currently supported).
fut_status_t futfs_create(const char *path, fut_handle_t *out);

/// Create a new directory (currently only at the root).
fut_status_t futfs_mkdir(const char *path);

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

/// Iterate directory entries. cookie is an opaque offset updated on success.
fut_status_t futfs_readdir(const char *path, size_t *cookie, futfs_dirent_t *out);

/// Remove a file.
fut_status_t futfs_unlink(const char *path);

/// Remove an empty directory.
fut_status_t futfs_rmdir(const char *path);

/// Query high-level filesystem statistics.
fut_status_t futfs_statfs(struct fut_statfs *out);

/// Compact a directory stream, removing tombstones (path-based helper).
fut_status_t futfs_compact_dir(const char *path, struct futfs_gc_stats *stats);

/// Enable or disable crash injection during compaction (testing aide).
void futfs_set_crash_compaction(bool enable);

#ifdef __cplusplus
}
#endif
