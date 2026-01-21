// SPDX-License-Identifier: MPL-2.0
/*
 * sys/statfs.h - Filesystem statistics
 *
 * Copyright (c) 2025 Kelsi Davis
 * Licensed under the MPL v2.0 — see LICENSE for details.
 *
 * Provides structures and functions for querying filesystem
 * statistics including space usage and mount information.
 */

#pragma once

#include <stdint.h>

/* ============================================================
 *   Filesystem Type Magic Numbers
 * ============================================================ */

#ifndef TMPFS_MAGIC
#define TMPFS_MAGIC         0x01021994
#endif
#ifndef RAMFS_MAGIC
#define RAMFS_MAGIC         0x858458F6
#endif
#ifndef EXT2_SUPER_MAGIC
#define EXT2_SUPER_MAGIC    0xEF53
#endif
#ifndef EXT3_SUPER_MAGIC
#define EXT3_SUPER_MAGIC    0xEF53
#endif
#ifndef EXT4_SUPER_MAGIC
#define EXT4_SUPER_MAGIC    0xEF53
#endif
#ifndef PROC_SUPER_MAGIC
#define PROC_SUPER_MAGIC    0x9FA0
#endif
#ifndef SYSFS_MAGIC
#define SYSFS_MAGIC         0x62656572
#endif
#ifndef DEVFS_SUPER_MAGIC
#define DEVFS_SUPER_MAGIC   0x1373
#endif
#ifndef NFS_SUPER_MAGIC
#define NFS_SUPER_MAGIC     0x6969
#endif
#ifndef BTRFS_SUPER_MAGIC
#define BTRFS_SUPER_MAGIC   0x9123683E
#endif

/* ============================================================
 *   Mount Flags (f_flags values)
 * ============================================================ */

#ifndef ST_RDONLY
#define ST_RDONLY       0x0001  /* Read-only filesystem */
#endif
#ifndef ST_NOSUID
#define ST_NOSUID       0x0002  /* Ignore suid and sgid bits */
#endif
#ifndef ST_NODEV
#define ST_NODEV        0x0004  /* Disallow device special files */
#endif
#ifndef ST_NOEXEC
#define ST_NOEXEC       0x0008  /* Disallow program execution */
#endif
#ifndef ST_SYNCHRONOUS
#define ST_SYNCHRONOUS  0x0010  /* Synchronous writes */
#endif
#ifndef ST_MANDLOCK
#define ST_MANDLOCK     0x0040  /* Mandatory locking enabled */
#endif
#ifndef ST_NOATIME
#define ST_NOATIME      0x0400  /* Don't update access times */
#endif
#ifndef ST_NODIRATIME
#define ST_NODIRATIME   0x0800  /* Don't update directory access times */
#endif
#ifndef ST_RELATIME
#define ST_RELATIME     0x1000  /* Relative access time updates */
#endif

/* ============================================================
 *   Filesystem ID Type
 * ============================================================ */

#ifndef _FSID_T_DEFINED
#define _FSID_T_DEFINED
typedef struct {
    int __val[2];
} fsid_t;
#endif

/* ============================================================
 *   statfs Structure
 * ============================================================ */

/**
 * struct statfs - Filesystem statistics (Linux-compatible)
 *
 * Contains information about a mounted filesystem.
 * Returned by statfs() and fstatfs() syscalls.
 *
 * @f_type     Filesystem type magic number
 * @f_bsize    Optimal transfer block size
 * @f_blocks   Total data blocks in filesystem
 * @f_bfree    Free blocks in filesystem
 * @f_bavail   Free blocks available to unprivileged user
 * @f_files    Total file nodes (inodes) in filesystem
 * @f_ffree    Free file nodes in filesystem
 * @f_fsid     Filesystem ID
 * @f_namelen  Maximum length of filenames
 * @f_frsize   Fragment size (for POSIX compliance)
 * @f_flags    Mount flags
 * @f_spare    Reserved for future use
 */
#ifndef _STRUCT_STATFS
#define _STRUCT_STATFS
struct statfs {
    uint64_t f_type;        /* Filesystem type */
    uint64_t f_bsize;       /* Optimal transfer block size */
    uint64_t f_blocks;      /* Total data blocks */
    uint64_t f_bfree;       /* Free blocks */
    uint64_t f_bavail;      /* Free blocks for unprivileged user */
    uint64_t f_files;       /* Total file nodes */
    uint64_t f_ffree;       /* Free file nodes */
    uint64_t f_fsid[2];     /* Filesystem ID */
    uint64_t f_namelen;     /* Maximum filename length */
    uint64_t f_frsize;      /* Fragment size */
    uint64_t f_flags;       /* Mount flags */
    uint64_t f_spare[4];    /* Reserved */
};
#endif

/**
 * struct statfs64 - 64-bit filesystem statistics
 *
 * Same as struct statfs but explicitly 64-bit.
 * Used by statfs64() and fstatfs64() on 32-bit systems.
 */
#ifndef _STRUCT_STATFS64
#define _STRUCT_STATFS64
struct statfs64 {
    uint64_t f_type;
    uint64_t f_bsize;
    uint64_t f_blocks;
    uint64_t f_bfree;
    uint64_t f_bavail;
    uint64_t f_files;
    uint64_t f_ffree;
    uint64_t f_fsid[2];
    uint64_t f_namelen;
    uint64_t f_frsize;
    uint64_t f_flags;
    uint64_t f_spare[4];
};
#endif

/* ============================================================
 *   Function Declarations
 * ============================================================ */

/**
 * statfs - Get filesystem statistics
 *
 * @path  Path to any file in the mounted filesystem
 * @buf   Buffer to receive filesystem statistics
 *
 * Returns 0 on success, -1 on error (with errno set).
 */
extern int statfs(const char *path, struct statfs *buf);

/**
 * fstatfs - Get filesystem statistics by file descriptor
 *
 * @fd   File descriptor of open file in filesystem
 * @buf  Buffer to receive filesystem statistics
 *
 * Returns 0 on success, -1 on error (with errno set).
 */
extern int fstatfs(int fd, struct statfs *buf);

/**
 * statfs64 - Get 64-bit filesystem statistics
 *
 * @path  Path to any file in the mounted filesystem
 * @buf   Buffer to receive filesystem statistics
 *
 * Returns 0 on success, -1 on error (with errno set).
 */
extern int statfs64(const char *path, struct statfs64 *buf);

/**
 * fstatfs64 - Get 64-bit filesystem statistics by file descriptor
 *
 * @fd   File descriptor of open file in filesystem
 * @buf  Buffer to receive filesystem statistics
 *
 * Returns 0 on success, -1 on error (with errno set).
 */
extern int fstatfs64(int fd, struct statfs64 *buf);

