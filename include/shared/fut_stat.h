// SPDX-License-Identifier: MPL-2.0
/*
 * shared/fut_stat.h - Kernel stat structure
 *
 * Copyright (c) 2025 Kelsi Davis
 * Licensed under the MPL v2.0 — see LICENSE for details.
 *
 * Provides the kernel-compatible stat structure used internally.
 * This uses raw int64_t timestamps instead of struct timespec for
 * simplicity in kernel syscall implementations.
 */

#pragma once

#include <stdint.h>

/* ============================================================
 *   Kernel stat structure
 * ============================================================ */

#ifndef _STRUCT_FUT_STAT
#define _STRUCT_FUT_STAT
struct fut_stat {
    uint64_t st_dev;        /* Device ID */
    uint64_t st_ino;        /* Inode number */
    uint32_t st_mode;       /* File mode */
    uint32_t st_nlink;      /* Number of hard links */
    uint32_t st_uid;        /* User ID */
    uint32_t st_gid;        /* Group ID */
    uint64_t st_rdev;       /* Device ID (if special file) */
    uint64_t st_size;       /* Total size in bytes */
    uint32_t st_blksize;    /* Block size for I/O */
    uint64_t st_blocks;     /* Number of 512B blocks */
    int64_t  st_atime;      /* Access time (seconds since epoch) */
    int64_t  st_mtime;      /* Modification time (seconds since epoch) */
    int64_t  st_ctime;      /* Status change time (seconds since epoch) */
};
#endif

/* ============================================================
 *   File Mode Constants
 * ============================================================ */

/* File type mask */
#ifndef S_IFMT
#define S_IFMT   0170000    /* File type mask */
#endif

/* File types */
#ifndef S_IFSOCK
#define S_IFSOCK 0140000    /* Socket */
#endif
#ifndef S_IFLNK
#define S_IFLNK  0120000    /* Symbolic link */
#endif
#ifndef S_IFREG
#define S_IFREG  0100000    /* Regular file */
#endif
#ifndef S_IFBLK
#define S_IFBLK  0060000    /* Block device */
#endif
#ifndef S_IFDIR
#define S_IFDIR  0040000    /* Directory */
#endif
#ifndef S_IFCHR
#define S_IFCHR  0020000    /* Character device */
#endif
#ifndef S_IFIFO
#define S_IFIFO  0010000    /* FIFO (named pipe) */
#endif

/* File type test macros */
#ifndef S_ISREG
#define S_ISREG(m)  (((m) & S_IFMT) == S_IFREG)
#endif
#ifndef S_ISDIR
#define S_ISDIR(m)  (((m) & S_IFMT) == S_IFDIR)
#endif
#ifndef S_ISCHR
#define S_ISCHR(m)  (((m) & S_IFMT) == S_IFCHR)
#endif
#ifndef S_ISBLK
#define S_ISBLK(m)  (((m) & S_IFMT) == S_IFBLK)
#endif
#ifndef S_ISFIFO
#define S_ISFIFO(m) (((m) & S_IFMT) == S_IFIFO)
#endif
#ifndef S_ISLNK
#define S_ISLNK(m)  (((m) & S_IFMT) == S_IFLNK)
#endif
#ifndef S_ISSOCK
#define S_ISSOCK(m) (((m) & S_IFMT) == S_IFSOCK)
#endif

/* Permission bits */
#ifndef S_ISUID
#define S_ISUID  04000      /* Set user ID on execution */
#endif
#ifndef S_ISGID
#define S_ISGID  02000      /* Set group ID on execution */
#endif
#ifndef S_ISVTX
#define S_ISVTX  01000      /* Sticky bit */
#endif

/* User permissions */
#ifndef S_IRWXU
#define S_IRWXU  0700       /* User rwx mask */
#endif
#ifndef S_IRUSR
#define S_IRUSR  0400       /* User read */
#endif
#ifndef S_IWUSR
#define S_IWUSR  0200       /* User write */
#endif
#ifndef S_IXUSR
#define S_IXUSR  0100       /* User execute */
#endif

/* Group permissions */
#ifndef S_IRWXG
#define S_IRWXG  0070       /* Group rwx mask */
#endif
#ifndef S_IRGRP
#define S_IRGRP  0040       /* Group read */
#endif
#ifndef S_IWGRP
#define S_IWGRP  0020       /* Group write */
#endif
#ifndef S_IXGRP
#define S_IXGRP  0010       /* Group execute */
#endif

/* Other permissions */
#ifndef S_IRWXO
#define S_IRWXO  0007       /* Other rwx mask */
#endif
#ifndef S_IROTH
#define S_IROTH  0004       /* Other read */
#endif
#ifndef S_IWOTH
#define S_IWOTH  0002       /* Other write */
#endif
#ifndef S_IXOTH
#define S_IXOTH  0001       /* Other execute */
#endif
