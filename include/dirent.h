// SPDX-License-Identifier: MPL-2.0
/*
 * dirent.h - Directory entry definitions
 *
 * Copyright (c) 2025 Kelsi Davis
 * Licensed under the MPL v2.0 — see LICENSE for details.
 *
 * Provides directory entry types and structures for reading
 * directory contents via getdents/getdents64 syscalls.
 */

#pragma once

#include <stdint.h>

/* ============================================================
 *   Directory Entry File Types (d_type values)
 * ============================================================ */

#ifndef DT_UNKNOWN
#define DT_UNKNOWN      0       /* Unknown file type */
#endif
#ifndef DT_FIFO
#define DT_FIFO         1       /* Named pipe (FIFO) */
#endif
#ifndef DT_CHR
#define DT_CHR          2       /* Character device */
#endif
#ifndef DT_DIR
#define DT_DIR          4       /* Directory */
#endif
#ifndef DT_BLK
#define DT_BLK          6       /* Block device */
#endif
#ifndef DT_REG
#define DT_REG          8       /* Regular file */
#endif
#ifndef DT_LNK
#define DT_LNK          10      /* Symbolic link */
#endif
#ifndef DT_SOCK
#define DT_SOCK         12      /* Unix domain socket */
#endif
#ifndef DT_WHT
#define DT_WHT          14      /* Whiteout (union filesystem) */
#endif

/* ============================================================
 *   Conversion Macros
 * ============================================================ */

/**
 * IFTODT - Convert stat mode to directory entry type
 *
 * Converts the file type portion of a stat mode_t to the
 * corresponding d_type value for directory entries.
 */
#ifndef IFTODT
#define IFTODT(mode)    (((mode) & 0170000) >> 12)
#endif

/**
 * DTTOIF - Convert directory entry type to stat mode
 *
 * Converts a d_type value to the corresponding file type
 * portion of a stat mode_t.
 */
#ifndef DTTOIF
#define DTTOIF(dirtype) ((dirtype) << 12)
#endif

/* ============================================================
 *   Directory Entry Structures
 * ============================================================ */

/**
 * struct linux_dirent64 - 64-bit directory entry
 *
 * Structure returned by the getdents64() syscall.
 * Used for directory traversal with large inode support.
 *
 * @d_ino    Inode number (0 for deleted/invalid entries)
 * @d_off    Offset to next entry (cookie for next read)
 * @d_reclen Record length of this entry (including padding)
 * @d_type   File type (DT_REG, DT_DIR, etc.)
 * @d_name   Null-terminated filename (variable length)
 *
 * Note: Entries are 8-byte aligned. d_reclen includes padding.
 */
#ifndef _STRUCT_LINUX_DIRENT64
#define _STRUCT_LINUX_DIRENT64
struct linux_dirent64 {
    uint64_t d_ino;         /* Inode number */
    int64_t  d_off;         /* Offset to next entry */
    uint16_t d_reclen;      /* Length of this record */
    uint8_t  d_type;        /* File type */
    char     d_name[];      /* Null-terminated filename */
} __attribute__((packed));
#endif

/**
 * struct linux_dirent - 32-bit directory entry (legacy)
 *
 * Structure returned by the legacy getdents() syscall.
 * Prefer linux_dirent64 for new code.
 *
 * @d_ino    Inode number (truncated to 32 bits)
 * @d_off    Offset to next entry
 * @d_reclen Record length
 * @d_name   Null-terminated filename (variable length)
 *
 * Note: d_type is stored as the last byte before the name's null terminator.
 */
#ifndef _STRUCT_LINUX_DIRENT
#define _STRUCT_LINUX_DIRENT
struct linux_dirent {
    uint32_t d_ino;         /* Inode number */
    uint32_t d_off;         /* Offset to next entry */
    uint16_t d_reclen;      /* Length of this record */
    char     d_name[];      /* Filename followed by d_type byte */
} __attribute__((packed));
#endif

/**
 * struct dirent - POSIX directory entry
 *
 * Standard POSIX directory entry structure for readdir().
 * Used by the C library's directory functions.
 */
#ifndef _STRUCT_DIRENT
#define _STRUCT_DIRENT
struct dirent {
    uint64_t d_ino;         /* Inode number */
    int64_t  d_off;         /* Offset to next entry */
    uint16_t d_reclen;      /* Length of this record */
    uint8_t  d_type;        /* File type */
    char     d_name[256];   /* Null-terminated filename */
};
#endif

/* ============================================================
 *   Name Length Constants
 * ============================================================ */

#ifndef NAME_MAX
#define NAME_MAX        255     /* Maximum filename length */
#endif

/* Maximum length for d_name in struct dirent */
#ifndef DIRENT_NAME_MAX
#define DIRENT_NAME_MAX 256
#endif

/* ============================================================
 *   Function Declarations
 * ============================================================ */

/**
 * getdents64 - Read directory entries
 *
 * @fd     Open directory file descriptor
 * @dirp   Buffer to receive directory entries
 * @count  Size of buffer
 *
 * Returns number of bytes read, 0 at end of directory, or -1 on error.
 */
extern int getdents64(int fd, void *dirp, unsigned int count);

/**
 * getdents - Read directory entries (legacy 32-bit interface)
 *
 * @fd     Open directory file descriptor
 * @dirp   Buffer to receive directory entries
 * @count  Size of buffer
 *
 * Returns number of bytes read, 0 at end of directory, or -1 on error.
 * Prefer getdents64() for new code.
 */
extern int getdents(int fd, void *dirp, unsigned int count);

