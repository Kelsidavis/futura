// SPDX-License-Identifier: MPL-2.0
/*
 * sys/types.h - POSIX data types
 *
 * Copyright (c) 2025 Kelsi Davis
 * Licensed under the MPL v2.0 — see LICENSE for details.
 *
 * Provides fundamental POSIX type definitions used throughout the system.
 * These types are required by many system interfaces and should be included
 * whenever POSIX-compatible system types are needed.
 */

#pragma once

#include <stdint.h>
#include <stddef.h>

/* ============================================================
 *   Process/User/Group ID Types
 * ============================================================ */

#ifndef __pid_t_defined
#define __pid_t_defined 1
typedef int32_t pid_t;          /* Process ID */
#endif

#ifndef __uid_t_defined
#define __uid_t_defined 1
typedef uint32_t uid_t;         /* User ID */
#endif

#ifndef __gid_t_defined
#define __gid_t_defined 1
typedef uint32_t gid_t;         /* Group ID */
#endif

#ifndef __id_t_defined
#define __id_t_defined 1
typedef uint32_t id_t;          /* Generic ID (pid, uid, or gid) */
#endif

/* ============================================================
 *   File System Types
 * ============================================================ */

#ifndef __mode_t_defined
#define __mode_t_defined 1
typedef uint32_t mode_t;        /* File permission mode */
#endif

#ifndef __dev_t_defined
#define __dev_t_defined 1
typedef uint64_t dev_t;         /* Device number */
#endif

#ifndef __ino_t_defined
#define __ino_t_defined 1
typedef uint64_t ino_t;         /* Inode number */
#endif

#ifndef __nlink_t_defined
#define __nlink_t_defined 1
typedef uint64_t nlink_t;       /* Link count */
#endif

/* ============================================================
 *   File Offset and Size Types
 * ============================================================ */

#ifndef __off_t_defined
#define __off_t_defined 1
typedef int64_t off_t;          /* File offset (signed for relative seeks) */
#endif

#ifndef __loff_t_defined
#define __loff_t_defined 1
typedef int64_t loff_t;         /* Large file offset */
#endif

#ifndef __blksize_t_defined
#define __blksize_t_defined 1
typedef int64_t blksize_t;      /* Block size for I/O */
#endif

#ifndef __blkcnt_t_defined
#define __blkcnt_t_defined 1
typedef int64_t blkcnt_t;       /* Block count */
#endif

#ifndef __fsblkcnt_t_defined
#define __fsblkcnt_t_defined 1
typedef uint64_t fsblkcnt_t;    /* File system block count */
#endif

#ifndef __fsfilcnt_t_defined
#define __fsfilcnt_t_defined 1
typedef uint64_t fsfilcnt_t;    /* File system file count */
#endif

/* ============================================================
 *   Size Types
 * ============================================================ */

#ifndef __ssize_t_defined
#define __ssize_t_defined 1
typedef int64_t ssize_t;        /* Signed size type */
#endif

/* ============================================================
 *   Socket/IPC Types
 * ============================================================ */

#ifndef __socklen_t_defined
#define __socklen_t_defined 1
typedef uint32_t socklen_t;     /* Socket address length */
#endif

#ifndef __sa_family_t_defined
#define __sa_family_t_defined 1
typedef uint16_t sa_family_t;   /* Socket address family */
#endif

#ifndef __in_port_t_defined
#define __in_port_t_defined 1
typedef uint16_t in_port_t;     /* IP port number */
#endif

#ifndef __in_addr_t_defined
#define __in_addr_t_defined 1
typedef uint32_t in_addr_t;     /* IPv4 address */
#endif

#ifndef __key_t_defined
#define __key_t_defined 1
typedef int32_t key_t;          /* System V IPC key */
#endif

/* ============================================================
 *   Miscellaneous Types
 * ============================================================ */

#ifndef __useconds_t_defined
#define __useconds_t_defined 1
typedef uint32_t useconds_t;    /* Microseconds */
#endif

#ifndef __suseconds_t_defined
#define __suseconds_t_defined 1
typedef int64_t suseconds_t;    /* Signed microseconds */
#endif

/* ============================================================
 *   Major/Minor Device Number Macros
 * ============================================================ */

#ifndef major
#define major(dev)      ((unsigned int)(((dev) >> 8) & 0xff))
#endif

#ifndef minor
#define minor(dev)      ((unsigned int)((dev) & 0xff))
#endif

#ifndef makedev
#define makedev(maj, min)   ((dev_t)(((maj) << 8) | ((min) & 0xff)))
#endif

/* Extended macros for Linux-style device numbers (12-bit major, 20-bit minor) */
#ifndef gnu_dev_major
#define gnu_dev_major(dev)      ((unsigned int)(((dev) >> 8) & 0xfff))
#endif

#ifndef gnu_dev_minor
#define gnu_dev_minor(dev)      ((unsigned int)(((dev) & 0xff) | (((dev) >> 12) & 0xfff00)))
#endif

#ifndef gnu_dev_makedev
#define gnu_dev_makedev(maj, min) \
    ((dev_t)(((min) & 0xff) | (((maj) & 0xfff) << 8) | (((min) & ~0xff) << 12)))
#endif

