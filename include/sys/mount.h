// SPDX-License-Identifier: MPL-2.0
/*
 * sys/mount.h - Mount operations
 *
 * Copyright (c) 2025 Kelsi Davis
 * Licensed under the MPL v2.0 — see LICENSE for details.
 *
 * Provides constants for mount(), umount(), and related filesystem
 * mounting operations.
 */

#pragma once

#include <stdint.h>

/* ============================================================
 *   Mount Flags
 * ============================================================ */

#ifndef MS_RDONLY
#define MS_RDONLY       1       /* Mount read-only */
#endif
#ifndef MS_NOSUID
#define MS_NOSUID       2       /* Ignore suid and sgid bits */
#endif
#ifndef MS_NODEV
#define MS_NODEV        4       /* Disallow access to device special files */
#endif
#ifndef MS_NOEXEC
#define MS_NOEXEC       8       /* Disallow program execution */
#endif
#ifndef MS_SYNCHRONOUS
#define MS_SYNCHRONOUS  16      /* Writes are synced at once */
#endif
#ifndef MS_REMOUNT
#define MS_REMOUNT      32      /* Alter flags of a mounted filesystem */
#endif
#ifndef MS_MANDLOCK
#define MS_MANDLOCK     64      /* Allow mandatory locks */
#endif
#ifndef MS_DIRSYNC
#define MS_DIRSYNC      128     /* Directory modifications are synchronous */
#endif
#ifndef MS_NOSYMFOLLOW
#define MS_NOSYMFOLLOW  256     /* Don't follow symlinks */
#endif
#ifndef MS_NOATIME
#define MS_NOATIME      1024    /* Do not update access times */
#endif
#ifndef MS_NODIRATIME
#define MS_NODIRATIME   2048    /* Do not update directory access times */
#endif
#ifndef MS_BIND
#define MS_BIND         4096    /* Bind directory at different place */
#endif
#ifndef MS_MOVE
#define MS_MOVE         8192    /* Atomically move mounted tree */
#endif
#ifndef MS_REC
#define MS_REC          16384   /* Recursive (for bind and move) */
#endif
#ifndef MS_SILENT
#define MS_SILENT       32768   /* Suppress certain printk warning messages */
#endif
#ifndef MS_POSIXACL
#define MS_POSIXACL     (1 << 16)   /* VFS does not apply the umask */
#endif
#ifndef MS_UNBINDABLE
#define MS_UNBINDABLE   (1 << 17)   /* Change to unbindable */
#endif
#ifndef MS_PRIVATE
#define MS_PRIVATE      (1 << 18)   /* Change to private */
#endif
#ifndef MS_SLAVE
#define MS_SLAVE        (1 << 19)   /* Change to slave */
#endif
#ifndef MS_SHARED
#define MS_SHARED       (1 << 20)   /* Change to shared */
#endif
#ifndef MS_RELATIME
#define MS_RELATIME     (1 << 21)   /* Update atime relative to mtime/ctime */
#endif
#ifndef MS_KERNMOUNT
#define MS_KERNMOUNT    (1 << 22)   /* This is a kernel-internal mount */
#endif
#ifndef MS_I_VERSION
#define MS_I_VERSION    (1 << 23)   /* Update inode I_version field */
#endif
#ifndef MS_STRICTATIME
#define MS_STRICTATIME  (1 << 24)   /* Always perform atime updates */
#endif
#ifndef MS_LAZYTIME
#define MS_LAZYTIME     (1 << 25)   /* Update timestamps lazily */
#endif

/* ============================================================
 *   Umount Flags
 * ============================================================ */

#ifndef MNT_FORCE
#define MNT_FORCE       1       /* Force unmount even if busy */
#endif
#ifndef MNT_DETACH
#define MNT_DETACH      2       /* Lazy unmount */
#endif
#ifndef MNT_EXPIRE
#define MNT_EXPIRE      4       /* Mark for expiry */
#endif
#ifndef UMOUNT_NOFOLLOW
#define UMOUNT_NOFOLLOW 8       /* Don't follow symlinks */
#endif

/* ============================================================
 *   Function Declarations
 * ============================================================ */

extern int mount(const char *source, const char *target,
                 const char *filesystemtype, unsigned long mountflags,
                 const void *data);
extern int umount(const char *target);
extern int umount2(const char *target, int flags);

