// SPDX-License-Identifier: MPL-2.0
/*
 * fcntl.h - File control operations
 *
 * Copyright (c) 2025 Kelsi Davis
 * Licensed under the MPL v2.0 — see LICENSE for details.
 *
 * Provides file control constants, flags for open(), fcntl(),
 * and *at() family of syscalls.
 */

#pragma once

#include <stdint.h>
#include <sys/types.h>  /* For mode_t */

/* ============================================================
 *   File Access Modes (mutually exclusive)
 * ============================================================ */

#ifndef O_RDONLY
#define O_RDONLY    00000000    /* Open for reading only */
#endif
#ifndef O_WRONLY
#define O_WRONLY    00000001    /* Open for writing only */
#endif
#ifndef O_RDWR
#define O_RDWR      00000002    /* Open for reading and writing */
#endif
#ifndef O_ACCMODE
#define O_ACCMODE   00000003    /* Mask for file access modes */
#endif

/* ============================================================
 *   File Creation and Status Flags
 * ============================================================ */

#ifndef O_CREAT
#define O_CREAT     00000100    /* Create file if it doesn't exist */
#endif
#ifndef O_EXCL
#define O_EXCL      00000200    /* Exclusive use flag (fail if exists) */
#endif
#ifndef O_NOCTTY
#define O_NOCTTY    00000400    /* Do not assign controlling terminal */
#endif
#ifndef O_TRUNC
#define O_TRUNC     00001000    /* Truncate file to zero length */
#endif
#ifndef O_APPEND
#define O_APPEND    00002000    /* Append mode */
#endif
#ifndef O_NONBLOCK
#define O_NONBLOCK  00004000    /* Non-blocking mode */
#endif
#ifndef O_DSYNC
#define O_DSYNC     00010000    /* Synchronized data writes */
#endif
#ifndef O_SYNC
#define O_SYNC      00010000    /* Synchronous writes */
#endif
#ifndef O_RSYNC
#define O_RSYNC     00010000    /* Synchronized read operations */
#endif
#ifndef O_DIRECTORY
#define O_DIRECTORY 00200000    /* Must be a directory */
#endif
#ifndef O_NOFOLLOW
#define O_NOFOLLOW  00400000    /* Don't follow symbolic links */
#endif
#ifndef O_CLOEXEC
#define O_CLOEXEC   02000000    /* Close on exec */
#endif
#ifndef O_TMPFILE
#define O_TMPFILE   (020000000 | O_DIRECTORY)  /* Create unnamed temporary file */
#endif
#ifndef O_NDELAY
#define O_NDELAY    O_NONBLOCK  /* Alias for O_NONBLOCK */
#endif
#ifndef O_LARGEFILE
#define O_LARGEFILE 00100000    /* Allow large files (>2GB) */
#endif
#ifndef O_DIRECT
#define O_DIRECT    00040000    /* Direct I/O (bypass page cache) */
#endif
#ifndef O_NOATIME
#define O_NOATIME   01000000    /* Don't update access time */
#endif
#ifndef O_PATH
#define O_PATH      010000000   /* Open for path operations only */
#endif

/* ============================================================
 *   AT_* Constants for *at() Syscalls
 * ============================================================ */

#ifndef AT_FDCWD
#define AT_FDCWD            (-100)  /* Use current working directory */
#endif
#ifndef AT_SYMLINK_NOFOLLOW
#define AT_SYMLINK_NOFOLLOW 0x100   /* Don't follow symbolic links */
#endif
#ifndef AT_REMOVEDIR
#define AT_REMOVEDIR        0x200   /* Remove directory instead of file */
#endif
#ifndef AT_SYMLINK_FOLLOW
#define AT_SYMLINK_FOLLOW   0x400   /* Follow symbolic links */
#endif
#ifndef AT_NO_AUTOMOUNT
#define AT_NO_AUTOMOUNT     0x800   /* Don't trigger automount */
#endif
#ifndef AT_EMPTY_PATH
#define AT_EMPTY_PATH       0x1000  /* Allow empty pathname (operate on fd itself) */
#endif
#ifndef AT_EACCESS
#define AT_EACCESS          0x200   /* Test access using effective IDs */
#endif

/* ============================================================
 *   fcntl() Commands
 * ============================================================ */

#ifndef F_DUPFD
#define F_DUPFD         0   /* Duplicate file descriptor */
#endif
#ifndef F_GETFD
#define F_GETFD         1   /* Get file descriptor flags */
#endif
#ifndef F_SETFD
#define F_SETFD         2   /* Set file descriptor flags */
#endif
#ifndef F_GETFL
#define F_GETFL         3   /* Get file status flags */
#endif
#ifndef F_SETFL
#define F_SETFL         4   /* Set file status flags */
#endif
#ifndef F_GETLK
#define F_GETLK         5   /* Get record locking information */
#endif
#ifndef F_SETLK
#define F_SETLK         6   /* Set record locking information */
#endif
#ifndef F_SETLKW
#define F_SETLKW        7   /* Set record locking; wait if blocked */
#endif
#ifndef F_SETOWN
#define F_SETOWN        8   /* Set process/group to receive SIGIO */
#endif
#ifndef F_GETOWN
#define F_GETOWN        9   /* Get process/group receiving SIGIO */
#endif
#ifndef F_SETSIG
#define F_SETSIG        10  /* Set signal to be sent */
#endif
#ifndef F_GETSIG
#define F_GETSIG        11  /* Get signal to be sent */
#endif
#ifndef F_DUPFD_CLOEXEC
#define F_DUPFD_CLOEXEC 1030 /* Duplicate FD with close-on-exec */
#endif

/* ============================================================
 *   File Descriptor Flags
 * ============================================================ */

#ifndef FD_CLOEXEC
#define FD_CLOEXEC      1   /* Close on exec */
#endif

/* ============================================================
 *   Advisory Locking (flock constants)
 * ============================================================ */

#ifndef LOCK_SH
#define LOCK_SH         1   /* Shared lock */
#endif
#ifndef LOCK_EX
#define LOCK_EX         2   /* Exclusive lock */
#endif
#ifndef LOCK_NB
#define LOCK_NB         4   /* Don't block when locking */
#endif
#ifndef LOCK_UN
#define LOCK_UN         8   /* Unlock */
#endif

/* ============================================================
 *   Record Locking Structure
 * ============================================================ */

#ifndef _STRUCT_FLOCK
#define _STRUCT_FLOCK
struct flock {
    short l_type;       /* Type of lock: F_RDLCK, F_WRLCK, F_UNLCK */
    short l_whence;     /* How to interpret l_start: SEEK_SET, SEEK_CUR, SEEK_END */
    long  l_start;      /* Starting offset for lock */
    long  l_len;        /* Number of bytes to lock (0 = to EOF) */
    int   l_pid;        /* PID of process blocking our lock (F_GETLK only) */
};
#endif

/* Lock types for struct flock */
#ifndef F_RDLCK
#define F_RDLCK         0   /* Read lock */
#endif
#ifndef F_WRLCK
#define F_WRLCK         1   /* Write lock */
#endif
#ifndef F_UNLCK
#define F_UNLCK         2   /* Remove lock */
#endif

/* ============================================================
 *   Function Declarations
 * ============================================================ */

extern int fcntl(int fd, int cmd, ...);
extern int open(const char *pathname, int flags, ...);
extern int openat(int dirfd, const char *pathname, int flags, ...);
extern int creat(const char *pathname, mode_t mode);
