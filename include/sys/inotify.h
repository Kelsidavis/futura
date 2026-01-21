// SPDX-License-Identifier: MPL-2.0
/*
 * sys/inotify.h - File system event monitoring
 *
 * Copyright (c) 2025 Kelsi Davis
 * Licensed under the MPL v2.0 — see LICENSE for details.
 *
 * Provides the inotify interface for monitoring file system events.
 * Essential for file managers, build systems, and applications that
 * need to react to file system changes.
 */

#pragma once

#include <stdint.h>

/* ============================================================
 *   inotify_init1 Flags
 * ============================================================ */

#ifndef IN_CLOEXEC
#define IN_CLOEXEC      02000000    /* Close on exec */
#endif
#ifndef IN_NONBLOCK
#define IN_NONBLOCK     00004000    /* Non-blocking */
#endif

/* ============================================================
 *   Event Mask Constants
 * ============================================================ */

/* File/directory events */
#ifndef IN_ACCESS
#define IN_ACCESS           0x00000001  /* File was accessed (read) */
#endif
#ifndef IN_MODIFY
#define IN_MODIFY           0x00000002  /* File was modified (write) */
#endif
#ifndef IN_ATTRIB
#define IN_ATTRIB           0x00000004  /* Metadata changed (permissions, timestamps, etc.) */
#endif
#ifndef IN_CLOSE_WRITE
#define IN_CLOSE_WRITE      0x00000008  /* Writable file was closed */
#endif
#ifndef IN_CLOSE_NOWRITE
#define IN_CLOSE_NOWRITE    0x00000010  /* Non-writable file was closed */
#endif
#ifndef IN_OPEN
#define IN_OPEN             0x00000020  /* File was opened */
#endif
#ifndef IN_MOVED_FROM
#define IN_MOVED_FROM       0x00000040  /* File was moved out of watched directory */
#endif
#ifndef IN_MOVED_TO
#define IN_MOVED_TO         0x00000080  /* File was moved into watched directory */
#endif
#ifndef IN_CREATE
#define IN_CREATE           0x00000100  /* File/directory was created */
#endif
#ifndef IN_DELETE
#define IN_DELETE           0x00000200  /* File/directory was deleted */
#endif
#ifndef IN_DELETE_SELF
#define IN_DELETE_SELF      0x00000400  /* Watched file/directory was deleted */
#endif
#ifndef IN_MOVE_SELF
#define IN_MOVE_SELF        0x00000800  /* Watched file/directory was moved */
#endif

/* Special events (returned in revents only) */
#ifndef IN_UNMOUNT
#define IN_UNMOUNT          0x00002000  /* Filesystem containing watched object was unmounted */
#endif
#ifndef IN_Q_OVERFLOW
#define IN_Q_OVERFLOW       0x00004000  /* Event queue overflowed (wd is -1) */
#endif
#ifndef IN_IGNORED
#define IN_IGNORED          0x00008000  /* Watch was removed (explicitly or implicitly) */
#endif

/* Watch flags (for inotify_add_watch) */
#ifndef IN_ONLYDIR
#define IN_ONLYDIR          0x01000000  /* Only watch if target is directory */
#endif
#ifndef IN_DONT_FOLLOW
#define IN_DONT_FOLLOW      0x02000000  /* Don't dereference symbolic links */
#endif
#ifndef IN_EXCL_UNLINK
#define IN_EXCL_UNLINK      0x04000000  /* Exclude events on unlinked objects */
#endif
#ifndef IN_MASK_CREATE
#define IN_MASK_CREATE      0x10000000  /* Don't modify existing watch, fail if exists */
#endif
#ifndef IN_MASK_ADD
#define IN_MASK_ADD         0x20000000  /* Add events to existing watch mask */
#endif
#ifndef IN_ISDIR
#define IN_ISDIR            0x40000000  /* Event subject is a directory */
#endif
#ifndef IN_ONESHOT
#define IN_ONESHOT          0x80000000  /* Remove watch after one event */
#endif

/* ============================================================
 *   Combined Event Masks
 * ============================================================ */

#ifndef IN_CLOSE
#define IN_CLOSE            (IN_CLOSE_WRITE | IN_CLOSE_NOWRITE)
#endif
#ifndef IN_MOVE
#define IN_MOVE             (IN_MOVED_FROM | IN_MOVED_TO)
#endif

/* All standard events */
#ifndef IN_ALL_EVENTS
#define IN_ALL_EVENTS       (IN_ACCESS | IN_MODIFY | IN_ATTRIB | \
                             IN_CLOSE_WRITE | IN_CLOSE_NOWRITE | IN_OPEN | \
                             IN_MOVED_FROM | IN_MOVED_TO | IN_CREATE | \
                             IN_DELETE | IN_DELETE_SELF | IN_MOVE_SELF)
#endif

/* ============================================================
 *   Event Structure
 * ============================================================ */

#ifndef _STRUCT_INOTIFY_EVENT
#define _STRUCT_INOTIFY_EVENT
struct inotify_event {
    int      wd;        /* Watch descriptor */
    uint32_t mask;      /* Mask describing event */
    uint32_t cookie;    /* Unique cookie associating related events (for rename) */
    uint32_t len;       /* Length (including nulls) of name */
    char     name[];    /* Optional null-terminated name */
};
#endif

/* ============================================================
 *   Function Declarations
 * ============================================================ */

/**
 * inotify_init - Create inotify instance (legacy)
 *
 * Equivalent to inotify_init1(0).
 *
 * Returns inotify file descriptor, or -1 on error.
 */
extern int inotify_init(void);

/**
 * inotify_init1 - Create inotify instance with flags
 *
 * @flags  IN_CLOEXEC, IN_NONBLOCK, or 0
 *
 * Returns inotify file descriptor, or -1 on error.
 */
extern int inotify_init1(int flags);

/**
 * inotify_add_watch - Add watch for file/directory
 *
 * @fd       inotify file descriptor
 * @pathname Path to watch
 * @mask     Events to watch for (IN_ACCESS, IN_MODIFY, etc.)
 *
 * Returns watch descriptor on success, -1 on error.
 */
extern int inotify_add_watch(int fd, const char *pathname, uint32_t mask);

/**
 * inotify_rm_watch - Remove watch from inotify instance
 *
 * @fd  inotify file descriptor
 * @wd  Watch descriptor to remove
 *
 * Returns 0 on success, -1 on error.
 */
extern int inotify_rm_watch(int fd, int wd);

