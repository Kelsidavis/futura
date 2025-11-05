/* kernel/sys_inotify.c - File system monitoring syscalls
 *
 * Copyright (c) 2025 Kelsi Davis
 * Licensed under the MPL v2.0 — see LICENSE for details.
 *
 * Implements inotify syscalls for monitoring file system events.
 * Essential for file managers, build systems, and any application that needs
 * to react to file system changes.
 *
 * Phase 1 (Current): Validation and stub implementations
 * Phase 2: Implement inotify event queue and watch management
 * Phase 3: Integrate with VFS for actual file system monitoring
 * Phase 4: Performance optimization with efficient event delivery
 */

#include <kernel/fut_task.h>
#include <kernel/errno.h>
#include <stdint.h>

extern void fut_printf(const char *fmt, ...);

/* inotify_init1 flags */
#define IN_CLOEXEC  02000000  /* Close on exec */
#define IN_NONBLOCK 00004000  /* Non-blocking */

/* inotify event masks */
#define IN_ACCESS        0x00000001  /* File was accessed */
#define IN_MODIFY        0x00000002  /* File was modified */
#define IN_ATTRIB        0x00000004  /* Metadata changed */
#define IN_CLOSE_WRITE   0x00000008  /* Writable file closed */
#define IN_CLOSE_NOWRITE 0x00000010  /* Unwritable file closed */
#define IN_OPEN          0x00000020  /* File was opened */
#define IN_MOVED_FROM    0x00000040  /* File moved from */
#define IN_MOVED_TO      0x00000080  /* File moved to */
#define IN_CREATE        0x00000100  /* File/directory created */
#define IN_DELETE        0x00000200  /* File/directory deleted */
#define IN_DELETE_SELF   0x00000400  /* Watched file/directory deleted */
#define IN_MOVE_SELF     0x00000800  /* Watched file/directory moved */

/* Special flags */
#define IN_UNMOUNT       0x00002000  /* Filesystem unmounted */
#define IN_Q_OVERFLOW    0x00004000  /* Event queue overflowed */
#define IN_IGNORED       0x00008000  /* Watch was removed */

/* Watch flags */
#define IN_ONLYDIR       0x01000000  /* Only watch if directory */
#define IN_DONT_FOLLOW   0x02000000  /* Don't follow symlinks */
#define IN_EXCL_UNLINK   0x04000000  /* Exclude events on unlinked objects */
#define IN_MASK_ADD      0x20000000  /* Add to existing watch mask */
#define IN_ISDIR         0x40000000  /* Event occurred on directory */
#define IN_ONESHOT       0x80000000  /* Only send event once */

/* Combined events */
#define IN_CLOSE         (IN_CLOSE_WRITE | IN_CLOSE_NOWRITE)  /* Close */
#define IN_MOVE          (IN_MOVED_FROM | IN_MOVED_TO)        /* Move */

/* All events */
#define IN_ALL_EVENTS    (IN_ACCESS | IN_MODIFY | IN_ATTRIB | IN_CLOSE_WRITE | \
                          IN_CLOSE_NOWRITE | IN_OPEN | IN_MOVED_FROM | \
                          IN_MOVED_TO | IN_CREATE | IN_DELETE | \
                          IN_DELETE_SELF | IN_MOVE_SELF)

/**
 * inotify_init1() - Create inotify instance
 *
 * Creates and initializes an inotify instance and returns a file descriptor
 * referring to the inotify instance. The inotify instance is used to monitor
 * file system events.
 *
 * @param flags  IN_CLOEXEC (close on exec) or IN_NONBLOCK (non-blocking)
 *
 * Returns:
 *   - File descriptor on success
 *   - -EINVAL if flags contains invalid values
 *   - -EMFILE if per-process fd limit reached
 *   - -ENFILE if system-wide fd limit reached
 *   - -ENOMEM if insufficient memory
 *
 * Usage:
 *   int fd = inotify_init1(IN_CLOEXEC | IN_NONBLOCK);
 *   if (fd < 0) perror("inotify_init1");
 *
 * The returned file descriptor can be used with inotify_add_watch() to add
 * watches and with read() to receive events. Events are read as struct
 * inotify_event from the file descriptor.
 *
 * Phase 1: Validate flags and return dummy fd
 * Phase 2: Create actual inotify instance with event queue
 */
long sys_inotify_init1(int flags) {
    fut_task_t *task = fut_task_current();
    if (!task) {
        fut_printf("[INOTIFY] inotify_init1(flags=0x%x) -> ESRCH (no current task)\n", flags);
        return -ESRCH;
    }

    /* Validate flags */
    const int VALID_FLAGS = IN_CLOEXEC | IN_NONBLOCK;
    if (flags & ~VALID_FLAGS) {
        fut_printf("[INOTIFY] inotify_init1(flags=0x%x, pid=%d) -> EINVAL (invalid flags)\n",
                   flags, task->pid);
        return -EINVAL;
    }

    /* Categorize flags */
    const char *flags_desc;
    if (flags == 0) {
        flags_desc = "none";
    } else if (flags == IN_CLOEXEC) {
        flags_desc = "IN_CLOEXEC";
    } else if (flags == IN_NONBLOCK) {
        flags_desc = "IN_NONBLOCK";
    } else if (flags == (IN_CLOEXEC | IN_NONBLOCK)) {
        flags_desc = "IN_CLOEXEC | IN_NONBLOCK";
    } else {
        flags_desc = "combination";
    }

    /* Phase 1: Return dummy fd */
    int dummy_fd = 42;  /* Placeholder fd */
    fut_printf("[INOTIFY] inotify_init1(flags=%s, pid=%d) -> %d "
               "(Phase 1 stub - no actual monitoring yet)\n",
               flags_desc, task->pid, dummy_fd);

    return dummy_fd;
}

/**
 * inotify_add_watch() - Add watch to inotify instance
 *
 * Adds a watch to an inotify instance to monitor events on a pathname.
 * If the pathname is already being watched, the mask is updated.
 *
 * @param fd        File descriptor from inotify_init1()
 * @param pathname  Path to monitor
 * @param mask      Events to monitor (IN_ACCESS, IN_MODIFY, etc.)
 *
 * Returns:
 *   - Watch descriptor (non-negative) on success
 *   - -EBADF if fd is not valid inotify instance
 *   - -EFAULT if pathname points to inaccessible memory
 *   - -EINVAL if mask has no valid events
 *   - -ENAMETOOLONG if pathname too long
 *   - -ENOENT if pathname component doesn't exist
 *   - -ENOMEM if insufficient memory
 *   - -ENOSPC if watch limit reached
 *
 * Usage:
 *   int wd = inotify_add_watch(fd, "/tmp/test", IN_MODIFY | IN_CREATE);
 *   if (wd < 0) perror("inotify_add_watch");
 *
 * The watch descriptor can be used to identify events when reading from the
 * inotify fd and can be passed to inotify_rm_watch() to remove the watch.
 *
 * Phase 1: Validate parameters and return dummy watch descriptor
 * Phase 2: Create actual watch and register with VFS
 */
long sys_inotify_add_watch(int fd, const char *pathname, uint32_t mask) {
    fut_task_t *task = fut_task_current();
    if (!task) {
        return -ESRCH;
    }

    /* Validate fd */
    if (fd < 0) {
        fut_printf("[INOTIFY] inotify_add_watch(fd=%d [invalid], pathname=%p, mask=0x%x, pid=%d) "
                   "-> EBADF\n", fd, pathname, mask, task->pid);
        return -EBADF;
    }

    /* Validate pathname */
    if (!pathname) {
        fut_printf("[INOTIFY] inotify_add_watch(fd=%d, pathname=NULL, mask=0x%x, pid=%d) "
                   "-> EFAULT\n", fd, mask, task->pid);
        return -EFAULT;
    }

    /* Validate mask has at least one valid event */
    if ((mask & IN_ALL_EVENTS) == 0 && (mask & (IN_DONT_FOLLOW | IN_ONLYDIR | IN_MASK_ADD | IN_ONESHOT)) == mask) {
        fut_printf("[INOTIFY] inotify_add_watch(fd=%d, pathname=%p, mask=0x%x [no events], pid=%d) "
                   "-> EINVAL\n", fd, pathname, mask, task->pid);
        return -EINVAL;
    }

    /* Categorize event mask */
    const char *mask_desc;
    if (mask & IN_ALL_EVENTS) {
        if ((mask & IN_ALL_EVENTS) == IN_ALL_EVENTS) {
            mask_desc = "ALL_EVENTS";
        } else if (mask & (IN_MODIFY | IN_CREATE | IN_DELETE)) {
            mask_desc = "file changes (modify/create/delete)";
        } else if (mask & (IN_ACCESS | IN_OPEN | IN_CLOSE)) {
            mask_desc = "access events (access/open/close)";
        } else if (mask & (IN_MOVED_FROM | IN_MOVED_TO)) {
            mask_desc = "move events";
        } else {
            mask_desc = "custom event set";
        }
    } else {
        mask_desc = "flags only (ONLYDIR/DONT_FOLLOW/etc)";
    }

    /* Phase 1: Return dummy watch descriptor */
    int dummy_wd = 1;  /* Placeholder watch descriptor */
    fut_printf("[INOTIFY] inotify_add_watch(fd=%d, pathname=%p, mask=%s, pid=%d) -> %d "
               "(Phase 1 stub - no actual watch created)\n",
               fd, pathname, mask_desc, task->pid, dummy_wd);

    return dummy_wd;
}

/**
 * inotify_rm_watch() - Remove watch from inotify instance
 *
 * Removes a watch from an inotify instance. The watch descriptor becomes
 * invalid after removal and an IN_IGNORED event is generated.
 *
 * @param fd  File descriptor from inotify_init1()
 * @param wd  Watch descriptor from inotify_add_watch()
 *
 * Returns:
 *   - 0 on success
 *   - -EBADF if fd is not valid inotify instance
 *   - -EINVAL if wd is not valid watch descriptor
 *
 * Usage:
 *   if (inotify_rm_watch(fd, wd) < 0) perror("inotify_rm_watch");
 *
 * Phase 1: Validate parameters and return success
 * Phase 2: Actually remove watch from VFS monitoring
 */
long sys_inotify_rm_watch(int fd, int wd) {
    fut_task_t *task = fut_task_current();
    if (!task) {
        return -ESRCH;
    }

    /* Validate fd */
    if (fd < 0) {
        fut_printf("[INOTIFY] inotify_rm_watch(fd=%d [invalid], wd=%d, pid=%d) -> EBADF\n",
                   fd, wd, task->pid);
        return -EBADF;
    }

    /* Validate wd */
    if (wd < 0) {
        fut_printf("[INOTIFY] inotify_rm_watch(fd=%d, wd=%d [invalid], pid=%d) -> EINVAL\n",
                   fd, wd, task->pid);
        return -EINVAL;
    }

    /* Phase 1: Accept removal */
    fut_printf("[INOTIFY] inotify_rm_watch(fd=%d, wd=%d, pid=%d) -> 0 "
               "(Phase 1 stub - no actual watch removed)\n", fd, wd, task->pid);

    return 0;
}
