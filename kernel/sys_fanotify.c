/* kernel/sys_fanotify.c - fanotify filesystem notification
 *
 * Copyright (c) 2025 Kelsi Davis
 * Licensed under the MPL v2.0 — see LICENSE for details.
 *
 * Implements the fanotify API for filesystem event monitoring.
 * Used by antivirus scanners (ClamAV), file indexing (mlocate),
 * audit logging, and systemd for file access notifications.
 *
 * fanotify provides:
 *   - Mount-wide and filesystem-wide event monitoring
 *   - Access permission decisions (FAN_ACCESS_PERM, FAN_OPEN_PERM)
 *   - File identification via FAN_REPORT_FID
 *   - Directory event reporting (FAN_ONDIR)
 *
 * Syscall numbers (Linux x86_64):
 *   fanotify_init   300
 *   fanotify_mark   301
 */

#include <kernel/kprintf.h>
#include <kernel/errno.h>
#include <kernel/fut_task.h>
#include <kernel/fut_vfs.h>
#include <kernel/chrdev.h>
#include <kernel/uaccess.h>
#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>
#include <string.h>

#include <platform/platform.h>

/* Stage a user pathname into a kernel buffer of size out_size, including
 * the trailing NUL. Returns 0 on success, -EFAULT/-ENAMETOOLONG on error.
 * Bypasses uaccess only for kernel-side self-test pointers; never
 * dereferences a user pointer directly (the previous code used strcmp
 * straight on the user pointer, which let a caller hand the kernel a
 * kernel address as 'pathname' to read kernel memory or fault). */
static int fan_copy_user_path(const char *upath, char *kpath, size_t out_size) {
    if (!upath || out_size == 0) return -EINVAL;
#ifdef KERNEL_VIRTUAL_BASE
    if ((uintptr_t)upath >= KERNEL_VIRTUAL_BASE) {
        size_t i = 0;
        for (; i + 1 < out_size; i++) {
            kpath[i] = upath[i];
            if (upath[i] == '\0') return 0;
        }
        return -ENAMETOOLONG;
    }
#endif
    for (size_t i = 0; i + 1 < out_size; i++) {
        char c;
        if (fut_copy_from_user(&c, upath + i, 1) != 0) return -EFAULT;
        kpath[i] = c;
        if (c == '\0') return 0;
    }
    return -ENAMETOOLONG;
}

/* ── fanotify constants (Linux ABI) ── */

/* fanotify_init flags */
#define FAN_CLASS_NOTIF         0x00000000
#define FAN_CLASS_CONTENT       0x00000004
#define FAN_CLASS_PRE_CONTENT   0x00000008
#define FAN_CLOEXEC             0x00000001
#define FAN_NONBLOCK            0x00000002
#define FAN_UNLIMITED_QUEUE     0x00000010
#define FAN_UNLIMITED_MARKS     0x00000020
#define FAN_ENABLE_AUDIT        0x00000040
#define FAN_REPORT_TID          0x00000100
#define FAN_REPORT_FID          0x00000200
#define FAN_REPORT_DIR_FID      0x00000400
#define FAN_REPORT_NAME         0x00000800
#define FAN_REPORT_DFID_NAME    (FAN_REPORT_DIR_FID | FAN_REPORT_NAME)

/* fanotify_mark flags */
#define FAN_MARK_ADD            0x00000001
#define FAN_MARK_REMOVE         0x00000002
#define FAN_MARK_DONT_FOLLOW    0x00000004
#define FAN_MARK_ONLYDIR        0x00000008
#define FAN_MARK_INODE          0x00000000  /* default */
#define FAN_MARK_MOUNT          0x00000010
#define FAN_MARK_FILESYSTEM     0x00000100
#define FAN_MARK_IGNORED_MASK   0x00000020
#define FAN_MARK_IGNORED_SURV_MODIFY 0x00000040
#define FAN_MARK_FLUSH          0x00000080

/* Event mask bits */
#define FAN_ACCESS          0x00000001
#define FAN_MODIFY          0x00000002
#define FAN_ATTRIB          0x00000004
#define FAN_CLOSE_WRITE     0x00000008
#define FAN_CLOSE_NOWRITE   0x00000010
#define FAN_OPEN            0x00000020
#define FAN_MOVED_FROM      0x00000040
#define FAN_MOVED_TO        0x00000080
#define FAN_CREATE          0x00000100
#define FAN_DELETE           0x00000200
#define FAN_DELETE_SELF      0x00000400
#define FAN_MOVE_SELF        0x00000800
#define FAN_OPEN_EXEC        0x00001000
#define FAN_Q_OVERFLOW       0x00004000
#define FAN_OPEN_PERM        0x00010000
#define FAN_ACCESS_PERM      0x00020000
#define FAN_OPEN_EXEC_PERM   0x00040000
#define FAN_EVENT_ON_CHILD   0x08000000
#define FAN_ONDIR            0x40000000

#define FAN_CLOSE     (FAN_CLOSE_WRITE | FAN_CLOSE_NOWRITE)
#define FAN_MOVE      (FAN_MOVED_FROM | FAN_MOVED_TO)

#define FAN_ALL_EVENTS (FAN_ACCESS | FAN_MODIFY | FAN_CLOSE | FAN_OPEN | \
                        FAN_MOVE | FAN_CREATE | FAN_DELETE | FAN_DELETE_SELF | \
                        FAN_MOVE_SELF | FAN_OPEN_EXEC | FAN_ATTRIB)

/* Event metadata */
struct fanotify_event_metadata {
    uint32_t event_len;
    uint8_t  vers;
    uint8_t  reserved;
    uint16_t metadata_len;
    uint64_t mask;
    int32_t  fd;
    int32_t  pid;
};

#define FAN_EVENT_METADATA_LEN  sizeof(struct fanotify_event_metadata)
#define FANOTIFY_METADATA_VERSION 3

/* ── Internal state ── */

#define MAX_FANOTIFY_GROUPS   16
#define MAX_FANOTIFY_MARKS    64
#define MAX_FANOTIFY_EVENTS  256

struct fanotify_mark_entry {
    bool     active;
    uint64_t mask;              /* Event mask (FAN_ACCESS, FAN_MODIFY, ...) */
    uint64_t ignored_mask;      /* Ignored events mask */
    uint32_t flags;             /* FAN_MARK_MOUNT, etc. */
    char     path[256];         /* Monitored path (inode marks) */
};

struct fanotify_event {
    uint64_t mask;
    int32_t  fd;                /* FD pointing to the file (-1 if N/A) */
    int32_t  pid;               /* PID of the process causing the event */
};

struct fanotify_group {
    bool     active;
    int      group_fd;          /* fd in owner's fd_table */
    uint64_t owner_pid;
    uint32_t init_flags;        /* FAN_CLASS_*, FAN_CLOEXEC, etc. */
    uint32_t event_f_flags;     /* O_RDONLY, O_WRONLY, O_RDWR, O_LARGEFILE */

    /* Marks */
    struct fanotify_mark_entry marks[MAX_FANOTIFY_MARKS];
    uint32_t nr_marks;

    /* Event queue (ring buffer) */
    struct fanotify_event events[MAX_FANOTIFY_EVENTS];
    uint32_t event_head;
    uint32_t event_tail;
    uint32_t event_count;

    /* Overflow tracking */
    bool     overflow;
};

static struct fanotify_group fan_groups[MAX_FANOTIFY_GROUPS];

/* ── File operations ── */

static int fanotify_release(void *inode, void *priv) {
    (void)inode;
    struct fanotify_group *grp = (struct fanotify_group *)priv;
    if (grp) {
        grp->active = false;
        grp->nr_marks = 0;
        grp->event_count = 0;
    }
    return 0;
}

static const struct fut_file_ops fanotify_fops = {
    .release = fanotify_release,
};

/* ── Helpers ── */

static struct fanotify_group *fan_find_fd(int fd) {
    for (int i = 0; i < MAX_FANOTIFY_GROUPS; i++) {
        if (fan_groups[i].active && fan_groups[i].group_fd == fd)
            return &fan_groups[i];
    }
    return NULL;
}

/* Enqueue an event */
static void fan_enqueue_event(struct fanotify_group *grp, uint64_t mask,
                               int32_t fd, int32_t pid) {
    if (grp->event_count >= MAX_FANOTIFY_EVENTS) {
        grp->overflow = true;
        return;
    }
    uint32_t tail = grp->event_tail % MAX_FANOTIFY_EVENTS;
    grp->events[tail].mask = mask;
    grp->events[tail].fd = fd;
    grp->events[tail].pid = pid;
    grp->event_tail++;
    grp->event_count++;
}

/* ── Syscall implementations ── */

/**
 * fanotify_init() - Create a fanotify group.
 * @flags:        FAN_CLASS_* | FAN_CLOEXEC | FAN_NONBLOCK | ...
 * @event_f_flags: O_RDONLY | O_WRONLY | O_RDWR | O_LARGEFILE
 * Returns: file descriptor for the fanotify group, or negative errno.
 */
long sys_fanotify_init(unsigned int flags, unsigned int event_f_flags) {
    /* Permission check: content/pre-content classes need CAP_SYS_ADMIN */
    uint32_t fan_class = flags & 0x0C;
    if (fan_class == FAN_CLASS_CONTENT || fan_class == FAN_CLASS_PRE_CONTENT) {
        fut_task_t *task = fut_task_current();
        if (task && !(task->cap_effective & (1ULL << 21))) /* CAP_SYS_ADMIN */
            return -EPERM;
    }

    /* Find free slot */
    struct fanotify_group *grp = NULL;
    for (int i = 0; i < MAX_FANOTIFY_GROUPS; i++) {
        if (!fan_groups[i].active) { grp = &fan_groups[i]; break; }
    }
    if (!grp) return -EMFILE;

    memset(grp, 0, sizeof(*grp));
    grp->active = true;
    grp->init_flags = flags;
    grp->event_f_flags = event_f_flags;

    fut_task_t *task = fut_task_current();
    grp->owner_pid = task ? task->pid : 0;

    int fd = chrdev_alloc_fd(&fanotify_fops, NULL, grp);
    if (fd < 0) { grp->active = false; return fd; }
    grp->group_fd = fd;

    /* Apply FAN_CLOEXEC. Guard against tasks that haven't allocated
     * fd_flags (early init / kernel threads); pipe2, socketpair, dup3,
     * pidfd_open, and perf_event_open all check fd_flags non-NULL — the
     * previous code here would NULL-deref the kernel for any caller
     * without an fd_flags table. */
    if ((flags & FAN_CLOEXEC) && task && task->fd_flags && fd < task->max_fds)
        task->fd_flags[fd] |= 1;

    return fd;
}

/**
 * fanotify_mark() - Add/remove/modify a fanotify mark.
 * @fanotify_fd: fd from fanotify_init().
 * @flags:       FAN_MARK_ADD | FAN_MARK_REMOVE | FAN_MARK_FLUSH | ...
 * @mask:        Event mask (FAN_ACCESS, FAN_MODIFY, ...).
 * @dirfd:       Directory fd (AT_FDCWD for cwd).
 * @pathname:    Path to monitor (NULL for mount/filesystem marks).
 */
long sys_fanotify_mark(int fanotify_fd, unsigned int flags,
                       unsigned long mask, int dirfd, const char *pathname) {
    (void)dirfd;

    struct fanotify_group *grp = fan_find_fd(fanotify_fd);
    if (!grp) return -EBADF;

    /* Stage the user-supplied path into a kernel buffer up front so we
     * never strcmp/index a user pointer directly. */
    char kpath[256];
    bool have_path = false;
    if (pathname) {
        int rc = fan_copy_user_path(pathname, kpath, sizeof(kpath));
        if (rc < 0) return rc;
        have_path = true;
    }

    /* Handle FAN_MARK_FLUSH */
    if (flags & FAN_MARK_FLUSH) {
        for (uint32_t i = 0; i < MAX_FANOTIFY_MARKS; i++)
            grp->marks[i].active = false;
        grp->nr_marks = 0;
        return 0;
    }

    /* FAN_MARK_REMOVE */
    if (flags & FAN_MARK_REMOVE) {
        for (uint32_t i = 0; i < MAX_FANOTIFY_MARKS; i++) {
            if (!grp->marks[i].active) continue;
            if (have_path && strcmp(grp->marks[i].path, kpath) != 0) continue;
            if (flags & FAN_MARK_IGNORED_MASK) {
                grp->marks[i].ignored_mask &= ~mask;
            } else {
                grp->marks[i].mask &= ~mask;
                if (grp->marks[i].mask == 0) {
                    grp->marks[i].active = false;
                    grp->nr_marks--;
                }
            }
            return 0;
        }
        return -ENOENT;
    }

    /* FAN_MARK_ADD */
    if (flags & FAN_MARK_ADD) {
        /* Check if mark already exists for this path */
        for (uint32_t i = 0; i < MAX_FANOTIFY_MARKS; i++) {
            if (!grp->marks[i].active) continue;
            bool path_match = (!have_path && grp->marks[i].path[0] == '\0') ||
                              (have_path && strcmp(grp->marks[i].path, kpath) == 0);
            if (path_match) {
                if (flags & FAN_MARK_IGNORED_MASK) {
                    grp->marks[i].ignored_mask |= mask;
                } else {
                    grp->marks[i].mask |= mask;
                }
                return 0;
            }
        }

        /* Create new mark */
        if (grp->nr_marks >= MAX_FANOTIFY_MARKS) return -ENOSPC;
        for (uint32_t i = 0; i < MAX_FANOTIFY_MARKS; i++) {
            if (grp->marks[i].active) continue;
            grp->marks[i].active = true;
            grp->marks[i].mask = mask;
            grp->marks[i].ignored_mask = 0;
            grp->marks[i].flags = flags;
            if (have_path) {
                size_t j = 0;
                while (kpath[j] && j < sizeof(grp->marks[i].path) - 1) {
                    grp->marks[i].path[j] = kpath[j]; j++;
                }
                grp->marks[i].path[j] = '\0';
            } else {
                grp->marks[i].path[0] = '\0';
            }
            grp->nr_marks++;
            return 0;
        }
        return -ENOMEM;
    }

    return -EINVAL;
}

/**
 * fanotify_notify() - Kernel internal: notify fanotify groups of an event.
 * Called from VFS operations to deliver events.
 */
void fanotify_notify(const char *path, uint64_t event_mask, int32_t pid) {
    for (int g = 0; g < MAX_FANOTIFY_GROUPS; g++) {
        struct fanotify_group *grp = &fan_groups[g];
        if (!grp->active) continue;

        for (uint32_t m = 0; m < MAX_FANOTIFY_MARKS; m++) {
            if (!grp->marks[m].active) continue;

            /* Check if path matches */
            bool match = false;
            if (grp->marks[m].path[0] == '\0') {
                match = true; /* Mount/filesystem-wide mark */
            } else if (path) {
                /* Prefix match for directory marks, exact for file marks */
                int plen = 0;
                while (grp->marks[m].path[plen]) plen++;
                if (memcmp(path, grp->marks[m].path, (size_t)plen) == 0 &&
                    (path[plen] == '\0' || path[plen] == '/'))
                    match = true;
            }
            if (!match) continue;

            /* Check event mask */
            uint64_t effective = grp->marks[m].mask & ~grp->marks[m].ignored_mask;
            if (effective & event_mask) {
                fan_enqueue_event(grp, event_mask & effective, -1, pid);
                break; /* One notification per group per event */
            }
        }
    }
}
