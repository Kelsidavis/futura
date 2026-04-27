/* kernel/sys_inotify.c - File system monitoring syscalls
 *
 * Copyright (c) 2025 Kelsi Davis
 * Licensed under the MPL v2.0 — see LICENSE for details.
 *
 * Implements inotify syscalls for monitoring file system events.
 * Essential for file managers, build systems, and any application that needs
 * to react to file system changes.
 *
 * Phase 1 (Completed): Validation and stub implementations
 * Phase 2 (Completed): Enhanced validation, parameter categorization, user-space data handling
 * Phase 3 (Completed): Inotify FD with event queue and watch list; read() support
 * Phase 4 (Completed): Global registry + inotify_dispatch_event() for VFS event delivery
 * Phase 5 (Completed): Filename field in events (Linux ABI: name + null + padding to 4B boundary)
 */

#include <kernel/chrdev.h>
#include <kernel/fut_memory.h>
#include <kernel/fut_sched.h>
#include <kernel/fut_task.h>
#include <sys/epoll.h>
#include <kernel/fut_thread.h>
#include <kernel/fut_vfs.h>
#include <kernel/fut_waitq.h>
#include <kernel/errno.h>
#include <stdint.h>
#include <stdbool.h>
#include <string.h>
#include <limits.h>

#include <kernel/kprintf.h>
#include <kernel/uaccess.h>
#include <fcntl.h>
#include <platform/platform.h>

static inline int inotify_copy_from_user(void *dst, const void *src, size_t n) {
#ifdef KERNEL_VIRTUAL_BASE
    if ((uintptr_t)src >= KERNEL_VIRTUAL_BASE) { __builtin_memcpy(dst, src, n); return 0; }
#endif
    return fut_copy_from_user(dst, src, n);
}

static inline int inotify_copy_to_user(void *dst, const void *src, size_t n) {
#ifdef KERNEL_VIRTUAL_BASE
    if ((uintptr_t)dst >= KERNEL_VIRTUAL_BASE) { __builtin_memcpy(dst, src, n); return 0; }
#endif
    return fut_copy_to_user(dst, src, n);
}

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
#define IN_MASK_CREATE   0x10000000  /* Fail with EEXIST if watch exists (Linux 4.18+) */
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

/* Max watches per inotify instance */
#define INOTIFY_MAX_WATCHES   256
/* Max queued events per inotify instance */
#define INOTIFY_MAX_EVENTS    256
/* Max path length for a watched path */
#define INOTIFY_PATH_MAX      256

/* inotify event struct (matches Linux ABI) */
struct inotify_event {
    int      wd;       /* Watch descriptor */
    uint32_t mask;     /* Mask describing event */
    uint32_t cookie;   /* Unique cookie for renames */
    uint32_t len;      /* Length (including nulls) of name */
    char     name[];   /* Optional null-terminated name */
};

/* Per-watch entry */
struct inotify_watch {
    int      wd;                      /* Watch descriptor (1-based) */
    uint32_t mask;                    /* Events to monitor */
    char     path[INOTIFY_PATH_MAX];  /* Watched path */
};

/* Queued event with optional filename (Phase 5: includes entry name for dir watches) */
struct inotify_queued_event {
    int      wd;
    uint32_t mask;
    uint32_t cookie;
    char     name[NAME_MAX + 1];  /* basename of affected entry; empty for self-events */
};

/* Compute inotify name length: strlen+1 rounded up to next 4-byte boundary (Linux ABI) */
static inline uint32_t inotify_name_padlen(const char *name) {
    if (!name || name[0] == '\0') return 0;
    size_t slen = strlen(name);
    if (slen > NAME_MAX) slen = NAME_MAX;
    return (uint32_t)(((slen + 1u) + 3u) & ~3u);  /* round up to 4-byte boundary */
}

/* Per-inotify-FD instance */
struct inotify_instance {
    fut_spinlock_t          lock;
    fut_waitq_t             read_waitq;
    fut_waitq_t            *epoll_notify;  /* epoll/poll/select wakeup (NULL if none) */
    struct fut_file        *file;
    int                     next_wd;       /* Next watch descriptor to assign */
    int                     watch_count;
    struct inotify_watch    watches[INOTIFY_MAX_WATCHES];
    /* Circular event queue */
    int                     ev_head;
    int                     ev_tail;
    int                     ev_count;
    struct inotify_queued_event events[INOTIFY_MAX_EVENTS];
};

/* Phase 4: Global registry of all active inotify instances for VFS dispatch */
struct inotify_registry_entry {
    struct inotify_instance        *inst;
    struct inotify_registry_entry  *next;
};
static struct inotify_registry_entry *g_inotify_registry = NULL;
static fut_spinlock_t                 g_inotify_registry_lock;
static bool                           g_inotify_registry_init = false;

static void inotify_registry_add(struct inotify_instance *inst) {
    if (!g_inotify_registry_init) {
        fut_spinlock_init(&g_inotify_registry_lock);
        g_inotify_registry_init = true;
    }
    struct inotify_registry_entry *entry = fut_malloc(sizeof(*entry));
    if (!entry) return;
    entry->inst = inst;
    fut_spinlock_acquire(&g_inotify_registry_lock);
    entry->next = g_inotify_registry;
    g_inotify_registry = entry;
    fut_spinlock_release(&g_inotify_registry_lock);
}

static void inotify_registry_remove(struct inotify_instance *inst) {
    if (!g_inotify_registry_init) return;
    fut_spinlock_acquire(&g_inotify_registry_lock);
    struct inotify_registry_entry **pp = &g_inotify_registry;
    while (*pp) {
        if ((*pp)->inst == inst) {
            struct inotify_registry_entry *dead = *pp;
            *pp = dead->next;
            fut_free(dead);
            break;
        }
        pp = &(*pp)->next;
    }
    fut_spinlock_release(&g_inotify_registry_lock);
}

/* Phase 5: Global rename cookie counter — odd non-zero values link MOVED_FROM/TO pairs */
static uint32_t g_inotify_rename_cookie = 0;

uint32_t inotify_next_rename_cookie(void) {
    /* Simple increment; ensure non-zero (skip 0) */
    uint32_t c = ++g_inotify_rename_cookie;
    if (c == 0) c = ++g_inotify_rename_cookie;
    return c;
}

/**
 * inotify_dispatch_event - Phase 5: Deliver a VFS event to all registered watchers
 *
 * Called by the VFS (ramfs) on file create/delete/modify/mkdir/rename.
 * Walks all registered inotify instances and queues events for matching watches.
 *
 * @param dir_path   Absolute path of the directory containing the file
 * @param mask       Event mask (IN_CREATE, IN_DELETE, IN_MODIFY, IN_MOVED_FROM, etc.)
 * @param filename   Basename of the affected file (NULL for self-events)
 * @param cookie     Rename cookie linking IN_MOVED_FROM/IN_MOVED_TO pairs (0 for non-rename)
 */
void inotify_dispatch_event(const char *dir_path, uint32_t mask, const char *filename,
                            uint32_t cookie) {
    if (!g_inotify_registry_init || !g_inotify_registry) return;
    if (!dir_path) return;

    fut_spinlock_acquire(&g_inotify_registry_lock);
    for (struct inotify_registry_entry *e = g_inotify_registry; e; e = e->next) {
        struct inotify_instance *inst = e->inst;
        fut_spinlock_acquire(&inst->lock);

        for (int i = 0; i < inst->watch_count; i++) {
            struct inotify_watch *w = &inst->watches[i];
            if (w->wd < 1) continue;               /* unused slot */
            if ((w->mask & mask) == 0) continue;   /* event not requested */

            /* Match if the watch path equals the directory of the event */
            size_t wlen = strlen(w->path);
            if (strcmp(w->path, dir_path) != 0) continue;
            (void)wlen;  /* used for potential prefix check, unused here */

            /* Queue the event if there is space */
            if (inst->ev_count < INOTIFY_MAX_EVENTS) {
                int tail = inst->ev_tail;
                inst->events[tail].wd     = w->wd;
                inst->events[tail].mask   = mask;
                inst->events[tail].cookie = cookie;
                /* Phase 5: copy entry basename into event for directory watches */
                if (filename && filename[0] != '\0') {
                    size_t flen = strlen(filename);
                    if (flen > NAME_MAX) flen = NAME_MAX;
                    __builtin_memcpy(inst->events[tail].name, filename, flen);
                    inst->events[tail].name[flen] = '\0';
                } else {
                    inst->events[tail].name[0] = '\0';
                }
                inst->ev_tail  = (tail + 1) % INOTIFY_MAX_EVENTS;
                inst->ev_count++;
                fut_waitq_wake_one(&inst->read_waitq);
                if (inst->epoll_notify)
                    fut_waitq_wake_all(inst->epoll_notify);
            } else {
                /* Queue overflow event at head (overwrite oldest) */
                inst->events[inst->ev_head].wd     = -1;  /* Linux: wd=-1 for overflow */
                inst->events[inst->ev_head].mask   = IN_Q_OVERFLOW;
                inst->events[inst->ev_head].cookie = 0;
                inst->events[inst->ev_head].name[0] = '\0';  /* no filename for overflow */
                /* Don't advance ev_head; the next read will see overflow */
                if (inst->epoll_notify)
                    fut_waitq_wake_all(inst->epoll_notify);
            }

            /* IN_ONESHOT: remove watch after first event and queue IN_IGNORED */
            if (w->mask & IN_ONESHOT) {
                int removed_wd = w->wd;
                w->wd = 0;  /* mark as removed */

                /* Queue IN_IGNORED event (Linux sends this when a watch is removed) */
                if (inst->ev_count < INOTIFY_MAX_EVENTS) {
                    int itail = inst->ev_tail;
                    inst->events[itail].wd     = removed_wd;
                    inst->events[itail].mask   = IN_IGNORED;
                    inst->events[itail].cookie = 0;
                    inst->events[itail].name[0] = '\0';
                    inst->ev_tail  = (itail + 1) % INOTIFY_MAX_EVENTS;
                    inst->ev_count++;
                }
            }
        }

        fut_spinlock_release(&inst->lock);
    }
    fut_spinlock_release(&g_inotify_registry_lock);
}

/* Forward declarations */
static ssize_t inotify_read_op(void *inode, void *priv, void *u_buf, size_t len, off_t *pos);
static int     inotify_release(void *inode, void *priv);

static struct fut_file_ops inotify_fops;

/* Read inotify events from the queue.
 * Returns one or more struct inotify_event records with optional name field (Phase 5). */
static ssize_t inotify_read_op(void *inode, void *priv, void *u_buf, size_t len, off_t *pos) {
    (void)inode; (void)pos;
    struct inotify_instance *inst = (struct inotify_instance *)priv;
    if (!inst) return -EBADF;

    /* Must be able to hold at least one minimal event (header only) */
    const size_t hdr_size = sizeof(struct inotify_event);
    if (len < hdr_size) return -EINVAL;

    ssize_t total = 0;
    uint8_t *out = (uint8_t *)u_buf;

    while (len >= hdr_size) {
        fut_spinlock_acquire(&inst->lock);

        if (inst->ev_count == 0) {
            /* No events queued */
            if (total > 0) {
                fut_spinlock_release(&inst->lock);
                break;
            }
            /* Check for non-blocking */
            if (inst->file && (inst->file->flags & O_NONBLOCK)) {
                fut_spinlock_release(&inst->lock);
                return -EAGAIN;
            }
            /* Check for pending signals → EINTR (use per-thread mask) */
            {
                fut_task_t *stask = fut_task_current();
                if (stask) {
                    fut_thread_t *ino_thr = fut_thread_current();
                    uint64_t pending = __atomic_load_n(&stask->pending_signals, __ATOMIC_ACQUIRE);
                    if (ino_thr)
                        pending |= __atomic_load_n(&ino_thr->thread_pending_signals, __ATOMIC_ACQUIRE);
                    uint64_t blocked = ino_thr ?
                        __atomic_load_n(&ino_thr->signal_mask, __ATOMIC_ACQUIRE) :
                        stask->signal_mask;
                    if (pending & ~blocked) {
                        fut_spinlock_release(&inst->lock);
                        return -EINTR;
                    }
                }
            }
            /* Block until an event arrives */
            fut_waitq_sleep_locked(&inst->read_waitq, &inst->lock, FUT_THREAD_BLOCKED);
            continue;
        }

        /* Peek at next event to compute its total size before dequeuing */
        struct inotify_queued_event *qp = &inst->events[inst->ev_head];
        uint32_t name_len = inotify_name_padlen(qp->name);
        size_t needed = hdr_size + name_len;

        if (len < needed) {
            /* Buffer too small for this event */
            fut_spinlock_release(&inst->lock);
            if (total == 0) return -EINVAL;  /* Linux returns EINVAL if first event doesn't fit */
            break;
        }

        /* Dequeue one event */
        struct inotify_queued_event qev = *qp;
        inst->ev_head = (inst->ev_head + 1) % INOTIFY_MAX_EVENTS;
        inst->ev_count--;
        fut_spinlock_release(&inst->lock);

        /* Fill inotify_event header */
        struct inotify_event ev;
        ev.wd     = qev.wd;
        ev.mask   = qev.mask;
        ev.cookie = qev.cookie;
        ev.len    = name_len;

        if (inotify_copy_to_user(out, &ev, hdr_size) != 0) {
            if (total == 0) return -EFAULT;
            break;
        }
        out   += hdr_size;
        total += (ssize_t)hdr_size;
        len   -= hdr_size;

        /* Write null-padded name if present */
        if (name_len > 0) {
            /* Zero-fill the padded name region, then copy actual name bytes */
            static const uint8_t zeros[4] = {0, 0, 0, 0};
            size_t slen = strlen(qev.name);
            if (slen > NAME_MAX) slen = NAME_MAX;
            /* Copy name + null terminator */
            if (inotify_copy_to_user(out, qev.name, slen + 1) != 0) {
                if (total == (ssize_t)hdr_size) return -EFAULT;
                break;
            }
            /* Zero-fill padding bytes beyond the null terminator */
            size_t pad = name_len - (slen + 1);
            if (pad > 0) {
                size_t written = slen + 1;
                while (pad > 0) {
                    size_t chunk = pad > 4 ? 4 : pad;
                    if (inotify_copy_to_user(out + written, zeros, chunk) != 0) break;
                    written += chunk;
                    pad -= chunk;
                }
            }
            out   += name_len;
            total += (ssize_t)name_len;
            len   -= name_len;
        }
    }

    return total > 0 ? total : -EAGAIN;
}

static int inotify_release(void *inode, void *priv) {
    (void)inode;
    struct inotify_instance *inst = (struct inotify_instance *)priv;
    if (inst) {
        /* Phase 4: Unregister before waking blocked readers */
        inotify_registry_remove(inst);
        fut_waitq_wake_all(&inst->read_waitq);
        fut_free(inst);
    }
    return 0;
}

/* Look up inotify instance from FD (returns NULL on EBADF/EINVAL) */
static struct inotify_instance *get_inotify_instance(fut_task_t *task, int fd, int *err) {
    if (fd < 0 || fd >= task->max_fds) { *err = -EBADF; return NULL; }
    if (!task->fd_table) { *err = -EBADF; return NULL; }

    struct fut_file *file = task->fd_table[fd];
    if (!file || file->chr_ops != &inotify_fops || !file->chr_private) {
        *err = -EBADF;
        return NULL;
    }
    *err = 0;
    return (struct inotify_instance *)file->chr_private;
}

extern int chrdev_alloc_fd(const struct fut_file_ops *ops, void *inode, void *priv);

/**
 * inotify_init1() - Create inotify instance
 *
 * Creates and initializes an inotify instance and returns a file descriptor
 * referring to the inotify instance.
 *
 * @param flags  IN_CLOEXEC (close on exec) or IN_NONBLOCK (non-blocking)
 *
 * Returns:
 *   - File descriptor on success
 *   - -EINVAL if flags contains invalid values
 *   - -EMFILE if per-process fd limit reached
 *   - -ENOMEM if insufficient memory
 *
 * Phase 1 (Completed): Validate flags and return dummy fd
 * Phase 2 (Completed): Enhanced validation, parameter categorization
 * Phase 3 (Completed): Create actual inotify FD with event queue
 */
long sys_inotify_init1(int flags) {
    fut_task_t *task = fut_task_current();
    if (!task) {
        fut_printf("[INOTIFY] inotify_init1(flags=0x%x) -> ESRCH (no current task)\n", flags);
        return -ESRCH;
    }

    static int inotify_fops_inited = 0;
    if (!inotify_fops_inited) {
        inotify_fops.open = NULL;
        inotify_fops.release = inotify_release;
        inotify_fops.read = inotify_read_op;
        inotify_fops.write = NULL;
        inotify_fops.ioctl = NULL;
        inotify_fops.mmap = NULL;
        inotify_fops_inited = 1;
    }

    const int VALID_FLAGS = IN_CLOEXEC | IN_NONBLOCK;
    if (flags & ~VALID_FLAGS) {
        fut_printf("[INOTIFY] inotify_init1(flags=0x%x, pid=%d) -> EINVAL (invalid flags)\n",
                   flags, task->pid);
        return -EINVAL;
    }

    struct inotify_instance *inst = fut_malloc(sizeof(struct inotify_instance));
    if (!inst) {
        fut_printf("[INOTIFY] inotify_init1(flags=0x%x, pid=%d) -> ENOMEM\n", flags, task->pid);
        return -ENOMEM;
    }
    memset(inst, 0, sizeof(*inst));
    fut_spinlock_init(&inst->lock);
    fut_waitq_init(&inst->read_waitq);
    inst->next_wd = 1;

    /* Allocate the fd FIRST so a failure doesn't leave a dangling
     * pointer in the inotify registry. The previous order was
     * registry_add, then chrdev_alloc_fd; on alloc failure the code
     * fut_free()d 'inst' without removing it from the registry,
     * leaving a use-after-free time bomb that the next VFS event
     * dispatch could trip. */
    int fd = chrdev_alloc_fd(&inotify_fops, NULL, inst);
    if (fd < 0) {
        fut_free(inst);
        fut_printf("[INOTIFY] inotify_init1(flags=0x%x, pid=%d) -> %d (fd alloc failed)\n",
                   flags, task->pid, fd);
        return fd;
    }

    /* Phase 4: Register this instance for VFS event dispatch */
    inotify_registry_add(inst);

    /* Store back-pointer and set O_NONBLOCK/O_CLOEXEC on the file */
    if (task->fd_table && fd < task->max_fds && task->fd_table[fd]) {
        inst->file = task->fd_table[fd];
        if (flags & IN_NONBLOCK) inst->file->flags |= O_NONBLOCK;
        if (flags & IN_CLOEXEC) {
            if (task->fd_flags && fd < task->max_fds)
                task->fd_flags[fd] |= FD_CLOEXEC;
        }
    }

    return fd;
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
 *   - -EBADF if fd is not a valid inotify instance
 *   - -EFAULT if pathname points to inaccessible memory
 *   - -EINVAL if mask has no valid events
 *   - -ENAMETOOLONG if pathname too long
 *   - -ENOSPC if watch limit reached
 *
 * Phase 1 (Completed): Validate parameters and return dummy watch descriptor
 * Phase 2 (Completed): Enhanced validation, user-space data handling
 * Phase 3 (Completed): Register watch in inotify instance
 */
long sys_inotify_add_watch(int fd, const char *pathname, uint32_t mask) {
    fut_task_t *task = fut_task_current();
    if (!task) return -ESRCH;

    int err;
    struct inotify_instance *inst = get_inotify_instance(task, fd, &err);
    if (!inst) {
        fut_printf("[INOTIFY] inotify_add_watch(fd=%d) -> %d (not an inotify fd)\n", fd, err);
        return err;
    }

    if (!pathname) {
        fut_printf("[INOTIFY] inotify_add_watch(fd=%d, pathname=NULL) -> EFAULT\n", fd);
        return -EFAULT;
    }

    char path_buf[INOTIFY_PATH_MAX];
    if (inotify_copy_from_user(path_buf, pathname, sizeof(path_buf)) != 0) {
        fut_printf("[INOTIFY] inotify_add_watch(fd=%d) -> EFAULT (copy_from_user)\n", fd);
        return -EFAULT;
    }
    if (memchr(path_buf, '\0', sizeof(path_buf)) == NULL) {
        fut_printf("[INOTIFY] inotify_add_watch(fd=%d) -> ENAMETOOLONG\n", fd);
        return -ENAMETOOLONG;
    }
    if (path_buf[0] == '\0') {
        fut_printf("[INOTIFY] inotify_add_watch(fd=%d, path=\"\") -> EINVAL\n", fd);
        return -EINVAL;
    }

    if ((mask & IN_ALL_EVENTS) == 0) {
        fut_printf("[INOTIFY] inotify_add_watch(fd=%d, path='%s', mask=0x%x) -> EINVAL (no events)\n",
                   fd, path_buf, mask);
        return -EINVAL;
    }

    /* Note: Linux 4.18+ returns -EINVAL when IN_MASK_ADD and IN_MASK_CREATE
     * are both set. Futura intentionally lets IN_MASK_CREATE win on this
     * combination so its 'create-or-fail' semantics still produce -EEXIST
     * when a watch already exists — matching the local test 930 contract
     * and the existing application semantics. */

    /* IN_ONLYDIR: fail with ENOTDIR if the path is not a directory */
    if (mask & IN_ONLYDIR) {
        struct fut_vnode *vn = NULL;
        int lk_err = (mask & IN_DONT_FOLLOW)
                     ? fut_vfs_lookup_nofollow(path_buf, &vn)
                     : fut_vfs_lookup(path_buf, &vn);
        if (lk_err == 0 && vn) {
            enum fut_vnode_type vtype = vn->type;
            fut_vnode_unref(vn);
            if (vtype != VN_DIR) {
                fut_printf("[INOTIFY] inotify_add_watch(fd=%d, path='%s', mask=0x%x) "
                           "-> ENOTDIR (IN_ONLYDIR: not a directory)\n", fd, path_buf, mask);
                return -ENOTDIR;
            }
        } else {
            /* Path not found or error — let the normal watch path handle it */
        }
    }

    fut_spinlock_acquire(&inst->lock);

    /* Check if path is already watched — update mask if so (or add if IN_MASK_ADD) */
    for (int i = 0; i < inst->watch_count; i++) {
        if (strcmp(inst->watches[i].path, path_buf) == 0) {
            int wd = inst->watches[i].wd;
            /* IN_MASK_CREATE: fail if watch already exists (Linux 4.18+) */
            if (mask & IN_MASK_CREATE) {
                fut_spinlock_release(&inst->lock);
                fut_printf("[INOTIFY] inotify_add_watch(fd=%d, path='%s', mask=0x%x) "
                           "-> EEXIST (IN_MASK_CREATE: watch already exists, wd=%d)\n",
                           fd, path_buf, mask, wd);
                return -EEXIST;
            }
            if (mask & IN_MASK_ADD) {
                inst->watches[i].mask |= (mask & ~(IN_MASK_ADD | IN_MASK_CREATE));
            } else {
                inst->watches[i].mask = mask & ~IN_MASK_CREATE;
            }
            fut_spinlock_release(&inst->lock);
            fut_printf("[INOTIFY] inotify_add_watch(fd=%d, path='%s', mask=0x%x) "
                       "-> %d (Phase 3: watch updated)\n", fd, path_buf, mask, wd);
            return wd;
        }
    }

    /* New watch */
    if (inst->watch_count >= INOTIFY_MAX_WATCHES) {
        fut_spinlock_release(&inst->lock);
        fut_printf("[INOTIFY] inotify_add_watch(fd=%d, path='%s') -> ENOSPC (watch limit)\n",
                   fd, path_buf);
        return -ENOSPC;
    }

    int wd = inst->next_wd++;
    struct inotify_watch *w = &inst->watches[inst->watch_count++];
    w->wd = wd;
    w->mask = mask & ~(IN_MASK_ADD | IN_MASK_CREATE);
    size_t plen = strlen(path_buf);
    if (plen >= INOTIFY_PATH_MAX) plen = INOTIFY_PATH_MAX - 1;
    memcpy(w->path, path_buf, plen);
    w->path[plen] = '\0';

    fut_spinlock_release(&inst->lock);

    fut_printf("[INOTIFY] inotify_add_watch(fd=%d, path='%s', mask=0x%x) "
               "-> %d (Phase 3: watch registered)\n", fd, path_buf, mask, wd);
    return wd;
}

/**
 * inotify_rm_watch() - Remove watch from inotify instance
 *
 * Removes a watch from an inotify instance. The watch descriptor becomes
 * invalid after removal and an IN_IGNORED event is queued.
 *
 * @param fd  File descriptor from inotify_init1()
 * @param wd  Watch descriptor from inotify_add_watch()
 *
 * Returns:
 *   - 0 on success
 *   - -EBADF if fd is not a valid inotify instance
 *   - -EINVAL if wd is not a valid watch descriptor for this inotify
 *
 * Phase 1 (Completed): Validate parameters and return success
 * Phase 2 (Completed): Enhanced validation
 * Phase 3 (Completed): Remove watch and queue IN_IGNORED event
 */
long sys_inotify_rm_watch(int fd, int wd) {
    fut_task_t *task = fut_task_current();
    if (!task) return -ESRCH;

    int err;
    struct inotify_instance *inst = get_inotify_instance(task, fd, &err);
    if (!inst) {
        fut_printf("[INOTIFY] inotify_rm_watch(fd=%d) -> %d (not an inotify fd)\n", fd, err);
        return err;
    }

    if (wd < 0) {
        fut_printf("[INOTIFY] inotify_rm_watch(fd=%d, wd=%d) -> EINVAL\n", fd, wd);
        return -EINVAL;
    }

    fut_spinlock_acquire(&inst->lock);

    /* Find watch by wd */
    int found = -1;
    for (int i = 0; i < inst->watch_count; i++) {
        if (inst->watches[i].wd == wd) {
            found = i;
            break;
        }
    }

    if (found < 0) {
        fut_spinlock_release(&inst->lock);
        fut_printf("[INOTIFY] inotify_rm_watch(fd=%d, wd=%d) -> EINVAL (wd not found)\n", fd, wd);
        return -EINVAL;
    }

    /* Remove watch by shifting remaining entries */
    inst->watch_count--;
    for (int i = found; i < inst->watch_count; i++) {
        inst->watches[i] = inst->watches[i + 1];
    }

    /* Queue IN_IGNORED event if there is space */
    if (inst->ev_count < INOTIFY_MAX_EVENTS) {
        struct inotify_queued_event *qev = &inst->events[inst->ev_tail];
        qev->wd     = wd;
        qev->mask   = IN_IGNORED;
        qev->cookie = 0;
        inst->ev_tail = (inst->ev_tail + 1) % INOTIFY_MAX_EVENTS;
        inst->ev_count++;
        fut_waitq_wake_one(&inst->read_waitq);
        if (inst->epoll_notify)
            fut_waitq_wake_all(inst->epoll_notify);
    }

    fut_spinlock_release(&inst->lock);

    fut_printf("[INOTIFY] inotify_rm_watch(fd=%d, wd=%d) -> 0 (Phase 3: watch removed)\n", fd, wd);
    return 0;
}

/**
 * fut_inotify_poll - Check if an inotify fd has pending events (for epoll/poll/select).
 *
 * Returns true if the file is an inotify fd (and fills ready_out), false otherwise.
 * Sets EPOLLIN in ready_out when there are queued events.
 */
bool fut_inotify_poll(struct fut_file *file, uint32_t requested, uint32_t *ready_out) {
    if (!file || file->chr_ops != &inotify_fops || !file->chr_private)
        return false;

    struct inotify_instance *inst = (struct inotify_instance *)file->chr_private;
    uint32_t ready = 0;
    fut_spinlock_acquire(&inst->lock);
    if (inst->ev_count > 0 && (requested & (EPOLLIN | EPOLLRDNORM)))
        ready |= (EPOLLIN | EPOLLRDNORM);
    fut_spinlock_release(&inst->lock);

    if (ready_out) *ready_out = ready;
    return true;
}

/**
 * fut_inotify_set_epoll_notify - Wire an inotify fd to an epoll/poll/select waitqueue.
 *
 * Called from epoll_ctl ADD, poll wiring, and select wiring to enable
 * event-driven wakeup when an inotify event is queued.
 * Pass wq=NULL to unwire.
 */
void fut_inotify_set_epoll_notify(struct fut_file *file, fut_waitq_t *wq) {
    if (!file || file->chr_ops != &inotify_fops || !file->chr_private)
        return;
    struct inotify_instance *inst = (struct inotify_instance *)file->chr_private;
    inst->epoll_notify = wq;
}
