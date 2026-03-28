/* kernel/vfs/fut_lock.c - Advisory file locking
 *
 * Copyright (c) 2025 Kelsi Davis
 * Licensed under the MPL v2.0 — see LICENSE for details.
 *
 * Implements advisory file locking for inter-process coordination.
 * Provides flock()-style whole-file locks and fcntl()-style POSIX
 * byte-range locks on vnodes.
 *
 * Phase 3: Whole-file flock() locks with blocking/non-blocking.
 * Phase 5: Global lock registry for /proc/locks, per-vnode lock lists.
 */

#include <kernel/fut_vfs.h>
#include <kernel/fut_lock.h>
#include <kernel/fut_task.h>
#include <kernel/fut_waitq.h>
#include <kernel/fut_memory.h>
#include <kernel/errno.h>

#include <kernel/kprintf.h>

/* Lock type constants */
#define FUT_LOCK_NONE       0
#define FUT_LOCK_SHARED     1
#define FUT_LOCK_EXCLUSIVE  2

/* ============================================================
 *   Global lock registry for /proc/locks
 * ============================================================ */

static struct fut_file_lock g_lock_table[FUT_MAX_FILE_LOCKS];
static int g_lock_count = 0;
static int g_lock_initialized = 0;

/**
 * fut_lock_registry_init() - Initialize the global file lock registry
 */
void fut_lock_registry_init(void) {
    for (int i = 0; i < FUT_MAX_FILE_LOCKS; i++) {
        g_lock_table[i].fl_type = 0;
        g_lock_table[i].fl_pid = 0;
        g_lock_table[i].fl_vnode = NULL;
        g_lock_table[i].fl_next = NULL;
    }
    g_lock_count = 0;
    g_lock_initialized = 1;
}

/**
 * fut_lock_register() - Register a file lock in the global registry
 *
 * Adds a lock entry to the global table so /proc/locks can enumerate it.
 * If the table is full, the lock still works but won't appear in /proc/locks.
 */
void fut_lock_register(struct fut_vnode *vnode, uint32_t pid,
                       uint8_t fl_class, uint8_t fl_type,
                       int64_t start, int64_t end) {
    if (!g_lock_initialized)
        fut_lock_registry_init();

    /* Find a free slot */
    for (int i = 0; i < FUT_MAX_FILE_LOCKS; i++) {
        if (g_lock_table[i].fl_type == 0 && g_lock_table[i].fl_vnode == NULL) {
            g_lock_table[i].fl_class = fl_class;
            g_lock_table[i].fl_type = fl_type;
            g_lock_table[i].fl_whence = 0; /* SEEK_SET */
            g_lock_table[i].fl_pid = pid;
            g_lock_table[i].fl_start = start;
            g_lock_table[i].fl_end = end;
            g_lock_table[i].fl_ino = vnode ? vnode->ino : 0;
            g_lock_table[i].fl_vnode = vnode;
            g_lock_table[i].fl_next = NULL;
            g_lock_count++;

            /* Also add to per-vnode lock list */
            if (vnode) {
                g_lock_table[i].fl_next = vnode->file_lock_list;
                vnode->file_lock_list = &g_lock_table[i];
            }
            return;
        }
    }
    /* Table full -- lock works but is not visible in /proc/locks */
}

/**
 * fut_lock_unregister() - Remove a file lock from the global registry
 *
 * Removes the matching lock entry for the given vnode and pid.
 * If pid==0, removes any one entry for the vnode (used for shared lock decrement).
 */
void fut_lock_unregister(struct fut_vnode *vnode, uint32_t pid) {
    if (!g_lock_initialized)
        return;

    for (int i = 0; i < FUT_MAX_FILE_LOCKS; i++) {
        if (g_lock_table[i].fl_vnode == vnode &&
            (pid == 0 || g_lock_table[i].fl_pid == pid)) {
            /* Remove from per-vnode lock list */
            if (vnode) {
                struct fut_file_lock **pp = &vnode->file_lock_list;
                while (*pp) {
                    if (*pp == &g_lock_table[i]) {
                        *pp = g_lock_table[i].fl_next;
                        break;
                    }
                    pp = &(*pp)->fl_next;
                }
            }
            g_lock_table[i].fl_type = 0;
            g_lock_table[i].fl_pid = 0;
            g_lock_table[i].fl_vnode = NULL;
            g_lock_table[i].fl_next = NULL;
            g_lock_table[i].fl_start = 0;
            g_lock_table[i].fl_end = 0;
            g_lock_table[i].fl_ino = 0;
            if (g_lock_count > 0) g_lock_count--;
            return; /* Remove one entry at a time */
        }
    }
}

/**
 * fut_lock_count() - Return the number of active file locks
 */
int fut_lock_count(void) {
    return g_lock_count;
}

/* Helper: append a decimal number to buffer */
static int lock_append_u64(char *buf, size_t bufsz, int pos, uint64_t v) {
    char tmp[20];
    int n = 0;
    if (v == 0) { tmp[n++] = '0'; }
    else {
        uint64_t w = v;
        while (w) { tmp[n++] = '0' + (int)(w % 10); w /= 10; }
    }
    for (int i = n - 1; i >= 0 && pos < (int)bufsz - 1; i--)
        buf[pos++] = tmp[i];
    return pos;
}

/* Helper: append a string to buffer */
static int lock_append_str(char *buf, size_t bufsz, int pos, const char *s) {
    while (*s && pos < (int)bufsz - 1)
        buf[pos++] = *s++;
    return pos;
}

/**
 * fut_lock_enumerate() - Enumerate active locks for /proc/locks
 *
 * Produces output in Linux /proc/locks format:
 *   N: FLOCK  ADVISORY  WRITE PID MAJ:MIN:INO START END
 *   N: POSIX  ADVISORY  READ  PID MAJ:MIN:INO START END
 */
int fut_lock_enumerate(char *buf, size_t bufsz) {
    if (!buf || bufsz == 0)
        return 0;
    if (!g_lock_initialized) {
        buf[0] = '\0';
        return 0;
    }

    int pos = 0;
    int entry_num = 0;

    for (int i = 0; i < FUT_MAX_FILE_LOCKS && pos < (int)bufsz - 80; i++) {
        if (g_lock_table[i].fl_vnode == NULL || g_lock_table[i].fl_type == 0)
            continue;

        entry_num++;

        /* Entry number */
        pos = lock_append_u64(buf, bufsz, pos, (uint64_t)entry_num);
        pos = lock_append_str(buf, bufsz, pos, ": ");

        /* Lock class: FLOCK or POSIX */
        if (g_lock_table[i].fl_class == FUT_FL_FLOCK) {
            pos = lock_append_str(buf, bufsz, pos, "FLOCK  ADVISORY  ");
        } else {
            pos = lock_append_str(buf, bufsz, pos, "POSIX  ADVISORY  ");
        }

        /* Lock type: READ or WRITE */
        if (g_lock_table[i].fl_type == FUT_LOCK_SHARED) {
            pos = lock_append_str(buf, bufsz, pos, "READ  ");
        } else {
            pos = lock_append_str(buf, bufsz, pos, "WRITE ");
        }

        /* PID */
        pos = lock_append_u64(buf, bufsz, pos, (uint64_t)g_lock_table[i].fl_pid);
        pos = lock_append_str(buf, bufsz, pos, " ");

        /* DEV:INO -- use 00:00:ino format (ramfs has no real device) */
        pos = lock_append_str(buf, bufsz, pos, "00:00:");
        pos = lock_append_u64(buf, bufsz, pos, g_lock_table[i].fl_ino);
        pos = lock_append_str(buf, bufsz, pos, " ");

        /* START */
        pos = lock_append_u64(buf, bufsz, pos,
            g_lock_table[i].fl_start >= 0 ? (uint64_t)g_lock_table[i].fl_start : 0);
        pos = lock_append_str(buf, bufsz, pos, " ");

        /* END */
        if (g_lock_table[i].fl_end < 0) {
            pos = lock_append_str(buf, bufsz, pos, "EOF");
        } else {
            pos = lock_append_u64(buf, bufsz, pos, (uint64_t)g_lock_table[i].fl_end);
        }

        pos = lock_append_str(buf, bufsz, pos, "\n");
    }

    buf[pos] = '\0';
    return pos;
}

/* ============================================================
 *   Whole-file flock() lock operations
 * ============================================================ */

/**
 * fut_vnode_lock_shared() - Acquire shared (read) lock on vnode
 *
 * Shared locks allow multiple holders but block exclusive locks.
 * If an exclusive lock is held, this blocks (or returns -EAGAIN if non-blocking).
 *
 * @param vnode VNode to lock
 * @param pid   Process ID requesting the lock
 * @param nonblock If true, don't block - return -EAGAIN instead
 * @return 0 on success, negative error code on failure
 */
int fut_vnode_lock_shared(struct fut_vnode *vnode, uint32_t pid, int nonblock) {
    if (!vnode) {
        return -EINVAL;
    }

    /* Check if exclusive lock is held by another process */
    if (vnode->lock_type == FUT_LOCK_EXCLUSIVE && vnode->lock_owner_pid != pid) {
        if (nonblock) {
            return -EAGAIN;
        }
        /* Block until exclusive lock is released, with EINTR on signal */
        while (vnode->lock_type == FUT_LOCK_EXCLUSIVE && vnode->lock_owner_pid != pid) {
            /* Check for pending unblocked signals -> EINTR */
            extern fut_thread_t *fut_thread_current(void);
            fut_task_t *sig_task = fut_task_current();
            if (sig_task) {
                uint64_t pending = __atomic_load_n(&sig_task->pending_signals, __ATOMIC_ACQUIRE);
                fut_thread_t *thr = fut_thread_current();
                uint64_t blocked = thr ?
                    __atomic_load_n(&thr->signal_mask, __ATOMIC_ACQUIRE) :
                    __atomic_load_n(&sig_task->signal_mask, __ATOMIC_ACQUIRE);
                if (pending & ~blocked)
                    return -EINTR;
            }
            fut_waitq_sleep_locked(&vnode->lock_waitq, NULL, FUT_THREAD_BLOCKED);
        }
    }

    /* Acquire shared lock */
    if (vnode->lock_type == FUT_LOCK_NONE) {
        vnode->lock_type = FUT_LOCK_SHARED;
        vnode->lock_count = 1;
        vnode->lock_owner_pid = 0;
        /* Register in global lock table */
        fut_lock_register(vnode, pid, FUT_FL_FLOCK, FUT_LOCK_SHARED, 0, -1);
    } else if (vnode->lock_type == FUT_LOCK_SHARED) {
        if (vnode->lock_count == UINT32_MAX) {
            return -EOVERFLOW;
        }
        vnode->lock_count++;
        /* Register additional shared lock holder */
        fut_lock_register(vnode, pid, FUT_FL_FLOCK, FUT_LOCK_SHARED, 0, -1);
    } else if (vnode->lock_type == FUT_LOCK_EXCLUSIVE && vnode->lock_owner_pid == pid) {
        /* Same process downgrading from exclusive to shared */
        fut_lock_unregister(vnode, pid);
        vnode->lock_type = FUT_LOCK_SHARED;
        vnode->lock_count = 1;
        vnode->lock_owner_pid = 0;
        fut_lock_register(vnode, pid, FUT_FL_FLOCK, FUT_LOCK_SHARED, 0, -1);
    }

    return 0;
}

/**
 * fut_vnode_lock_exclusive() - Acquire exclusive (write) lock on vnode
 *
 * Exclusive locks allow only one holder and block all other locks.
 * If any locks are held, this blocks (or returns -EAGAIN if non-blocking).
 *
 * @param vnode VNode to lock
 * @param pid   Process ID requesting the lock
 * @param nonblock If true, don't block - return -EAGAIN instead
 * @return 0 on success, negative error code on failure
 */
int fut_vnode_lock_exclusive(struct fut_vnode *vnode, uint32_t pid, int nonblock) {
    if (!vnode) {
        return -EINVAL;
    }

    /* Check if any locks are held by other processes */
    if (vnode->lock_type == FUT_LOCK_SHARED ||
        (vnode->lock_type == FUT_LOCK_EXCLUSIVE && vnode->lock_owner_pid != pid)) {
        if (nonblock) {
            return -EAGAIN;
        }
        /* Block until all conflicting locks are released, with EINTR on signal */
        while (vnode->lock_type == FUT_LOCK_SHARED ||
               (vnode->lock_type == FUT_LOCK_EXCLUSIVE && vnode->lock_owner_pid != pid)) {
            /* Check for pending unblocked signals -> EINTR */
            extern fut_thread_t *fut_thread_current(void);
            fut_task_t *sig_task = fut_task_current();
            if (sig_task) {
                uint64_t pending = __atomic_load_n(&sig_task->pending_signals, __ATOMIC_ACQUIRE);
                fut_thread_t *thr = fut_thread_current();
                uint64_t blocked = thr ?
                    __atomic_load_n(&thr->signal_mask, __ATOMIC_ACQUIRE) :
                    __atomic_load_n(&sig_task->signal_mask, __ATOMIC_ACQUIRE);
                if (pending & ~blocked)
                    return -EINTR;
            }
            fut_waitq_sleep_locked(&vnode->lock_waitq, NULL, FUT_THREAD_BLOCKED);
        }
    }

    /* If upgrading from existing exclusive (same pid), unregister old first */
    if (vnode->lock_type == FUT_LOCK_EXCLUSIVE && vnode->lock_owner_pid == pid) {
        fut_lock_unregister(vnode, pid);
    }

    /* Acquire exclusive lock */
    vnode->lock_type = FUT_LOCK_EXCLUSIVE;
    vnode->lock_count = 1;
    vnode->lock_owner_pid = pid;

    /* Register in global lock table */
    fut_lock_register(vnode, pid, FUT_FL_FLOCK, FUT_LOCK_EXCLUSIVE, 0, -1);

    return 0;
}

/**
 * fut_vnode_unlock() - Release lock on vnode
 *
 * Releases the lock held by the specified process.
 * For shared locks, decrements the count (unlocked when count reaches 0).
 * For exclusive locks, removes the lock immediately.
 *
 * @param vnode VNode to unlock
 * @param pid   Process ID releasing the lock
 * @return 0 on success, negative error code on failure
 */
int fut_vnode_unlock(struct fut_vnode *vnode, uint32_t pid) {
    if (!vnode) {
        return -EINVAL;
    }

    /* If no lock held, nothing to do (idempotent) */
    if (vnode->lock_type == FUT_LOCK_NONE) {
        return 0;
    }

    /* Release exclusive lock */
    if (vnode->lock_type == FUT_LOCK_EXCLUSIVE) {
        if (vnode->lock_owner_pid == pid) {
            vnode->lock_type = FUT_LOCK_NONE;
            vnode->lock_count = 0;
            vnode->lock_owner_pid = 0;
            fut_lock_unregister(vnode, pid);
            fut_waitq_wake_all(&vnode->lock_waitq);
        }
        return 0;
    }

    /* Release shared lock */
    if (vnode->lock_type == FUT_LOCK_SHARED) {
        if (vnode->lock_count > 0) {
            vnode->lock_count--;
            /* Unregister one shared lock entry (pid may be 0 for shared) */
            fut_lock_unregister(vnode, pid);
            if (vnode->lock_count == 0) {
                vnode->lock_type = FUT_LOCK_NONE;
                vnode->lock_owner_pid = 0;
                fut_waitq_wake_all(&vnode->lock_waitq);
            }
        }
        return 0;
    }

    return 0;
}

/**
 * fut_vnode_lock_init() - Initialize lock state for new vnode
 *
 * Called when creating new vnodes to initialize lock fields to unlocked state.
 *
 * @param vnode VNode to initialize
 */
void fut_vnode_lock_init(struct fut_vnode *vnode) {
    if (!vnode) {
        return;
    }

    vnode->lock_type = FUT_LOCK_NONE;
    vnode->lock_count = 0;
    vnode->lock_owner_pid = 0;
    vnode->file_lock_list = NULL;
    fut_waitq_init(&vnode->lock_waitq);
    fut_spinlock_init(&vnode->write_lock);
}

/**
 * fut_vnode_lock_get_info() - Get current lock information for logging
 *
 * @param vnode VNode to query
 * @param type_out Output: lock type (0=none, 1=shared, 2=exclusive)
 * @param count_out Output: lock count
 * @param owner_out Output: owner PID (0 if shared/none)
 */
void fut_vnode_lock_get_info(struct fut_vnode *vnode, uint32_t *type_out,
                              uint32_t *count_out, uint32_t *owner_out) {
    if (!vnode) {
        if (type_out) *type_out = 0;
        if (count_out) *count_out = 0;
        if (owner_out) *owner_out = 0;
        return;
    }

    if (type_out) *type_out = vnode->lock_type;
    if (count_out) *count_out = vnode->lock_count;
    if (owner_out) *owner_out = vnode->lock_owner_pid;
}
