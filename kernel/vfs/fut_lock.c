/* kernel/vfs/fut_lock.c - Advisory file locking (Phase 3)
 *
 * Copyright (c) 2025 Kelsi Davis
 * Licensed under the MPL v2.0 — see LICENSE for details.
 *
 * Implements advisory file locking for inter-process coordination.
 * Provides flock()-style locks (shared and exclusive) on vnodes.
 */

#include <kernel/fut_vfs.h>
#include <kernel/fut_task.h>
#include <kernel/errno.h>

#include <kernel/kprintf.h>

/* Lock type constants */
#define FUT_LOCK_NONE       0
#define FUT_LOCK_SHARED     1
#define FUT_LOCK_EXCLUSIVE  2

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
            return -EAGAIN;  /* Would block, but non-blocking requested */
        }
        /* Phase 3: Blocking not yet implemented - return EAGAIN for now */
        return -EAGAIN;
    }

    /* Acquire shared lock */
    if (vnode->lock_type == FUT_LOCK_NONE) {
        vnode->lock_type = FUT_LOCK_SHARED;
        vnode->lock_count = 1;
        vnode->lock_owner_pid = 0;  /* Shared locks have no single owner */
    } else if (vnode->lock_type == FUT_LOCK_SHARED) {
        /* Already shared, just increment count */
        vnode->lock_count++;
    } else if (vnode->lock_type == FUT_LOCK_EXCLUSIVE && vnode->lock_owner_pid == pid) {
        /* Same process downgrading from exclusive to shared */
        vnode->lock_type = FUT_LOCK_SHARED;
        vnode->lock_count = 1;
        vnode->lock_owner_pid = 0;
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
    if (vnode->lock_type == FUT_LOCK_SHARED) {
        if (nonblock) {
            return -EAGAIN;  /* Would block, but non-blocking requested */
        }
        /* Phase 3: Blocking not yet implemented - return EAGAIN for now */
        return -EAGAIN;
    }

    if (vnode->lock_type == FUT_LOCK_EXCLUSIVE && vnode->lock_owner_pid != pid) {
        if (nonblock) {
            return -EAGAIN;  /* Would block, but non-blocking requested */
        }
        /* Phase 3: Blocking not yet implemented - return EAGAIN for now */
        return -EAGAIN;
    }

    /* Acquire exclusive lock */
    vnode->lock_type = FUT_LOCK_EXCLUSIVE;
    vnode->lock_count = 1;
    vnode->lock_owner_pid = pid;

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
        }
        return 0;
    }

    /* Release shared lock */
    if (vnode->lock_type == FUT_LOCK_SHARED) {
        if (vnode->lock_count > 0) {
            vnode->lock_count--;
            if (vnode->lock_count == 0) {
                vnode->lock_type = FUT_LOCK_NONE;
                vnode->lock_owner_pid = 0;
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
