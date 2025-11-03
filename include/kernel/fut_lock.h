/* include/kernel/fut_lock.h - Advisory file locking (Phase 3)
 *
 * Copyright (c) 2025 Kelsi Davis
 * Licensed under the MPL v2.0 — see LICENSE for details.
 *
 * Advisory file locking API for flock()-style locks.
 */

#ifndef FUT_LOCK_H
#define FUT_LOCK_H

#include <stdint.h>

struct fut_vnode;

/**
 * fut_vnode_lock_shared() - Acquire shared (read) lock on vnode
 *
 * @param vnode VNode to lock
 * @param pid   Process ID requesting the lock
 * @param nonblock If true, return -EAGAIN instead of blocking
 * @return 0 on success, -EAGAIN if would block, -EINVAL on invalid parameters
 */
int fut_vnode_lock_shared(struct fut_vnode *vnode, uint32_t pid, int nonblock);

/**
 * fut_vnode_lock_exclusive() - Acquire exclusive (write) lock on vnode
 *
 * @param vnode VNode to lock
 * @param pid   Process ID requesting the lock
 * @param nonblock If true, return -EAGAIN instead of blocking
 * @return 0 on success, -EAGAIN if would block, -EINVAL on invalid parameters
 */
int fut_vnode_lock_exclusive(struct fut_vnode *vnode, uint32_t pid, int nonblock);

/**
 * fut_vnode_unlock() - Release lock on vnode
 *
 * @param vnode VNode to unlock
 * @param pid   Process ID releasing the lock
 * @return 0 on success, -EINVAL on invalid parameters
 */
int fut_vnode_unlock(struct fut_vnode *vnode, uint32_t pid);

/**
 * fut_vnode_lock_init() - Initialize lock state for new vnode
 *
 * @param vnode VNode to initialize
 */
void fut_vnode_lock_init(struct fut_vnode *vnode);

/**
 * fut_vnode_lock_get_info() - Get current lock information
 *
 * @param vnode VNode to query
 * @param type_out Output: lock type (0=none, 1=shared, 2=exclusive)
 * @param count_out Output: lock count
 * @param owner_out Output: owner PID (0 if shared/none)
 */
void fut_vnode_lock_get_info(struct fut_vnode *vnode, uint32_t *type_out,
                              uint32_t *count_out, uint32_t *owner_out);

#endif /* FUT_LOCK_H */
