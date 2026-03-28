/* include/kernel/fut_lock.h - Advisory file locking (Phase 3 + Phase 5)
 *
 * Copyright (c) 2025 Kelsi Davis
 * Licensed under the MPL v2.0 — see LICENSE for details.
 *
 * Advisory file locking API for flock()-style whole-file locks and
 * fcntl()-style POSIX byte-range locks with global lock registry for
 * /proc/locks enumeration.
 */

#ifndef FUT_LOCK_H
#define FUT_LOCK_H

#include <stdint.h>
#include <stddef.h>

struct fut_vnode;

/* ============================================================
 *   Lock type constants (used in file_lock entries)
 * ============================================================ */

#define FUT_FL_FLOCK    0   /* BSD flock() whole-file lock */
#define FUT_FL_POSIX    1   /* POSIX fcntl() byte-range lock */

/* ============================================================
 *   Per-file lock entry for byte-range (POSIX) and flock locks
 * ============================================================ */

/** Represents a single file lock (flock or POSIX byte-range) */
struct fut_file_lock {
    uint8_t  fl_class;      /* FUT_FL_FLOCK or FUT_FL_POSIX */
    uint8_t  fl_type;       /* 0=none, 1=shared/read, 2=exclusive/write */
    uint16_t fl_whence;     /* SEEK_SET/SEEK_CUR/SEEK_END (for POSIX) */
    uint32_t fl_pid;        /* Owner PID */
    int64_t  fl_start;      /* Start offset (0 for flock whole-file) */
    int64_t  fl_end;        /* End offset (-1 = EOF, 0 for flock whole-file) */
    uint64_t fl_ino;        /* Inode number of locked file */
    struct fut_vnode *fl_vnode; /* Back-pointer to owning vnode */
    struct fut_file_lock *fl_next; /* Next lock on same vnode */
};

/* Maximum number of globally tracked file locks for /proc/locks */
#define FUT_MAX_FILE_LOCKS 256

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

/* ============================================================
 *   Global lock registry for /proc/locks
 * ============================================================ */

/**
 * fut_lock_registry_init() - Initialize the global lock registry
 *
 * Called once during kernel startup to prepare the lock table.
 */
void fut_lock_registry_init(void);

/**
 * fut_lock_register() - Register a file lock in the global registry
 *
 * @param vnode    Locked vnode
 * @param pid      Owner PID
 * @param fl_class FUT_FL_FLOCK or FUT_FL_POSIX
 * @param fl_type  1=shared, 2=exclusive
 * @param start    Start offset (0 for whole-file)
 * @param end      End offset (-1 for EOF / whole-file)
 */
void fut_lock_register(struct fut_vnode *vnode, uint32_t pid,
                       uint8_t fl_class, uint8_t fl_type,
                       int64_t start, int64_t end);

/**
 * fut_lock_unregister() - Remove a file lock from the global registry
 *
 * @param vnode Locked vnode
 * @param pid   Owner PID (0 to match any pid for shared lock release)
 */
void fut_lock_unregister(struct fut_vnode *vnode, uint32_t pid);

/**
 * fut_lock_enumerate() - Enumerate active locks for /proc/locks
 *
 * @param buf    Output buffer
 * @param bufsz  Buffer size
 * @return Number of bytes written (not including NUL terminator)
 */
int fut_lock_enumerate(char *buf, size_t bufsz);

/**
 * fut_lock_count() - Return the number of active file locks
 *
 * @return Number of registered file locks
 */
int fut_lock_count(void);

#endif /* FUT_LOCK_H */
