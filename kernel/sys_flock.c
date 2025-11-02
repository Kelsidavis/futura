/* kernel/sys_flock.c - File locking syscall
 *
 * Copyright (c) 2025 Kelsi Davis
 * Licensed under the MPL v2.0 — see LICENSE for details.
 *
 * Implements the flock() syscall for file locking.
 */

#include <kernel/fut_task.h>
#include <kernel/errno.h>
#include <kernel/fut_vfs.h>
#include <stdint.h>

extern void fut_printf(const char *fmt, ...);
extern fut_task_t *fut_task_current(void);
extern struct fut_file *vfs_get_file_from_task(struct fut_task *task, int fd);

/* flock operation definitions */
#define LOCK_SH         1       /* Shared lock */
#define LOCK_EX         2       /* Exclusive lock */
#define LOCK_UN         8       /* Unlock */
#define LOCK_NB         4       /* Non-blocking */

/**
 * flock() - Apply or remove an advisory lock on an open file
 *
 * For a single-process operating system, file locking is a semantic no-op
 * since there's no concurrent access from other processes. This implementation
 * validates the file descriptor and always succeeds.
 *
 * In a multi-process environment, this would implement advisory file locking
 * with shared (LOCK_SH) and exclusive (LOCK_EX) modes.
 *
 * @param fd        File descriptor
 * @param operation Lock operation (LOCK_SH, LOCK_EX, LOCK_UN, optionally | LOCK_NB)
 *
 * Returns:
 *   - 0 on success
 *   - -EBADF if fd is not a valid open file descriptor
 *   - -EINVAL if operation is invalid
 */
long sys_flock(int fd, int operation) {
    /* Get current task */
    fut_task_t *task = fut_task_current();
    if (!task) {
        return -ESRCH;
    }

    /* Validate file descriptor */
    struct fut_file *file = vfs_get_file_from_task(task, fd);
    if (!file) {
        fut_printf("[FLOCK] flock(%d, %d) -> EBADF\n", fd, operation);
        return -EBADF;
    }

    /* Extract operation (ignore LOCK_NB flag for simplicity) */
    int op = operation & ~LOCK_NB;

    /* Validate operation */
    if (op != LOCK_SH && op != LOCK_EX && op != LOCK_UN) {
        fut_printf("[FLOCK] flock(%d, %d) -> EINVAL (invalid operation)\n", fd, operation);
        return -EINVAL;
    }

    /* In a single-process OS, locking is a no-op - always succeed */
    const char *op_name = (op == LOCK_SH) ? "LOCK_SH" :
                          (op == LOCK_EX) ? "LOCK_EX" : "LOCK_UN";
    fut_printf("[FLOCK] flock(%d, %s%s) -> 0 (no-op in single-process OS)\n",
               fd, op_name, (operation & LOCK_NB) ? "|LOCK_NB" : "");

    return 0;
}
