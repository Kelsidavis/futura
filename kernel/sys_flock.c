/* kernel/sys_flock.c - File locking syscall
 *
 * Copyright (c) 2025 Kelsi Davis
 * Licensed under the MPL v2.0 — see LICENSE for details.
 *
 * Implements the flock() syscall for file locking.
 *
 * Phase 1 (Completed): Basic stub that validates FD
 * Phase 2 (Completed): Enhanced validation, operation categorization, detailed logging
 * Phase 3 (Completed): Advisory lock implementation (multi-process support)
 * Phase 4: Deadlock detection, lock performance optimization
 */

#include <kernel/fut_task.h>
#include <kernel/errno.h>
#include <kernel/fut_vfs.h>
#include <kernel/fut_lock.h>
#include <kernel/fut_fd_util.h>
#include <stdint.h>

#include <kernel/kprintf.h>
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
 * Provides BSD-style file locking for inter-process coordination.
 * Locks are advisory and not enforced - cooperating processes must check locks.
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
 *   - -ESRCH if no current task
 *   - -EWOULDBLOCK if LOCK_NB specified and lock would block (Phase 3+)
 *
 * Behavior:
 *   - LOCK_SH: Apply shared (read) lock - multiple processes can hold
 *   - LOCK_EX: Apply exclusive (write) lock - only one process can hold
 *   - LOCK_UN: Release lock
 *   - LOCK_NB: Non-blocking mode - fail instead of blocking
 *   - Locks are associated with file, not FD
 *   - Locks are released on close() or process termination
 *   - fork() does not inherit locks (child has no locks)
 *
 * Lock types:
 *   - LOCK_SH (1): Shared lock - multiple readers allowed
 *   - LOCK_EX (2): Exclusive lock - single writer only
 *   - LOCK_UN (8): Unlock - release lock
 *   - LOCK_NB (4): Non-blocking flag (OR with above)
 *
 * Common usage patterns:
 *
 * Shared read lock:
 *   int fd = open("file.txt", O_RDONLY);
 *   flock(fd, LOCK_SH);  // Allow concurrent readers
 *   read(fd, buf, size);
 *   flock(fd, LOCK_UN);  // Release lock
 *   close(fd);
 *
 * Exclusive write lock:
 *   int fd = open("file.txt", O_WRONLY);
 *   flock(fd, LOCK_EX);  // Block other readers and writers
 *   write(fd, data, size);
 *   flock(fd, LOCK_UN);
 *   close(fd);
 *
 * Non-blocking lock:
 *   if (flock(fd, LOCK_EX | LOCK_NB) < 0) {
 *       if (errno == EWOULDBLOCK) {
 *           // Lock held by another process
 *       }
 *   }
 *
 * Automatic unlock on close:
 *   int fd = open("file.txt", O_WRONLY);
 *   flock(fd, LOCK_EX);
 *   write(fd, data, size);
 *   close(fd);  // Lock is automatically released
 *
 * Upgrade lock:
 *   flock(fd, LOCK_SH);       // Acquire shared lock
 *   // ... read data ...
 *   flock(fd, LOCK_EX);       // Upgrade to exclusive (may block)
 *   // ... write data ...
 *   flock(fd, LOCK_UN);
 *
 * Comparison with fcntl locking:
 *   - flock(): Whole-file locks, simpler, BSD-style
 *   - fcntl(): Byte-range locks, POSIX, more complex
 *   - flock() locks are per-file, fcntl() locks are per-process
 *
 * Related syscalls:
 *   - fcntl(F_SETLK): POSIX byte-range locking
 *   - open(O_EXLOCK): Open with exclusive lock (BSD)
 *   - open(O_SHLOCK): Open with shared lock (BSD)
 *
 * Phase 1 (Completed): Basic stub that validates FD
 * Phase 2 (Completed): Enhanced validation, operation categorization, detailed logging
 * Phase 3 (Completed): Advisory lock implementation (multi-process support)
 * Phase 4: Deadlock detection, lock performance optimization
 */
long sys_flock(int fd, int operation) {
    /* Get current task */
    fut_task_t *task = fut_task_current();
    if (!task) {
        char msg[128];
        int pos = 0;
        const char *text = "[FLOCK] flock(fd=";
        while (*text) { msg[pos++] = *text++; }

        char num[16]; int num_pos = 0; int val = fd;
        if (val == 0) { num[num_pos++] = '0'; }
        else { char temp[16]; int temp_pos = 0;
            int is_neg = 0;
            if (val < 0) { is_neg = 1; val = -val; }
            while (val > 0) { temp[temp_pos++] = '0' + (val % 10); val /= 10; }
            if (is_neg) num[num_pos++] = '-';
            while (temp_pos > 0) { num[num_pos++] = temp[--temp_pos]; } }
        num[num_pos] = '\0';
        for (int i = 0; num[i]; i++) { msg[pos++] = num[i]; }

        text = ") -> ESRCH (no current task)\n";
        while (*text) { msg[pos++] = *text++; }
        msg[pos] = '\0';
        fut_printf("%s", msg);

        return -ESRCH;
    }

    /* Phase 5: Validate FD upper bound to prevent OOB array access */
    if (fd < 0) {
        fut_printf("[FLOCK] flock(fd=%d, operation=0x%x) -> EBADF (negative fd)\n",
                   fd, operation);
        return -EBADF;
    }

    if (fd >= task->max_fds) {
        fut_printf("[FLOCK] flock(fd=%d, max_fds=%d, operation=0x%x) -> EBADF "
                   "(fd exceeds max_fds, Phase 5: FD bounds validation)\n",
                   fd, task->max_fds, operation);
        return -EBADF;
    }

    /* Phase 2: Categorize FD range - use shared helper */
    const char *fd_category = fut_fd_category(fd);

    /* Validate file descriptor */
    struct fut_file *file = vfs_get_file_from_task(task, fd);
    if (!file) {
        char msg[256];
        int pos = 0;
        const char *text = "[FLOCK] flock(fd=";
        while (*text) { msg[pos++] = *text++; }

        char num[16]; int num_pos = 0; int val = fd;
        if (val == 0) { num[num_pos++] = '0'; }
        else { char temp[16]; int temp_pos = 0;
            int is_neg = 0;
            if (val < 0) { is_neg = 1; val = -val; }
            while (val > 0) { temp[temp_pos++] = '0' + (val % 10); val /= 10; }
            if (is_neg) num[num_pos++] = '-';
            while (temp_pos > 0) { num[num_pos++] = temp[--temp_pos]; } }
        num[num_pos] = '\0';
        for (int i = 0; num[i]; i++) { msg[pos++] = num[i]; }

        text = " [";
        while (*text) { msg[pos++] = *text++; }
        while (*fd_category) { msg[pos++] = *fd_category++; }
        text = "]) -> EBADF (fd not open, pid=";
        while (*text) { msg[pos++] = *text++; }

        num_pos = 0; unsigned int uval = task->pid;
        if (uval == 0) { num[num_pos++] = '0'; }
        else { char temp[16]; int temp_pos = 0;
            while (uval > 0) { temp[temp_pos++] = '0' + (uval % 10); uval /= 10; }
            while (temp_pos > 0) { num[num_pos++] = temp[--temp_pos]; } }
        num[num_pos] = '\0';
        for (int i = 0; num[i]; i++) { msg[pos++] = num[i]; }

        text = ")\n";
        while (*text) { msg[pos++] = *text++; }
        msg[pos] = '\0';
        fut_printf("%s", msg);

        return -EBADF;
    }

    /* Phase 2: Categorize operation */
    int op = operation & ~LOCK_NB;
    int is_nonblock = (operation & LOCK_NB) != 0;

    const char *op_name;

    if (op == LOCK_SH) {
        op_name = "LOCK_SH";
    } else if (op == LOCK_EX) {
        op_name = "LOCK_EX";
    } else if (op == LOCK_UN) {
        op_name = "LOCK_UN";
    } else {
        op_name = "INVALID";
    }

    /* Validate operation */
    if (op != LOCK_SH && op != LOCK_EX && op != LOCK_UN) {
        char msg[256];
        int pos = 0;
        const char *text = "[FLOCK] flock(fd=";
        while (*text) { msg[pos++] = *text++; }

        char num[16]; int num_pos = 0; int val = fd;
        if (val == 0) { num[num_pos++] = '0'; }
        else { char temp[16]; int temp_pos = 0;
            while (val > 0) { temp[temp_pos++] = '0' + (val % 10); val /= 10; }
            while (temp_pos > 0) { num[num_pos++] = temp[--temp_pos]; } }
        num[num_pos] = '\0';
        for (int i = 0; num[i]; i++) { msg[pos++] = num[i]; }

        text = ", operation=0x";
        while (*text) { msg[pos++] = *text++; }

        /* Convert operation to hex */
        char hex[16]; int hex_pos = 0;
        unsigned int hex_val = (unsigned int)operation;
        if (hex_val == 0) { hex[hex_pos++] = '0'; }
        else {
            char temp[16]; int temp_pos = 0;
            while (hex_val > 0) {
                int digit = hex_val % 16;
                temp[temp_pos++] = (digit < 10) ? ('0' + digit) : ('a' + digit - 10);
                hex_val /= 16;
            }
            while (temp_pos > 0) { hex[hex_pos++] = temp[--temp_pos]; }
        }
        hex[hex_pos] = '\0';
        for (int i = 0; hex[i]; i++) { msg[pos++] = hex[i]; }

        text = ") -> EINVAL (invalid operation, expected LOCK_SH/EX/UN)\n";
        while (*text) { msg[pos++] = *text++; }
        msg[pos] = '\0';
        fut_printf("%s", msg);

        return -EINVAL;
    }

    /* Phase 3: Get vnode for lock operations */
    struct fut_vnode *vnode = file->vnode;
    if (!vnode) {
        fut_printf("[FLOCK] flock(fd=%d, operation=%s%s) -> EBADF (no vnode)\n",
                   fd, op_name, is_nonblock ? "|LOCK_NB" : "");
        return -EBADF;
    }

    /* Phase 3: Perform actual lock operation */
    int ret = 0;
    uint32_t pid = task->pid;

    if (op == LOCK_SH) {
        /* Acquire shared lock */
        ret = fut_vnode_lock_shared(vnode, pid, is_nonblock);
        if (ret < 0) {
            const char *error_desc = (ret == -EAGAIN) ? "would block" : "lock failed";
            fut_printf("[FLOCK] flock(fd=%d [%s], operation=%s%s, pid=%u) -> %d (%s, Phase 3)\n",
                       fd, fd_category, op_name, is_nonblock ? "|LOCK_NB" : "",
                       pid, ret, error_desc);
            return ret;
        }
    } else if (op == LOCK_EX) {
        /* Acquire exclusive lock */
        ret = fut_vnode_lock_exclusive(vnode, pid, is_nonblock);
        if (ret < 0) {
            const char *error_desc = (ret == -EAGAIN) ? "would block" : "lock failed";
            fut_printf("[FLOCK] flock(fd=%d [%s], operation=%s%s, pid=%u) -> %d (%s, Phase 3)\n",
                       fd, fd_category, op_name, is_nonblock ? "|LOCK_NB" : "",
                       pid, ret, error_desc);
            return ret;
        }
    } else if (op == LOCK_UN) {
        /* Release lock */
        ret = fut_vnode_unlock(vnode, pid);
        if (ret < 0) {
            fut_printf("[FLOCK] flock(fd=%d [%s], operation=%s, pid=%u) -> %d (unlock failed, Phase 3)\n",
                       fd, fd_category, op_name, pid, ret);
            return ret;
        }
    }

    /* Success - get lock info for detailed logging */
    uint32_t lock_type_num, lock_count, lock_owner;
    fut_vnode_lock_get_info(vnode, &lock_type_num, &lock_count, &lock_owner);

    const char *lock_state;
    if (lock_type_num == 0) {
        lock_state = "unlocked";
    } else if (lock_type_num == 1) {
        lock_state = "shared";
    } else {
        lock_state = "exclusive";
    }

    fut_printf("[FLOCK] flock(fd=%d [%s], operation=%s%s, pid=%u) -> 0 "
               "(lock_state=%s, count=%u, owner=%u, Phase 3)\n",
               fd, fd_category, op_name, is_nonblock ? "|LOCK_NB" : "",
               pid, lock_state, lock_count, lock_owner);

    return 0;
}
