/* kernel/sys_kcmp.c - kcmp() syscall (Linux 3.5)
 *
 * Copyright (c) 2025 Kelsi Davis
 * Licensed under the MPL v2.0 — see LICENSE for details.
 *
 * kcmp() allows comparing kernel objects between processes.
 * Used by checkpoint/restore tools (CRIU) and debugging utilities.
 *
 * Phase 1 (Completed):
 *   - KCMP_FILE: compare whether pid1/fd1 and pid2/fd2 refer to the same file
 *   - KCMP_VM: compare whether two pids share VM (always 0 in Futura)
 *   - KCMP_FILES: compare whether two pids share fd table (always 0)
 *   - KCMP_FS, KCMP_SIGHAND, KCMP_IO: always different (0 not applicable)
 *   Returns: <0, 0, >0 (like strcmp) or -errno
 */

#include <kernel/fut_task.h>
#include <kernel/errno.h>
#include <kernel/fut_vfs.h>
#include <kernel/kprintf.h>
#include <stddef.h>
#include <stdint.h>
#include <stdbool.h>

/* kcmp types */
#define KCMP_FILE      0
#define KCMP_VM        1
#define KCMP_FILES     2
#define KCMP_FS        3
#define KCMP_SIGHAND   4
#define KCMP_IO        5
#define KCMP_SYSVSEM   6
#define KCMP_EPOLL_TFD 7
#define KCMP_TYPES     8

/**
 * sys_kcmp - Compare kernel resources of two processes.
 *
 * @param pid1   First process PID
 * @param pid2   Second process PID
 * @param type   Type of comparison (KCMP_*)
 * @param idx1   Index 1 (e.g., fd for KCMP_FILE)
 * @param idx2   Index 2 (e.g., fd for KCMP_FILE)
 * @return 0 if same object, 1 if different, -errno on error
 */
long sys_kcmp(int pid1, int pid2, int type,
              unsigned long idx1, unsigned long idx2) {
    if (type < 0 || type >= KCMP_TYPES)
        return -EINVAL;
    /* Futura test 231 pins kcmp(pid1=0, ...) -> EINVAL (Linux returns
     * ESRCH after find_task_by_vpid(0) fails).  Per the project rule
     * 'Futura's local tests take precedence over Linux ABI parity',
     * keep EINVAL for non-positive pids so the test stays green. */
    if (pid1 <= 0 || pid2 <= 0)
        return -EINVAL;

    fut_task_t *task1 = fut_task_by_pid((uint64_t)pid1);
    fut_task_t *task2 = fut_task_by_pid((uint64_t)pid2);
    if (!task1 || !task2)
        return -ESRCH;

    /* PTRACE_MODE_READ_REALCREDS on both targets, matching Linux.
     * Without this gate any unprivileged caller could probe whether
     * two arbitrary processes share fd tables, file objects, or
     * VM/IO/sighand objects — useful sandbox-escape recon (e.g.
     * detecting that a privileged daemon shares a file with the
     * caller's helper). */
    fut_task_t *self = fut_task_current();
    if (self) {
        bool privileged = (self->uid == 0) ||
            (self->cap_effective & (1ULL << 19 /* CAP_SYS_PTRACE */));
        if (!privileged) {
            if (self->uid != task1->uid || self->uid != task2->uid)
                return -EPERM;
        }
    }

    switch (type) {
    case KCMP_FILE: {
        /* Compare whether pid1:fd1 and pid2:fd2 reference the same file object */
        int fd1 = (int)idx1, fd2 = (int)idx2;
        if (fd1 < 0 || fd2 < 0) return -EBADF;
        if (!task1->fd_table || fd1 >= task1->max_fds) return -EBADF;
        if (!task2->fd_table || fd2 >= task2->max_fds) return -EBADF;

        struct fut_file *f1 = task1->fd_table[fd1];
        struct fut_file *f2 = task2->fd_table[fd2];
        if (!f1 || !f2) return -EBADF;

        /* Same pointer → same file object */
        if (f1 == f2) return 0;
        /* Different objects: return Linux kcmp ordering — 1 if v1 < v2,
         * 2 if v1 > v2. Returning -1 here would be interpreted by
         * userspace as an -EPERM errno, breaking CRIU's file-share
         * detection. */
        return (uintptr_t)f1 < (uintptr_t)f2 ? 1 : 2;
    }

    case KCMP_VM:
        /* Compare the actual mm. Two threads in the same process share one
         * fut_mm; two ordinary fork()-children get distinct mms. The old
         * blanket 'return 0' falsely told CRIU and similar tools that any
         * two unrelated processes share VM, so dump-restore decisions
         * based on kcmp would treat them as a single thread group. */
        if (task1->mm == task2->mm) return 0;
        return (uintptr_t)task1->mm < (uintptr_t)task2->mm ? 1 : 2;

    case KCMP_FILES:
        /* Linux's kcmp returns 0 when the two objects are the same and
         * 1/2 based on pointer ordering for the 'different' case (via
         * kptr_obfuscate).  CRIU dumps fd tables in the order kcmp
         * reports, so a blanket '1' for the different case caused
         * non-deterministic fd-table dumps that could mismatch on
         * restore.  Mirror the matching KCMP_FILE / KCMP_VM ordering. */
        if (task1->fd_table == task2->fd_table) return 0;
        return (uintptr_t)task1->fd_table < (uintptr_t)task2->fd_table ? 1 : 2;

    case KCMP_FS:
    case KCMP_SIGHAND:
    case KCMP_IO:
    case KCMP_SYSVSEM:
        /* These kernel objects are per-task in Futura.  Same task =>
         * shared; different tasks => use task-pointer ordering so
         * userspace gets deterministic 1-vs-2 like Linux. */
        if (task1 == task2) return 0;
        return (uintptr_t)task1 < (uintptr_t)task2 ? 1 : 2;

    default:
        return -EINVAL;
    }
}
