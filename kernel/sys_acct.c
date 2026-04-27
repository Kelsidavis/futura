/* kernel/sys_acct.c - Process accounting syscall
 *
 * Copyright (c) 2025 Kelsi Davis
 * Licensed under the MPL v2.0 — see LICENSE for details.
 *
 * Implements process accounting for tracking system resource usage.
 * Essential for system auditing, billing, and resource monitoring.
 *
 * Phase 1 (Completed): Validation and stub implementation
 * Phase 2 (Completed): Enhanced validation, file path handling, operation type categorization
 * Phase 3 (Completed): Open accounting file and initialize record structure
 * Phase 4 (Completed): Generate and write accounting records on process exit
 */

#include <kernel/fut_task.h>
#include <kernel/fut_thread.h>
#include <kernel/fut_vfs.h>
#include <kernel/fut_timer.h>
#include <kernel/errno.h>
#include <stddef.h>
#include <stdbool.h>

#include <kernel/kprintf.h>
#include <kernel/uaccess.h>
#include <string.h>

#include <platform/platform.h>

static inline int acct_copy_from_user(void *dst, const void *src, size_t n) {
#ifdef KERNEL_VIRTUAL_BASE
    if ((uintptr_t)src >= KERNEL_VIRTUAL_BASE) { __builtin_memcpy(dst, src, n); return 0; }
#endif
    return fut_copy_from_user(dst, src, n);
}

/* ============================================================
 *   Accounting Record Format
 * ============================================================ */

/**
 * fut_acct_record - Kernel process accounting record
 *
 * Written to the accounting file when a process exits (if acct(2) is enabled).
 * Provides basic audit trail: who ran what, when it exited, and how much CPU
 * it consumed.  Intentionally compact — fields not tracked yet are zero.
 */
struct fut_acct_record {
    char     ac_comm[16];    /* Command identifier (PID as decimal string) */
    uint32_t ac_pid;         /* Process ID */
    uint32_t ac_ppid;        /* Parent process ID */
    uint32_t ac_uid;         /* Real user ID */
    uint32_t ac_gid;         /* Real group ID */
    uint32_t ac_exitcode;    /* Exit code (0 if killed by signal) */
    uint8_t  ac_term_signal; /* Termination signal (0 = normal exit) */
    uint8_t  _pad[3];        /* Alignment padding */
    uint64_t ac_etime_ms;    /* Monotonic time at exit (ms since boot) */
    uint64_t ac_cpu_ticks;   /* Total CPU ticks consumed by all threads */
};

/* ============================================================
 *   Global Accounting State
 * ============================================================ */

static char  acct_path[FUT_VFS_PATH_BUFFER_SIZE];
static bool  acct_enabled = false;

/* ============================================================
 *   acct_write_record — called on process exit
 * ============================================================ */

/**
 * acct_write_record - Write an accounting record for the exiting task.
 *
 * Called from task_cleanup_and_exit() before the task is marked as a zombie.
 * At this point task->threads still contains the exiting thread so we can
 * read its cpu_ticks.
 *
 * @param task    Exiting task
 * @param status  Exit status code
 * @param signal  Termination signal (0 = normal exit)
 */
void acct_write_record(fut_task_t *task, int status, int signal) {
    if (!acct_enabled || !task) {
        return;
    }

    /* Build the accounting record */
    struct fut_acct_record rec;
    memset(&rec, 0, sizeof(rec));

    rec.ac_pid  = (uint32_t)task->pid;
    rec.ac_ppid = task->parent ? (uint32_t)task->parent->pid : 0;
    rec.ac_uid  = task->ruid;
    rec.ac_gid  = task->rgid;
    rec.ac_exitcode    = (uint8_t)(status & 0xFF);
    rec.ac_term_signal = (uint8_t)(signal & 0xFF);
    rec.ac_etime_ms    = fut_get_ticks();

    /* Sum CPU ticks across all threads (still attached at this point) */
    uint64_t total_ticks = 0;
    for (fut_thread_t *t = task->threads; t != NULL; t = t->next) {
        total_ticks += t->stats.cpu_ticks;
    }
    rec.ac_cpu_ticks = total_ticks + task->child_cpu_ticks;

    /* Encode PID as command identifier (we have no argv[0] yet) */
    /* Simple itoa into ac_comm */
    uint64_t pid = task->pid;
    int pos = 15;
    rec.ac_comm[pos] = '\0';
    if (pid == 0) {
        rec.ac_comm[--pos] = '0';
    } else {
        while (pid > 0 && pos > 0) {
            rec.ac_comm[--pos] = '0' + (int)(pid % 10);
            pid /= 10;
        }
    }
    /* Left-justify the string */
    if (pos > 0) {
        int len = 15 - pos;
        for (int i = 0; i < len; i++) {
            rec.ac_comm[i] = rec.ac_comm[pos + i];
        }
        rec.ac_comm[len] = '\0';
    }

    /* Open accounting file in append mode and write the record.
     * Use the kernel-level VFS open so we bypass copy_from_user. */
    int fd = fut_vfs_open(acct_path, O_WRONLY | O_APPEND, 0);
    if (fd < 0) {
        /* Silently disable accounting if the file becomes inaccessible */
        fut_printf("[ACCT] acct_write_record: failed to open '%s' (err=%d) — disabling\n",
                   acct_path, fd);
        acct_enabled = false;
        return;
    }

    ssize_t written = fut_vfs_write(fd, &rec, sizeof(rec));
    fut_vfs_close(fd);

    if (written != (ssize_t)sizeof(rec)) {
        fut_printf("[ACCT] acct_write_record: short write (%zd/%zu) for pid=%u\n",
                   written, sizeof(rec), rec.ac_pid);
    } else {
        fut_printf("[ACCT] acct_write_record: pid=%u uid=%u cpu=%llu ticks exit=%u sig=%u\n",
                   rec.ac_pid, rec.ac_uid,
                   (unsigned long long)rec.ac_cpu_ticks,
                   rec.ac_exitcode, rec.ac_term_signal);
    }
}

/* ============================================================
 *   sys_acct
 * ============================================================ */

/**
 * acct() - Enable or disable process accounting
 *
 * Enables or disables the recording of process accounting information.
 * When enabled, the kernel writes an accounting record to the specified
 * file whenever a process terminates. This is used for system auditing,
 * billing, and resource usage analysis.
 *
 * @param filename  Path to accounting file, or NULL to disable accounting
 *
 * Returns:
 *   - 0 on success
 *   - -EFAULT if filename points to invalid memory
 *   - -EACCES if file is not a regular file
 *   - -EPERM if caller does not have CAP_SYS_PACCT capability
 *   - -EIO if I/O error occurs opening the file
 *   - -ENOENT if file does not exist
 *   - -EROFS if filesystem is read-only
 *
 * Phase 1 (Completed): Validate parameters and accept enable/disable requests
 * Phase 2 (Completed): Enhanced validation, file path categorization, operation type detection
 * Phase 3 (Completed): Open accounting file and initialize record structure
 * Phase 4 (Completed): Generate and write accounting records on process exit
 */
long sys_acct(const char *filename) {
    /* Phase 2: Get current task for validation and logging */
    fut_task_t *task = fut_task_current();
    if (!task) {
        return -ESRCH;
    }

    /* Linux: acct(2) requires CAP_SYS_PACCT, which is capability number
     * 20 (per linux/capability.h and Futura's own include/sys/capability.h).
     * The previous code shifted by 32 — that's not even a valid Linux
     * capability bit, so a properly-privileged caller (root or
     * CAP_SYS_PACCT) was correctly allowed via the uid==0 fast path,
     * but a non-root caller granted CAP_SYS_PACCT via setcap was
     * incorrectly rejected because we were checking the wrong bit. The
     * disable path also needs the cap so an attacker can't silently
     * turn off audit logging. */
    if (task->uid != 0 &&
        !(task->cap_effective & (1ULL << 20 /* CAP_SYS_PACCT */))) {
        fut_printf("[ACCT] acct() -> EPERM (CAP_SYS_PACCT required)\n");
        return -EPERM;
    }

    /* Phase 2: Check if disabling accounting (NULL filename) */
    if (filename == NULL) {
        acct_enabled = false;
        acct_path[0] = '\0';
        fut_printf("[ACCT] acct(NULL) -> 0 (accounting disabled, pid=%llu)\n",
                   (unsigned long long)task->pid);
        return 0;
    }

    /* Copy filename from userspace (full buffer to detect truncation)
     * VULNERABILITY: Uninitialized Byte in Truncation Check
     * Previously copied sizeof(buf)-1 bytes but checked memchr over sizeof(buf),
     * leaving the last byte uninitialized and making truncation detection unreliable.
     * DEFENSE: Copy full buffer size so all bytes are initialized for memchr check. */
    char path_buf[FUT_VFS_PATH_BUFFER_SIZE];
    if (acct_copy_from_user(path_buf, filename, sizeof(path_buf)) != 0) {
        fut_printf("[ACCT] acct(filename=?, pid=%llu) -> EFAULT "
                   "(filename copy_from_user failed)\n",
                   (unsigned long long)task->pid);
        return -EFAULT;
    }
    /* Verify path was not truncated */
    if (memchr(path_buf, '\0', sizeof(path_buf)) == NULL) {
        fut_printf("[ACCT] acct(path exceeds %zu bytes, pid=%llu) -> ENAMETOOLONG\n",
                   sizeof(path_buf) - 1, (unsigned long long)task->pid);
        return -ENAMETOOLONG;
    }

    /* Empty filename is ENOENT per Linux acct(2). */
    if (path_buf[0] == '\0') {
        fut_printf("[ACCT] acct(filename=\"\", pid=%llu) -> ENOENT\n",
                   (unsigned long long)task->pid);
        return -ENOENT;
    }

    /* Validate the accounting file. Linux acct(2) does NOT create the
     * file: filp_open uses O_RDWR|O_APPEND|O_LARGEFILE with no O_CREAT,
     * so a missing file returns -ENOENT (caller is expected to create
     * it ahead of time). The previous code passed O_CREAT, which let a
     * caller materialise an arbitrary 0600 file at any path the kernel
     * could touch — a path-typo accidental-creation hazard, and a
     * silent ABI deviation from Linux. Test 655 already creates the
     * file before calling acct() so this path remains green. */
    int fd = fut_vfs_open(path_buf, O_WRONLY | O_APPEND, 0);
    if (fd < 0) {
        fut_printf("[ACCT] acct(filename='%s', pid=%llu) -> %d "
                   "(failed to open accounting file)\n",
                   path_buf, (unsigned long long)task->pid, fd);
        return fd;
    }
    /* Linux's acct(2) rejects non-regular files with -EACCES after the
     * open succeeds: 'if (!S_ISREG(file_inode(file)->i_mode)) goto
     * out_putf' (kernel/acct.c:acct_on). Without this check Futura
     * would happily install a FIFO, character/block device, or socket
     * as the accounting "file" and silently dump per-process exit
     * records into it on every task exit — depending on the target,
     * that's either a write-anywhere primitive (device) or a system-
     * wide DoS hang (FIFO with no reader). */
    {
        struct fut_file *acct_file = fut_vfs_get_file(fd);
        if (acct_file && acct_file->vnode &&
            acct_file->vnode->type != VN_REG) {
            fut_vfs_close(fd);
            fut_printf("[ACCT] acct(filename='%s', pid=%llu) -> EACCES "
                       "(not a regular file: type=%d)\n",
                       path_buf, (unsigned long long)task->pid,
                       acct_file->vnode->type);
            return -EACCES;
        }
    }
    fut_vfs_close(fd);

    /* Enable accounting and store the path */
    memcpy(acct_path, path_buf, sizeof(acct_path));
    acct_enabled = true;

    fut_printf("[ACCT] acct(filename='%s', pid=%llu) -> 0 (accounting enabled)\n",
               acct_path, (unsigned long long)task->pid);
    return 0;
}
