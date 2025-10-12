/* posix_syscall.c - POSIX Syscall Dispatch Layer
 *
 * Copyright (c) 2025 Kelsi Davis
 * Licensed under the MPL v2.0 — see LICENSE for details.
 *
 * Central syscall dispatch mechanism for POSIX compatibility.
 * Maps syscall numbers to handler functions.
 */

#include "posix_shim.h"
#include <stdint.h>
#include <stddef.h>
#include <kernel/syscalls.h>
#include <kernel/uaccess.h>
#include <kernel/fut_vfs.h>
#include <kernel/fut_memory.h>
#include <kernel/errno.h>

/* ============================================================
 *   Syscall Numbers
 * ============================================================ */

/* Standard POSIX syscall numbers (subset) */
#define SYS_read        0
#define SYS_write       1
#define SYS_open        2
#define SYS_close       3
#define SYS_stat        4
#define SYS_fstat       5
#define SYS_lseek       8
#define SYS_mmap        9
#define SYS_munmap      11
#define SYS_brk         12
#define SYS_ioctl       16
#define SYS_pipe        22
#define SYS_select      23
#define SYS_dup         32
#define SYS_dup2        33
#define SYS_fork        57
#define SYS_execve      59
#ifndef SYS_exit
#define SYS_exit        60
#endif
#define SYS_wait4       61
#define SYS_kill        62
#define SYS_getpid      39
#define SYS_socket      41
#define SYS_connect     42
#define SYS_accept      43
#define SYS_sendto      44
#define SYS_recvfrom    45
#define SYS_bind        49
#define SYS_listen      50
#define SYS_getcwd      79
#define SYS_chdir       80
#define SYS_mkdir       83
#define SYS_rmdir       84
#define SYS_unlink      87
#define SYS_readlink    89
#define SYS_chmod       90
#define SYS_getuid      102
#define SYS_getgid      104
#define SYS_gettimeofday 96

#ifndef SYS_time_millis
#define SYS_time_millis  400
#endif

#define MAX_SYSCALL     512

/* ============================================================
 *   Syscall Handler Type
 * ============================================================ */

typedef int64_t (*syscall_handler_t)(uint64_t arg1, uint64_t arg2,
                                      uint64_t arg3, uint64_t arg4,
                                      uint64_t arg5, uint64_t arg6);

extern ssize_t sys_echo(const char *u_in, char *u_out, size_t n);
extern long sys_exit(int status);
extern long sys_waitpid(int pid, int *u_status, int flags);
extern long sys_time_millis(void);

static int64_t sys_echo_handler(uint64_t arg1, uint64_t arg2, uint64_t arg3,
                                uint64_t arg4, uint64_t arg5, uint64_t arg6) {
    (void)arg4;
    (void)arg5;
    (void)arg6;
    return (int64_t)sys_echo((const char *)arg1, (char *)arg2, (size_t)arg3);
}

static int copy_user_string(const char *u_path, char *kbuf, size_t max_len) {
    for (size_t i = 0; i < max_len; ++i) {
        char ch = 0;
        if (fut_copy_from_user(&ch, u_path + i, 1) != 0) {
            return -EFAULT;
        }
        kbuf[i] = ch;
        if (ch == '\0') {
            return 0;
        }
    }
    return -ENAMETOOLONG;
}

static int64_t sys_open_handler(uint64_t pathname, uint64_t flags, uint64_t mode,
                                uint64_t arg4, uint64_t arg5, uint64_t arg6) {
    (void)arg4;
    (void)arg5;
    (void)arg6;

    char kpath[256];
    int rc = copy_user_string((const char *)pathname, kpath, sizeof(kpath));
    if (rc != 0) {
        return rc;
    }
    return (int64_t)fut_vfs_open(kpath, (int)flags, (int)mode);
}

static int64_t sys_close_handler(uint64_t fd, uint64_t arg2, uint64_t arg3,
                                 uint64_t arg4, uint64_t arg5, uint64_t arg6) {
    (void)arg2;
    (void)arg3;
    (void)arg4;
    (void)arg5;
    (void)arg6;
    return (int64_t)fut_vfs_close((int)fd);
}

static int64_t sys_write_handler(uint64_t fd, uint64_t buf, uint64_t count,
                                 uint64_t arg4, uint64_t arg5, uint64_t arg6) {
    (void)arg4;
    (void)arg5;
    (void)arg6;

    size_t len = (size_t)count;
    if (len == 0) {
        return 0;
    }

    void *kbuf = fut_malloc(len);
    if (!kbuf) {
        return -ENOMEM;
    }

    if (fut_copy_from_user(kbuf, (const void *)buf, len) != 0) {
        fut_free(kbuf);
        return -EFAULT;
    }

    ssize_t ret = fut_vfs_write((int)fd, kbuf, len);
    fut_free(kbuf);
    return (int64_t)ret;
}

static int64_t sys_read_handler(uint64_t fd, uint64_t buf, uint64_t count,
                                uint64_t arg4, uint64_t arg5, uint64_t arg6) {
    (void)arg4;
    (void)arg5;
    (void)arg6;

    size_t len = (size_t)count;
    if (len == 0) {
        return 0;
    }

    void *kbuf = fut_malloc(len);
    if (!kbuf) {
        return -ENOMEM;
    }

    ssize_t ret = fut_vfs_read((int)fd, kbuf, len);
    if (ret > 0) {
        if (fut_copy_to_user((void *)buf, kbuf, (size_t)ret) != 0) {
            ret = -EFAULT;
        }
    }

    fut_free(kbuf);
    return (int64_t)ret;
}

static int64_t sys_ioctl_handler(uint64_t fd, uint64_t req, uint64_t argp,
                                 uint64_t arg4, uint64_t arg5, uint64_t arg6) {
    (void)arg4;
    (void)arg5;
    (void)arg6;
    return (int64_t)fut_vfs_ioctl((int)fd, req, argp);
}

static int64_t sys_mmap_handler(uint64_t addr, uint64_t len, uint64_t prot,
                                uint64_t flags, uint64_t fd, uint64_t off) {
    void *res = fut_vfs_mmap((int)fd, (void *)addr, (size_t)len, (int)prot, (int)flags, (off_t)off);
    return (int64_t)(intptr_t)res;
}

/* ============================================================
 *   Syscall Handlers (Wrappers)
 * ============================================================ */

/* File I/O */
/* File metadata */
static int64_t sys_stat_handler(uint64_t pathname, uint64_t statbuf, uint64_t arg3,
                                 uint64_t arg4, uint64_t arg5, uint64_t arg6) {
    (void)arg3; (void)arg4; (void)arg5; (void)arg6;
    return (int64_t)posix_stat((const char *)pathname, (struct posix_stat *)statbuf);
}

static int64_t sys_fstat_handler(uint64_t fd, uint64_t statbuf, uint64_t arg3,
                                   uint64_t arg4, uint64_t arg5, uint64_t arg6) {
    (void)arg3; (void)arg4; (void)arg5; (void)arg6;
    return (int64_t)posix_fstat((int)fd, (struct posix_stat *)statbuf);
}

/* Process management */
static int64_t sys_fork_handler(uint64_t arg1, uint64_t arg2, uint64_t arg3,
                                 uint64_t arg4, uint64_t arg5, uint64_t arg6) {
    (void)arg1; (void)arg2; (void)arg3; (void)arg4; (void)arg5; (void)arg6;
    return (int64_t)posix_fork();
}

static int64_t sys_execve_handler(uint64_t pathname, uint64_t argv, uint64_t envp,
                                    uint64_t arg4, uint64_t arg5, uint64_t arg6) {
    (void)arg4; (void)arg5; (void)arg6;
    return (int64_t)posix_execve((const char *)pathname, (char *const *)argv,
                                  (char *const *)envp);
}

static int64_t sys_exit_handler(uint64_t status, uint64_t arg2, uint64_t arg3,
                                 uint64_t arg4, uint64_t arg5, uint64_t arg6) {
    (void)arg2; (void)arg3; (void)arg4; (void)arg5; (void)arg6;
    sys_exit((int)status);
    return 0;
}

static int64_t sys_wait4_handler(uint64_t pid, uint64_t status, uint64_t options,
                                   uint64_t rusage, uint64_t arg5, uint64_t arg6) {
    (void)rusage; (void)arg5; (void)arg6;
    return (int64_t)sys_waitpid((int)pid, (int *)(uintptr_t)status, (int)options);
}

static int64_t sys_time_millis_handler(uint64_t arg1, uint64_t arg2, uint64_t arg3,
                                       uint64_t arg4, uint64_t arg5, uint64_t arg6) {
    (void)arg1; (void)arg2; (void)arg3; (void)arg4; (void)arg5; (void)arg6;
    return sys_time_millis();
}

/* Memory management */
static int64_t sys_brk_handler(uint64_t addr, uint64_t arg2, uint64_t arg3,
                                uint64_t arg4, uint64_t arg5, uint64_t arg6) {
    (void)addr; (void)arg2; (void)arg3; (void)arg4; (void)arg5; (void)arg6;
    /* Phase 2: Stub - return current break */
    return -1;
}

/* Unimplemented syscall handler */
static int64_t sys_unimplemented(uint64_t arg1, uint64_t arg2, uint64_t arg3,
                                  uint64_t arg4, uint64_t arg5, uint64_t arg6) {
    (void)arg1; (void)arg2; (void)arg3; (void)arg4; (void)arg5; (void)arg6;
    return -1;  /* ENOSYS */
}

/* ============================================================
 *   Syscall Table
 * ============================================================ */

static syscall_handler_t syscall_table[MAX_SYSCALL] = {
    [SYS_read]       = sys_read_handler,
    [SYS_write]      = sys_write_handler,
    [SYS_open]       = sys_open_handler,
    [SYS_close]      = sys_close_handler,
    [SYS_stat]       = sys_stat_handler,
    [SYS_fstat]      = sys_fstat_handler,
    [SYS_fork]       = sys_fork_handler,
    [SYS_execve]     = sys_execve_handler,
    [SYS_exit]       = sys_exit_handler,
    [SYS_wait4]      = sys_wait4_handler,
    [SYS_brk]        = sys_brk_handler,
    [SYS_echo]       = sys_echo_handler,
    [SYS_ioctl]      = sys_ioctl_handler,
    [SYS_mmap]       = sys_mmap_handler,
    [SYS_time_millis] = sys_time_millis_handler,
};

/* ============================================================
 *   Syscall Dispatcher
 * ============================================================ */

/**
 * Main syscall dispatch function.
 * Called from architecture-specific syscall entry point.
 *
 * @param syscall_num Syscall number
 * @param arg1-arg6   Syscall arguments
 * @return Syscall return value (or -errno on error)
 */
int64_t posix_syscall_dispatch(uint64_t syscall_num,
                                uint64_t arg1, uint64_t arg2, uint64_t arg3,
                                uint64_t arg4, uint64_t arg5, uint64_t arg6) {
    /* Validate syscall number */
    if (syscall_num >= MAX_SYSCALL) {
        return -1;  /* ENOSYS */
    }

    /* Get handler from table */
    syscall_handler_t handler = syscall_table[syscall_num];
    if (handler == NULL) {
        handler = sys_unimplemented;
    }

    /* Call handler */
    return handler(arg1, arg2, arg3, arg4, arg5, arg6);
}

/* ============================================================
 *   Syscall Initialization
 * ============================================================ */

/**
 * Initialize POSIX syscall subsystem.
 */
void posix_syscall_init(void) {
    /* Initialize unimplemented syscalls */
    for (int i = 0; i < MAX_SYSCALL; i++) {
        if (syscall_table[i] == NULL) {
            syscall_table[i] = sys_unimplemented;
        }
    }
}

long syscall_entry_c(uint64_t nr,
                     uint64_t a1, uint64_t a2, uint64_t a3,
                     uint64_t a4, uint64_t a5, uint64_t a6) {
    return (long)posix_syscall_dispatch(nr, a1, a2, a3, a4, a5, a6);
}
