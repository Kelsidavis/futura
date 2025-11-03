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
#include <kernel/fut_task.h>
#include <kernel/errno.h>
#include <kernel/fut_socket.h>
#include <kernel/signal.h>
#include <kernel/signal_frame.h>
#include <arch/x86_64/regs.h>

/* ============================================================
 *   Syscall Numbers
 * ============================================================ */

/* Standard POSIX syscall numbers (subset) */
#define SYS_read        0
#define SYS_write       1
#define SYS_open        2
#define SYS_close       3
#define SYS_openat      257
#define AT_FDCWD        -100
#define SYS_stat        4
#define SYS_fstat       5
#define SYS_lstat       6
#define SYS_poll        7
#define SYS_lseek       8
#ifndef SYS_mmap
#define SYS_mmap        9
#endif
#define SYS_mprotect    10
#ifndef SYS_munmap
#define SYS_munmap      11
#endif
#ifndef SYS_brk
#define SYS_brk         12
#endif
#define SYS_ioctl       16
#define SYS_pread64     17
#define SYS_pwrite64    18
#define SYS_pipe        22
#define SYS_select      23
#define SYS_sched_yield 24
#define SYS_dup         32
#define SYS_dup2        33
#define SYS_pause       34
#define SYS_alarm       37
#define SYS_fcntl       72
#define SYS_flock       73
#define SYS_fsync       74
#define SYS_fdatasync   75
#define SYS_truncate    76
#define SYS_ftruncate   77
#define SYS_fork        57
#define SYS_execve      59
#ifndef SYS_exit
#define SYS_exit        60
#endif
#define SYS_wait4       61
#define SYS_kill        62
#define SYS_uname       63
#define SYS_sigaction   13
#define SYS_sigprocmask 14
#define SYS_sigreturn   15
#define SYS_getpid      39
#define SYS_gettid      186
#define SYS_socket      41
#define SYS_connect     46  /* Note: non-standard, should be 42 per Linux ABI */
#define SYS_accept      43
#define SYS_sendto      44
#define SYS_recvfrom    45
#define SYS_bind        49
#define SYS_listen      50
#ifndef SYS_getcwd
#define SYS_getcwd      79
#endif
#ifndef SYS_chdir
#define SYS_chdir       80
#endif
#define SYS_mkdir       83
#define SYS_rmdir       84
#define SYS_link        86
#define SYS_unlink      87
#define SYS_symlink     88
#define SYS_readlink    89
#ifndef SYS_chmod
#define SYS_chmod       90
#endif
#ifndef SYS_fchmod
#define SYS_fchmod      91
#endif
#ifndef SYS_chown
#define SYS_chown       92
#endif
#ifndef SYS_fchown
#define SYS_fchown      93
#endif
#ifndef SYS_getuid
#define SYS_getuid      102
#endif
#ifndef SYS_getgid
#define SYS_getgid      104
#endif
#define SYS_umask        95
#define SYS_gettimeofday 96
#define SYS_getrlimit    97
#define SYS_clock_gettime 98
#define SYS_getrusage    99
#define SYS_times        100
#define SYS_setrlimit    160
#define SYS_time         201
#define SYS_getdents64   217
#define SYS_getpriority  140
#define SYS_setpriority  141

#ifndef SYS_time_millis
#define SYS_time_millis  400
#endif

#define MAX_SYSCALL     512

/* ============================================================
 *   Socket FD Mapping System
 * ============================================================ */

/** Maximum number of socket file descriptors per task */
#define MAX_SOCKET_FDS 256

/** Per-task socket FD table mapping FDs to kernel socket objects */
static fut_socket_t *socket_fd_table[MAX_SOCKET_FDS] = {NULL};

/**
 * Get a kernel socket object from a file descriptor.
 * Returns NULL if FD is invalid or not a socket.
 */
static inline fut_socket_t *get_socket_from_fd(int fd) {
    if (fd < 0 || fd >= MAX_SOCKET_FDS) {
        return NULL;
    }
    return socket_fd_table[fd];
}

/**
 * Store a kernel socket object for a file descriptor.
 * Returns 0 on success, -1 if FD is invalid.
 */
static inline int set_socket_for_fd(int fd, fut_socket_t *socket) {
    if (fd < 0 || fd >= MAX_SOCKET_FDS) {
        return -1;
    }
    socket_fd_table[fd] = socket;
    return 0;
}

/**
 * Find next available file descriptor for a socket.
 * Returns FD number (>=0) on success, -1 if no space.
 */
static inline int allocate_socket_fd(fut_socket_t *socket) {
    for (int i = 3; i < MAX_SOCKET_FDS; i++) {  /* Skip stdin/stdout/stderr */
        if (socket_fd_table[i] == NULL) {
            socket_fd_table[i] = socket;
            return i;
        }
    }
    return -1;
}

/**
 * Release a socket FD and cleanup the socket object.
 */
static inline int release_socket_fd(int fd) {
    fut_socket_t *socket = get_socket_from_fd(fd);
    if (!socket) {
        return -EBADF;
    }

    /* Close the socket */
    int ret = fut_socket_close(socket);

    /* Release the FD slot */
    socket_fd_table[fd] = NULL;

    return ret < 0 ? ret : 0;
}

/* ============================================================
 *   Syscall Handler Type
 * ============================================================ */

typedef int64_t (*syscall_handler_t)(uint64_t arg1, uint64_t arg2,
                                      uint64_t arg3, uint64_t arg4,
                                      uint64_t arg5, uint64_t arg6);

extern ssize_t sys_echo(const char *u_in, char *u_out, size_t n);
extern long sys_exit(int status);
extern long sys_waitpid(int pid, int *u_status, int flags);
extern long sys_nanosleep(const fut_timespec_t *u_req, fut_timespec_t *u_rem);
extern long sys_time_millis(void);
extern long sys_pipe(int pipefd[2]);
extern long sys_dup2(int oldfd, int newfd);
extern long sys_chdir(const char *path);
extern long sys_getcwd(char *buf, size_t size);

/* Helpers for missing syscalls */
extern int chrdev_alloc_fd(const struct fut_file_ops *ops, void *inode, void *priv);
extern struct fut_file *vfs_get_file(int fd);
extern int vfs_alloc_specific_fd(int target_fd, struct fut_file *file);
extern void vfs_file_ref(struct fut_file *file);
extern int fut_vfs_close(int fd);

static int64_t sys_echo_handler(uint64_t arg1, uint64_t arg2, uint64_t arg3,
                                uint64_t arg4, uint64_t arg5, uint64_t arg6) {
    (void)arg4;
    (void)arg5;
    (void)arg6;
    return (int64_t)sys_echo((const char *)arg1, (char *)arg2, (size_t)arg3);
}

static int64_t sys_pipe_handler(uint64_t arg1, uint64_t arg2, uint64_t arg3,
                                uint64_t arg4, uint64_t arg5, uint64_t arg6) {
    (void)arg2;
    (void)arg3;
    (void)arg4;
    (void)arg5;
    (void)arg6;
    return (int64_t)sys_pipe((int *)arg1);
}

static int64_t sys_dup2_handler(uint64_t arg1, uint64_t arg2, uint64_t arg3,
                                uint64_t arg4, uint64_t arg5, uint64_t arg6) {
    (void)arg3;
    (void)arg4;
    (void)arg5;
    (void)arg6;
    return (int64_t)sys_dup2((int)arg1, (int)arg2);
}

static int64_t sys_poll_handler(uint64_t fds, uint64_t nfds, uint64_t timeout,
                                uint64_t arg4, uint64_t arg5, uint64_t arg6) {
    (void)arg4;
    (void)arg5;
    (void)arg6;
    extern long sys_poll(struct pollfd *fds, unsigned long nfds, int timeout);
    return sys_poll((struct pollfd *)(uintptr_t)fds, (unsigned long)nfds, (int)timeout);
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

    extern void fut_printf(const char *, ...);
    fut_printf("[SYS-OPEN] called: pathname=0x%lx flags=0x%lx mode=0%lo\n", pathname, flags, mode);

    char kpath[256];
    int rc = copy_user_string((const char *)pathname, kpath, sizeof(kpath));
    fut_printf("[SYS-OPEN] copy_user_string returned %d, kpath='%s'\n", rc, kpath);
    if (rc != 0) {
        fut_printf("[SYS-OPEN] returning error %d\n", rc);
        return rc;
    }
    int result = fut_vfs_open(kpath, (int)flags, (int)mode);
    fut_printf("[SYS-OPEN] fut_vfs_open returned %d\n", result);
    return (int64_t)result;
}

static int64_t sys_openat_handler(uint64_t dirfd, uint64_t pathname, uint64_t flags,
                                  uint64_t mode, uint64_t arg5, uint64_t arg6) {
    (void)arg5;
    (void)arg6;
    (void)dirfd;  /* For now, we only support AT_FDCWD (current directory) */

    extern void fut_printf(const char *, ...);
    fut_printf("[SYS-OPENAT] INVOKED: dirfd=%ld pathname=0x%lx flags=0x%lx (O_CREAT=%d O_RDWR=%d O_CLOEXEC=%d) mode=0%lo\n",
               (long)dirfd, pathname, flags, !!(flags & 0x200), !!(flags & 0x2), !!(flags & 0x80000), mode);

    char kpath[256];
    int rc = copy_user_string((const char *)pathname, kpath, sizeof(kpath));
    fut_printf("[SYS-OPENAT] copy_user_string returned %d, kpath='%s'\n", rc, kpath);
    if (rc != 0) {
        fut_printf("[SYS-OPENAT] returning error %d\n", rc);
        return rc;
    }
    int result = fut_vfs_open(kpath, (int)flags, (int)mode);
    fut_printf("[SYS-OPENAT] fut_vfs_open returned %d for path '%s'\n", result, kpath);
    return (int64_t)result;
}

static int64_t sys_close_handler(uint64_t fd, uint64_t arg2, uint64_t arg3,
                                 uint64_t arg4, uint64_t arg5, uint64_t arg6) {
    (void)arg2;
    (void)arg3;
    (void)arg4;
    (void)arg5;
    (void)arg6;
    extern void fut_printf(const char *, ...);

    int fd_int = (int)fd;

    /* Check if FD is a socket first */
    fut_socket_t *socket = get_socket_from_fd(fd_int);
    if (socket) {
        /* It's a socket - release it */
        fut_printf("[CLOSE] Closing socket fd %d\n", fd_int);
        return (int64_t)release_socket_fd(fd_int);
    }

    /* Otherwise, close as a regular file descriptor */
    return (int64_t)fut_vfs_close(fd_int);
}

static int64_t sys_write_handler(uint64_t fd, uint64_t buf, uint64_t count,
                                 uint64_t arg4, uint64_t arg5, uint64_t arg6) {
    (void)arg4;
    (void)arg5;
    (void)arg6;

    extern void fut_printf(const char *, ...);
    // fut_printf("[WRITE] fd=%llu buf=0x%llx count=%llu\n", fd, buf, count);

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

    /* Sanity check: reject unreasonably large reads */
    if (len > 1024 * 1024) {  /* 1 MB limit */
        return -EINVAL;
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

static int64_t sys_pread64_handler(uint64_t fd, uint64_t buf, uint64_t count,
                                   uint64_t offset, uint64_t arg5, uint64_t arg6) {
    (void)arg5;
    (void)arg6;
    /* Use kernel sys_pread64 for position-based reading */
    return sys_pread64((unsigned int)fd, (void *)buf, (size_t)count, (int64_t)offset);
}

static int64_t sys_pwrite64_handler(uint64_t fd, uint64_t buf, uint64_t count,
                                    uint64_t offset, uint64_t arg5, uint64_t arg6) {
    (void)arg5;
    (void)arg6;
    /* Use kernel sys_pwrite64 for position-based writing */
    return sys_pwrite64((unsigned int)fd, (const void *)buf, (size_t)count, (int64_t)offset);
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
    return sys_mmap((void *)addr, (size_t)len, (int)prot, (int)flags, (int)fd, (long)off);
}

/* ============================================================
 *   Syscall Handlers (Wrappers)
 * ============================================================ */

/* File I/O */
/* File metadata */
static int64_t sys_stat_handler(uint64_t pathname, uint64_t statbuf, uint64_t arg3,
                                 uint64_t arg4, uint64_t arg5, uint64_t arg6) {
    (void)arg3; (void)arg4; (void)arg5; (void)arg6;
    /* Use kernel sys_stat which works with fut_stat structures */
    struct fut_stat *stat_ptr = (struct fut_stat *)statbuf;
    return sys_stat((const char *)pathname, stat_ptr);
}

static int64_t sys_fstat_handler(uint64_t fd, uint64_t statbuf, uint64_t arg3,
                                   uint64_t arg4, uint64_t arg5, uint64_t arg6) {
    (void)arg3; (void)arg4; (void)arg5; (void)arg6;

    /* Check if this FD is a socket */
    fut_socket_t *socket = get_socket_from_fd((int)fd);
    if (socket) {
        /* Return fake stat info for socket - just mark it as a valid file */
        struct fut_stat kernel_stat = {0};
        kernel_stat.st_mode = 0140000;  /* S_IFSOCK */
        kernel_stat.st_size = 0;
        kernel_stat.st_ino = socket->socket_id;

        if (fut_copy_to_user((struct fut_stat *)statbuf, &kernel_stat,
                             sizeof(struct fut_stat)) != 0) {
            return -EFAULT;
        }
        return 0;
    }

    /* Use kernel sys_fstat for regular files */
    return sys_fstat((int)fd, (struct fut_stat *)statbuf);
}

static int64_t sys_lstat_handler(uint64_t pathname, uint64_t statbuf, uint64_t arg3,
                                  uint64_t arg4, uint64_t arg5, uint64_t arg6) {
    (void)arg3; (void)arg4; (void)arg5; (void)arg6;
    extern long sys_lstat(const char *path, struct fut_stat *statbuf);
    return sys_lstat((const char *)pathname, (struct fut_stat *)statbuf);
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

static int64_t sys_nanosleep_handler(uint64_t req, uint64_t rem, uint64_t arg3,
                                     uint64_t arg4, uint64_t arg5, uint64_t arg6) {
    (void)arg3; (void)arg4; (void)arg5; (void)arg6;
    return (int64_t)sys_nanosleep((const fut_timespec_t *)(uintptr_t)req,
                                  (fut_timespec_t *)(uintptr_t)rem);
}

static int64_t sys_alarm_handler(uint64_t seconds, uint64_t arg2, uint64_t arg3,
                                  uint64_t arg4, uint64_t arg5, uint64_t arg6) {
    (void)arg2; (void)arg3; (void)arg4; (void)arg5; (void)arg6;
    extern long sys_alarm(unsigned int seconds);
    return sys_alarm((unsigned int)seconds);
}

static int64_t sys_pause_handler(uint64_t arg1, uint64_t arg2, uint64_t arg3,
                                  uint64_t arg4, uint64_t arg5, uint64_t arg6) {
    (void)arg1; (void)arg2; (void)arg3; (void)arg4; (void)arg5; (void)arg6;
    extern long sys_pause(void);
    return sys_pause();
}

static int64_t sys_sched_yield_handler(uint64_t arg1, uint64_t arg2, uint64_t arg3,
                                       uint64_t arg4, uint64_t arg5, uint64_t arg6) {
    (void)arg1; (void)arg2; (void)arg3; (void)arg4; (void)arg5; (void)arg6;
    extern long sys_sched_yield(void);
    return sys_sched_yield();
}

static int64_t sys_getpriority_handler(uint64_t which, uint64_t who, uint64_t arg3,
                                       uint64_t arg4, uint64_t arg5, uint64_t arg6) {
    (void)arg3; (void)arg4; (void)arg5; (void)arg6;
    extern long sys_getpriority(int which, int who);
    return sys_getpriority((int)which, (int)who);
}

static int64_t sys_setpriority_handler(uint64_t which, uint64_t who, uint64_t prio,
                                       uint64_t arg4, uint64_t arg5, uint64_t arg6) {
    (void)arg4; (void)arg5; (void)arg6;
    extern long sys_setpriority(int which, int who, int prio);
    return sys_setpriority((int)which, (int)who, (int)prio);
}

static int64_t sys_getrusage_handler(uint64_t who, uint64_t usage, uint64_t arg3,
                                     uint64_t arg4, uint64_t arg5, uint64_t arg6) {
    (void)arg3; (void)arg4; (void)arg5; (void)arg6;
    extern long sys_getrusage(int who, struct rusage *usage);
    return sys_getrusage((int)who, (struct rusage *)(uintptr_t)usage);
}

static int64_t sys_times_handler(uint64_t buf, uint64_t arg2, uint64_t arg3,
                                 uint64_t arg4, uint64_t arg5, uint64_t arg6) {
    (void)arg2; (void)arg3; (void)arg4; (void)arg5; (void)arg6;
    extern long sys_times(struct tms *buf);
    return sys_times((struct tms *)(uintptr_t)buf);
}

static int64_t sys_time_millis_handler(uint64_t arg1, uint64_t arg2, uint64_t arg3,
                                       uint64_t arg4, uint64_t arg5, uint64_t arg6) {
    (void)arg1; (void)arg2; (void)arg3; (void)arg4; (void)arg5; (void)arg6;
    return sys_time_millis();
}

static int64_t sys_mkdir_handler(uint64_t pathname, uint64_t mode, uint64_t arg3,
                                  uint64_t arg4, uint64_t arg5, uint64_t arg6) {
    (void)arg3; (void)arg4; (void)arg5; (void)arg6;
    return (int64_t)fut_vfs_mkdir((const char *)pathname, (uint32_t)mode);
}

static int64_t sys_rmdir_handler(uint64_t pathname, uint64_t arg2, uint64_t arg3,
                                  uint64_t arg4, uint64_t arg5, uint64_t arg6) {
    (void)arg2; (void)arg3; (void)arg4; (void)arg5; (void)arg6;
    return (int64_t)fut_vfs_rmdir((const char *)pathname);
}

static int64_t sys_unlink_handler(uint64_t pathname, uint64_t arg2, uint64_t arg3,
                                   uint64_t arg4, uint64_t arg5, uint64_t arg6) {
    (void)arg2; (void)arg3; (void)arg4; (void)arg5; (void)arg6;

    /* Copy pathname from userspace to kernel space */
    char path_buf[256];
    if (fut_copy_from_user(path_buf, (const void *)pathname, sizeof(path_buf) - 1) != 0) {
        return -EFAULT;
    }
    path_buf[sizeof(path_buf) - 1] = '\0';  /* Ensure null termination */

    return (int64_t)fut_vfs_unlink(path_buf);
}

/* Hard link creation (stub) */
static int64_t sys_link_handler(uint64_t oldpath, uint64_t newpath, uint64_t arg3,
                                 uint64_t arg4, uint64_t arg5, uint64_t arg6) {
    (void)arg3; (void)arg4; (void)arg5; (void)arg6;
    /* Use kernel sys_link (currently a stub returning -ENOSYS) */
    return sys_link((const char *)oldpath, (const char *)newpath);
}

/* Symbolic link creation (stub) */
static int64_t sys_symlink_handler(uint64_t target, uint64_t linkpath, uint64_t arg3,
                                    uint64_t arg4, uint64_t arg5, uint64_t arg6) {
    (void)arg3; (void)arg4; (void)arg5; (void)arg6;
    /* Use kernel sys_symlink (currently a stub returning -ENOSYS) */
    return sys_symlink((const char *)target, (const char *)linkpath);
}

/* Symbolic link reading (stub) */
static int64_t sys_readlink_handler(uint64_t pathname, uint64_t buf, uint64_t bufsiz,
                                     uint64_t arg4, uint64_t arg5, uint64_t arg6) {
    (void)arg4; (void)arg5; (void)arg6;
    /* Use kernel sys_readlink (currently a stub returning -ENOSYS) */
    return sys_readlink((const char *)pathname, (char *)buf, (size_t)bufsiz);
}

/* File truncation */
static int64_t sys_ftruncate_handler(uint64_t fd, uint64_t length, uint64_t arg3,
                                     uint64_t arg4, uint64_t arg5, uint64_t arg6) {
    (void)arg3; (void)arg4; (void)arg5; (void)arg6;
    /* Use kernel sys_ftruncate for file truncation */
    return sys_ftruncate((int)fd, (uint64_t)length);
}

/* Memory management */
static int64_t sys_brk_handler(uint64_t addr, uint64_t arg2, uint64_t arg3,
                                uint64_t arg4, uint64_t arg5, uint64_t arg6) {
    (void)arg2; (void)arg3; (void)arg4; (void)arg5; (void)arg6;
    return sys_brk((uintptr_t)addr);
}

static int64_t sys_munmap_handler(uint64_t addr, uint64_t len, uint64_t arg3,
                                  uint64_t arg4, uint64_t arg5, uint64_t arg6) {
    (void)arg3; (void)arg4; (void)arg5; (void)arg6;
    return sys_munmap((void *)addr, (size_t)len);
}

static int64_t sys_mprotect_handler(uint64_t addr, uint64_t len, uint64_t prot,
                                    uint64_t arg4, uint64_t arg5, uint64_t arg6) {
    (void)arg4; (void)arg5; (void)arg6;
    extern long sys_mprotect(void *addr, size_t len, int prot);
    return sys_mprotect((void *)addr, (size_t)len, (int)prot);
}

/* Directory operations */
static int64_t sys_getdents64_handler(uint64_t fd, uint64_t dirp, uint64_t count,
                                      uint64_t arg4, uint64_t arg5, uint64_t arg6) {
    (void)arg4; (void)arg5; (void)arg6;
    /* Use kernel sys_getdents64 for directory reading */
    return sys_getdents64((unsigned int)fd, (void *)dirp, (unsigned int)count);
}

/* getpid() handler */
static int64_t sys_getpid_handler(uint64_t arg1, uint64_t arg2, uint64_t arg3,
                                  uint64_t arg4, uint64_t arg5, uint64_t arg6) {
    (void)arg1; (void)arg2; (void)arg3; (void)arg4; (void)arg5; (void)arg6;
    extern fut_task_t *fut_task_current(void);
    fut_task_t *current = fut_task_current();
    if (!current) {
        return -1;
    }
    return (int64_t)current->pid;
}

/* ============================================================
 *   Signal Handling Syscalls
 * ============================================================ */

/**
 * kill() - Send signal to a task
 * @arg1: pid (target process ID)
 * @arg2: signum (signal number, 1-30)
 */
static int64_t sys_kill_handler(uint64_t pid, uint64_t signum, uint64_t arg3,
                                uint64_t arg4, uint64_t arg5, uint64_t arg6) {
    (void)arg3; (void)arg4; (void)arg5; (void)arg6;

    extern fut_task_t *fut_task_current(void);
    fut_task_t *current = fut_task_current();
    if (!current) {
        return -EINVAL;
    }

    /* Find target task by PID */
    fut_task_t *target = NULL;

    /* For now, simple approach: if pid == 0, send to current process group
     * if pid > 0, send to specific process
     * For MVP, we'll just handle pid > 0 case targeting current process for testing
     */
    if (pid == 0) {
        /* Send to current process group - not yet implemented */
        return -EINVAL;
    } else {
        /* Send to specific process - for now just support sending to self or children */
        /* TODO: Implement full process lookup by PID */
        if (pid == current->pid) {
            target = current;
        } else {
            /* Look through children */
            target = current->first_child;
            while (target && target->pid != pid) {
                target = target->sibling;
            }
        }
    }

    if (!target) {
        return -ESRCH;  /* No such process */
    }

    /* Validate signal number */
    if ((int)signum < 1 || (int)signum >= _NSIG) {
        return -EINVAL;
    }

    /* Queue the signal */
    return fut_signal_send(target, (int)signum);
}

/**
 * sigaction() - Install signal handler
 * @arg1: signum (signal number)
 * @arg2: act (new sigaction, may be NULL)
 * @arg3: oldact (old sigaction, may be NULL)
 */
static int64_t sys_sigaction_handler(uint64_t signum, uint64_t act, uint64_t oldact,
                                     uint64_t arg4, uint64_t arg5, uint64_t arg6) {
    (void)arg4; (void)arg5; (void)arg6;

    extern fut_task_t *fut_task_current(void);
    fut_task_t *current = fut_task_current();
    if (!current) {
        return -EINVAL;
    }

    /* Validate signal number */
    if ((int)signum < 1 || (int)signum >= _NSIG) {
        return -EINVAL;
    }

    /* SIGKILL and SIGSTOP cannot be caught */
    if ((int)signum == SIGKILL || (int)signum == SIGSTOP) {
        return -EINVAL;
    }

    /* Validate signal number for array access */
    if ((int)signum < 1 || (int)signum >= _NSIG) {
        return -EINVAL;
    }

    int sig_idx = (int)signum;  // Index into handler arrays (1-30)

    /* Copy old action if requested */
    if (oldact) {
        struct sigaction *old = (struct sigaction *)oldact;
        old->sa_handler = fut_signal_get_handler(current, sig_idx);
        old->sa_mask = current->signal_handler_masks[sig_idx];
        old->sa_flags = current->signal_handler_flags[sig_idx];
    }

    /* Install new handler if provided */
    if (act) {
        struct sigaction *new = (struct sigaction *)act;
        sighandler_t handler = new->sa_handler;
        int ret = fut_signal_set_handler(current, sig_idx, handler);
        if (ret < 0) {
            return ret;
        }

        /* Store sa_mask and sa_flags for this signal handler */
        current->signal_handler_masks[sig_idx] = new->sa_mask;
        current->signal_handler_flags[sig_idx] = new->sa_flags;
    }

    return 0;
}

/**
 * sigprocmask() - Modify signal mask
 * @arg1: how (SIGPROCMASK_BLOCK, SETMASK, UNBLOCK)
 * @arg2: set (signals to modify)
 * @arg3: oldset (old mask output)
 */
static int64_t sys_sigprocmask_handler(uint64_t how, uint64_t set, uint64_t oldset,
                                       uint64_t arg4, uint64_t arg5, uint64_t arg6) {
    (void)arg4; (void)arg5; (void)arg6;

    extern fut_task_t *fut_task_current(void);
    fut_task_t *current = fut_task_current();
    if (!current) {
        return -EINVAL;
    }

    const sigset_t *set_ptr = (set == 0) ? NULL : (const sigset_t *)set;
    sigset_t *oldset_ptr = (oldset == 0) ? NULL : (sigset_t *)oldset;

    return fut_signal_procmask(current, (int)how, set_ptr, oldset_ptr);
}

/**
 * sigreturn() - Return from signal handler
 *
 * This syscall is called by the signal handler trampoline code on the user stack.
 * It restores the full user context (registers, flags, stack pointer) that was
 * saved in the rt_sigframe when the signal was delivered.
 *
 * Context restoration:
 * 1. The trampoline code calls sigreturn with RSI = frame pointer to rt_sigframe
 * 2. This handler reads the rt_sigframe from user space
 * 3. Extracts the saved register and signal mask from the ucontext
 * 4. Modifies the kernel interrupt frame to restore all registers
 * 5. On return, the interrupt handler restores registers and switches to user mode
 *
 * Arch-specific: x86_64 version
 */
static int64_t sys_sigreturn_handler(uint64_t frame_ptr, uint64_t arg2, uint64_t arg3,
                                     uint64_t arg4, uint64_t arg5, uint64_t arg6) {
    (void)frame_ptr; (void)arg3; (void)arg4; (void)arg5; (void)arg6;

    /* arg2 (RSI) contains pointer to rt_sigframe on user stack */
    void *user_frame = (void *)(uintptr_t)arg2;

    extern fut_task_t *fut_task_current(void);
    extern int fut_copy_from_user(void *k_dst, const void *u_src, size_t n);
    extern fut_interrupt_frame_t *fut_current_frame;
    extern void fut_printf(const char *fmt, ...);

    fut_task_t *current = fut_task_current();
    if (!current || !user_frame) {
        return -EINVAL;
    }

    /* Read the signal frame from user space */
    struct rt_sigframe sigframe;
    if (fut_copy_from_user(&sigframe, user_frame, sizeof(sigframe)) != 0) {
        fut_printf("[SIGNAL] sigreturn: failed to read sigframe from user space\n");
        return -EFAULT;
    }

    /* Restore the signal mask from the ucontext
     * The signal mask was saved when the signal handler was entered */
    if (sigframe.uc.uc_sigmask.__mask != 0) {
        current->signal_mask = sigframe.uc.uc_sigmask.__mask;
    }

    /* Restore all general purpose registers from the saved context
     * The registers in uc_mcontext.gregs are in the same order as the interrupt frame */
    fut_interrupt_frame_t *frame = fut_current_frame;
    if (frame) {
        struct sigcontext *ctx = &sigframe.uc.uc_mcontext.gregs;

        /* Restore GPRs */
        frame->rax = ctx->rax;
        frame->rbx = ctx->rbx;
        frame->rcx = ctx->rcx;
        frame->rdx = ctx->rdx;
        frame->rsi = ctx->rsi;
        frame->rdi = ctx->rdi;
        frame->rbp = ctx->rbp;
        frame->rsp = ctx->rsp;
        frame->r8  = ctx->r8;
        frame->r9  = ctx->r9;
        frame->r10 = ctx->r10;
        frame->r11 = ctx->r11;
        frame->r12 = ctx->r12;
        frame->r13 = ctx->r13;
        frame->r14 = ctx->r14;
        frame->r15 = ctx->r15;

        /* Restore control registers */
        frame->rip    = ctx->rip;
        frame->rflags = ctx->eflags;

        /* Restore segment registers (careful with CS/SS) */
        frame->cs = ctx->cs;
        if (ctx->gs != 0) {
            frame->gs = ctx->gs;
        }
        if (ctx->fs != 0) {
            frame->fs = ctx->fs;
        }

        fut_printf("[SIGNAL] Restored context from sigreturn: rip=0x%llx rsp=0x%llx\n",
                   frame->rip, frame->rsp);
    }

    /* Return value is overwritten by the restored register state */
    return 0;
}

/* ============================================================
 *   I/O Multiplexing Syscall
 * ============================================================ */

/**
 * select() - Wait for file descriptor sets to become ready
 * @arg1: nfds (highest fd number + 1)
 * @arg2: readfds (file descriptors ready for reading)
 * @arg3: writefds (file descriptors ready for writing)
 * @arg4: exceptfds (file descriptors with exceptional conditions)
 * @arg5: timeout (timeval pointer for timeout, NULL for blocking)
 *
 * Enhanced implementation with:
 * - Non-blocking poll (timeout=0)
 * - Timeout support (timeout > 0)
 * - Better FD readiness detection
 * - Accurate ready count reporting
 *
 * Phase 4: Full blocking multiplexing would use event queues
 */
static int64_t sys_select_handler(uint64_t nfds, uint64_t readfds, uint64_t writefds,
                                  uint64_t exceptfds, uint64_t timeout_ptr, uint64_t arg6) {
    (void)arg6;  /* Unused parameter */

    if (nfds > 1024) {
        return -EINVAL;
    }

    extern void fut_printf(const char *, ...);
    extern int fut_copy_from_user(void *k_dst, const void *u_src, size_t n);
    extern long sys_nanosleep(const fut_timespec_t *u_req, fut_timespec_t *u_rem);

    int ready_count = 0;
    uint8_t *read_set = (uint8_t *)readfds;
    uint8_t *write_set = (uint8_t *)writefds;
    uint8_t *except_set = (uint8_t *)exceptfds;

    if (!read_set && !write_set && !except_set) {
        /* No FD sets provided - just sleep if timeout provided */
        if (timeout_ptr) {
            /* timeval has tv_sec (long) and tv_usec (long) */
            long tv_sec = 0, tv_usec = 0;
            if (fut_copy_from_user(&tv_sec, (void *)timeout_ptr, sizeof(long)) == 0) {
                if (fut_copy_from_user(&tv_usec, (void *)(timeout_ptr + sizeof(long)), sizeof(long)) == 0) {
                    fut_timespec_t req = {
                        .tv_sec = tv_sec,
                        .tv_nsec = tv_usec * 1000
                    };
                    sys_nanosleep(&req, NULL);
                }
            }
        }
        return 0;
    }

    /* Determine if this should block or poll
     * timeout == 0: non-blocking poll (return immediately)
     * timeout == NULL: blocking (wait indefinitely - use loop with retries)
     * timeout > 0: wait with timeout
     */
    bool should_timeout = (timeout_ptr != 0);
    int timeout_ms = 0;

    if (should_timeout) {
        long tv_sec = 0, tv_usec = 0;
        if (fut_copy_from_user(&tv_sec, (void *)timeout_ptr, sizeof(long)) == 0 &&
            fut_copy_from_user(&tv_usec, (void *)(timeout_ptr + sizeof(long)), sizeof(long)) == 0) {
            timeout_ms = (int)((tv_sec * 1000) + (tv_usec / 1000));
        }
    }

    /* Simple polling loop implementation:
     * - For timeout=0: poll once and return
     * - For timeout>0: poll with timeout using sleep
     * - For timeout=NULL: block indefinitely (future: use wait queues)
     */

    int poll_attempt = 0;
    int max_polls = (timeout_ms > 0) ? (timeout_ms / 10) + 1 : 1;  /* Poll every 10ms max */

    while (poll_attempt < max_polls) {
        ready_count = 0;

        /* Poll each file descriptor */
        for (int fd = 0; fd < (int)nfds; fd++) {
            int byte_offset = fd / 8;
            int bit_offset = fd % 8;
            uint8_t mask = (1 << bit_offset);

            struct fut_file *file = vfs_get_file(fd);

            /* Check read readiness */
            if (read_set && (read_set[byte_offset] & mask)) {
                if (file && file->vnode) {
                    /* Regular file/vnode - always readable (no blocking I/O) */
                    ready_count++;
                    fut_printf("[SELECT] FD %d ready for reading\n", fd);
                } else if (!file) {
                    /* FD not found - mark as exception */
                    if (except_set) {
                        except_set[byte_offset] |= mask;
                        ready_count++;
                    }
                    /* Remove from read set */
                    read_set[byte_offset] &= ~mask;
                }
            }

            /* Check write readiness */
            if (write_set && (write_set[byte_offset] & mask)) {
                if (file && file->vnode) {
                    /* Regular file/vnode - always writable */
                    ready_count++;
                    fut_printf("[SELECT] FD %d ready for writing\n", fd);
                } else if (!file) {
                    /* FD not found - mark as exception */
                    if (except_set) {
                        except_set[byte_offset] |= mask;
                        ready_count++;
                    }
                    /* Remove from write set */
                    write_set[byte_offset] &= ~mask;
                }
            }
        }

        /* If we found ready FDs or should return immediately, break */
        if (ready_count > 0 || timeout_ms == 0) {
            break;
        }

        /* If we have more polls to do, sleep before next attempt */
        if (poll_attempt < max_polls - 1) {
            fut_timespec_t sleep_req = {
                .tv_sec = 0,
                .tv_nsec = 10 * 1000000  /* 10ms sleep */
            };
            sys_nanosleep(&sleep_req, NULL);
        }

        poll_attempt++;
    }

    fut_printf("[SELECT] Returning %d ready file descriptors (attempts: %d)\n",
               ready_count, poll_attempt + 1);
    return ready_count;
}

/* dup() handler - duplicate file descriptor with auto selection */
static int64_t sys_dup_handler(uint64_t oldfd, uint64_t arg2, uint64_t arg3,
                               uint64_t arg4, uint64_t arg5, uint64_t arg6) {
    (void)arg2; (void)arg3; (void)arg4; (void)arg5; (void)arg6;
    /* Use kernel sys_dup for per-task FD duplication */
    return sys_dup((int)oldfd);
}

/* Socket operations handlers */
static int64_t sys_socket_handler(uint64_t domain, uint64_t type, uint64_t protocol,
                                  uint64_t arg4, uint64_t arg5, uint64_t arg6) {
    (void)protocol; (void)arg4; (void)arg5; (void)arg6;
    extern void fut_printf(const char *, ...);

    fut_printf("[SOCKET] domain=%lu type=%lu protocol=%lu\n", domain, type, protocol);

    /* Phase 3 implementation: Full kernel socket support via fut_socket system
     *
     * Architecture:
     * - Kernel: Complete socket object system in kernel/ipc/fut_socket.c
     *   (Full state machine, accept queue, bidirectional I/O)
     * - POSIX shim: Maps POSIX syscalls to kernel socket API
     * - Handles: Socket FD management with per-task FD table
     *
     * Supported: AF_UNIX SOCK_STREAM sockets with full kernel support
     * - socket() creates kernel socket object
     * - bind() binds to path in VFS
     * - listen() marks as listener with accept queue
     * - accept() dequeues pending connections
     * - connect() initiates connection to listening socket
     * - send/recv() bidirectional I/O with blocking wait queues
     */

    /* Validate domain and type */
    if (domain != 1) {  /* AF_UNIX */
        fut_printf("[SOCKET] ERROR: Unsupported domain %lu\n", domain);
        return -EINVAL;
    }
    if (type != 1) {  /* SOCK_STREAM */
        fut_printf("[SOCKET] ERROR: Unsupported type %lu\n", type);
        return -EINVAL;
    }

    /* Create kernel socket object */
    fut_socket_t *socket = fut_socket_create((int)domain, (int)type);
    if (!socket) {
        fut_printf("[SOCKET] ERROR: Failed to create kernel socket\n");
        return -EMFILE;  /* Too many open files */
    }

    /* Allocate FD for this socket */
    int fd = allocate_socket_fd(socket);
    if (fd < 0) {
        fut_printf("[SOCKET] ERROR: Failed to allocate socket FD\n");
        fut_socket_unref(socket);
        return -EMFILE;
    }

    fut_printf("[SOCKET] Created socket %u with FD %d\n", socket->socket_id, fd);
    return (int64_t)fd;
}

static int64_t sys_bind_handler(uint64_t sockfd, uint64_t addr, uint64_t addrlen,
                                uint64_t arg4, uint64_t arg5, uint64_t arg6) {
    (void)arg4; (void)arg5; (void)arg6;
    extern void fut_printf(const char *, ...);

    fut_printf("[BIND] sockfd=%lu addr=0x%lx addrlen=%lu\n", sockfd, addr, addrlen);

    /* Extract socket path from sockaddr_un structure
     * struct sockaddr_un {
     *     sa_family_t sun_family;  // 2 bytes
     *     char sun_path[108];      // path
     * }
     */

    if (addrlen < 3) {  /* At least family (2 bytes) + 1 char for path */
        fut_printf("[BIND] ERROR: addrlen too small (%lu)\n", addrlen);
        return -EINVAL;
    }

    /* Copy the socket path from user space */
    char sock_path[256];
    uint16_t sun_family;
    if (fut_copy_from_user(&sun_family, (const void *)addr, 2) != 0) {
        fut_printf("[BIND] ERROR: failed to copy sun_family\n");
        return -EFAULT;
    }

    /* Copy path component (skip the 2-byte family field) */
    size_t path_len = addrlen - 2;
    if (path_len > sizeof(sock_path) - 1) {
        path_len = sizeof(sock_path) - 1;
    }

    if (path_len > 0) {
        if (fut_copy_from_user(sock_path, (const void *)(addr + 2), path_len) != 0) {
            fut_printf("[BIND] ERROR: failed to copy sun_path\n");
            return -EFAULT;
        }
    }
    sock_path[path_len] = '\0';

    fut_printf("[BIND] sun_family=%u path='%s'\n", sun_family, sock_path);

    /* Get kernel socket object from FD */
    fut_socket_t *socket = get_socket_from_fd((int)sockfd);
    if (!socket) {
        fut_printf("[BIND] ERROR: socket fd %lu not valid\n", sockfd);
        return -EBADF;
    }

    /* Bind socket to path using kernel socket API */
    int ret = fut_socket_bind(socket, sock_path);
    if (ret < 0) {
        fut_printf("[BIND] ERROR: fut_socket_bind failed with code %d\n", ret);
        return ret;
    }

    fut_printf("[BIND] Successfully bound socket to path '%s'\n", sock_path);
    return 0;  /* Success */
}

static int64_t sys_listen_handler(uint64_t sockfd, uint64_t backlog, uint64_t arg3,
                                  uint64_t arg4, uint64_t arg5, uint64_t arg6) {
    (void)arg3; (void)arg4; (void)arg5; (void)arg6;
    extern void fut_printf(const char *, ...);

    fut_printf("[LISTEN] sockfd=%lu backlog=%lu\n", sockfd, backlog);

    /* Get kernel socket object from FD */
    fut_socket_t *socket = get_socket_from_fd((int)sockfd);
    if (!socket) {
        fut_printf("[LISTEN] ERROR: socket fd %lu not valid\n", sockfd);
        return -EBADF;
    }

    /* Mark socket as listening with given backlog */
    int ret = fut_socket_listen(socket, (int)backlog);
    if (ret < 0) {
        fut_printf("[LISTEN] ERROR: fut_socket_listen failed with code %d\n", ret);
        return ret;
    }

    fut_printf("[LISTEN] Socket %u marked as listening with backlog %lu\n",
               socket->socket_id, backlog);
    return 0;  /* Success */
}

static int64_t sys_accept_handler(uint64_t sockfd, uint64_t addr, uint64_t addrlen,
                                  uint64_t arg4, uint64_t arg5, uint64_t arg6) {
    (void)addr; (void)addrlen; (void)arg4; (void)arg5; (void)arg6;
    extern void fut_printf(const char *, ...);

    fut_printf("[ACCEPT] sockfd=%lu\n", sockfd);

    /* Get listening socket from FD */
    fut_socket_t *listener = get_socket_from_fd((int)sockfd);
    if (!listener) {
        fut_printf("[ACCEPT] ERROR: socket fd %lu not valid\n", sockfd);
        return -EBADF;
    }

    /* Accept pending connection */
    fut_socket_t *peer = NULL;
    int ret = fut_socket_accept(listener, &peer);
    if (ret < 0) {
        fut_printf("[ACCEPT] ERROR: fut_socket_accept failed with code %d\n", ret);
        return ret;  /* EAGAIN if no connections, or other error */
    }

    /* Allocate FD for accepted socket */
    int peer_fd = allocate_socket_fd(peer);
    if (peer_fd < 0) {
        fut_printf("[ACCEPT] ERROR: Failed to allocate FD for accepted socket\n");
        fut_socket_unref(peer);
        return -EMFILE;
    }

    fut_printf("[ACCEPT] Accepted connection: listener=%u peer=%u fd=%d\n",
               listener->socket_id, peer->socket_id, peer_fd);
    return (int64_t)peer_fd;
}

/**
 * Connect to a socket.
 * For AF_UNIX SOCK_STREAM, initiates connection to a listening socket.
 *
 * Phase 3 Implementation:
 * - Connects to a listening socket path
 * - Uses kernel socket connection mechanism
 * - Establishes bidirectional communication channel
 * - Returns 0 on success for connected socket
 */
static int64_t sys_connect_handler(uint64_t sockfd, uint64_t addr, uint64_t addrlen,
                                   uint64_t arg4, uint64_t arg5, uint64_t arg6) {
    (void)arg4; (void)arg5; (void)arg6;
    extern void fut_printf(const char *, ...);

    fut_printf("[CONNECT] sockfd=%lu addr=0x%lx addrlen=%lu\n", sockfd, addr, addrlen);

    /* Extract socket path from sockaddr_un structure */
    if (addrlen < 3) {  /* At least family (2 bytes) + 1 char for path */
        fut_printf("[CONNECT] ERROR: addrlen too small\n");
        return -EINVAL;
    }

    /* Copy the socket path from user space */
    char sock_path[256];
    uint16_t sun_family;
    if (fut_copy_from_user(&sun_family, (const void *)addr, 2) != 0) {
        fut_printf("[CONNECT] ERROR: failed to copy sun_family\n");
        return -EFAULT;
    }

    /* Copy path component (skip the 2-byte family field) */
    size_t path_len = addrlen - 2;
    if (path_len > sizeof(sock_path) - 1) {
        path_len = sizeof(sock_path) - 1;
    }

    if (path_len > 0) {
        if (fut_copy_from_user(sock_path, (const void *)(addr + 2), path_len) != 0) {
            fut_printf("[CONNECT] ERROR: failed to copy sun_path\n");
            return -EFAULT;
        }
    }
    sock_path[path_len] = '\0';

    fut_printf("[CONNECT] sun_family=%u path='%s'\n", sun_family, sock_path);

    /* Get client socket from FD */
    fut_socket_t *socket = get_socket_from_fd((int)sockfd);
    if (!socket) {
        fut_printf("[CONNECT] ERROR: socket fd %lu not valid\n", sockfd);
        return -EBADF;
    }

    /* Connect socket to listening socket at target path */
    int ret = fut_socket_connect(socket, sock_path);
    if (ret < 0) {
        fut_printf("[CONNECT] ERROR: fut_socket_connect failed with code %d\n", ret);
        return ret;
    }

    fut_printf("[CONNECT] Socket %u successfully connected to '%s'\n",
               socket->socket_id, sock_path);
    return 0;  /* Success - socket is now connected */
}

/**
 * Send data to a socket.
 * For pipe-based sockets, this is equivalent to writing to the pipe.
 *
 * Phase 2 Implementation Notes:
 * - Writes data to the socket's pipe backend
 * - Handles partial writes
 * - Returns bytes sent or error code
 */
static int64_t sys_sendto_handler(uint64_t sockfd, uint64_t buf, uint64_t len,
                                  uint64_t flags, uint64_t addr, uint64_t addrlen) {
    extern void fut_printf(const char *, ...);

    (void)flags; (void)addr; (void)addrlen;

    fut_printf("[SENDTO] sockfd=%lu buf=0x%lx len=%lu\n", sockfd, buf, len);

    /* Validate the socket fd exists */
    struct fut_file *file = vfs_get_file((int)sockfd);
    if (!file) {
        fut_printf("[SENDTO] ERROR: socket fd %lu is not valid\n", sockfd);
        return -EBADF;
    }

    /* For pipe-based sockets, write to the pipe */
    long ret = sys_write_handler((uint64_t)sockfd, buf, len, 0, 0, 0);

    fut_printf("[SENDTO] wrote %ld bytes\n", ret);
    return ret;
}

/**
 * Receive data from a socket.
 * For pipe-based sockets, this is equivalent to reading from the pipe.
 *
 * Phase 2 Implementation Notes:
 * - Reads data from the socket's pipe backend
 * - Handles partial reads
 * - Returns bytes received or error code
 */
static int64_t sys_recvfrom_handler(uint64_t sockfd, uint64_t buf, uint64_t len,
                                    uint64_t flags, uint64_t addr, uint64_t addrlen) {
    extern void fut_printf(const char *, ...);

    (void)flags; (void)addr; (void)addrlen;

    fut_printf("[RECVFROM] sockfd=%lu buf=0x%lx len=%lu\n", sockfd, buf, len);

    /* Validate the socket fd exists */
    struct fut_file *file = vfs_get_file((int)sockfd);
    if (!file) {
        fut_printf("[RECVFROM] ERROR: socket fd %lu is not valid\n", sockfd);
        return -EBADF;
    }

    /* For pipe-based sockets, read from the pipe */
    long ret = sys_read_handler((uint64_t)sockfd, buf, len, 0, 0, 0);

    fut_printf("[RECVFROM] read %ld bytes\n", ret);
    return ret;
}

/* Unimplemented syscall handler */
static int64_t sys_unimplemented(uint64_t arg1, uint64_t arg2, uint64_t arg3,
                                  uint64_t arg4, uint64_t arg5, uint64_t arg6) {
    (void)arg1; (void)arg2; (void)arg3; (void)arg4; (void)arg5; (void)arg6;
    return -1;  /* ENOSYS */
}

static int64_t sys_getcwd_handler(uint64_t buf, uint64_t size, uint64_t arg3,
                                   uint64_t arg4, uint64_t arg5, uint64_t arg6) {
    (void)arg3; (void)arg4; (void)arg5; (void)arg6;
    return sys_getcwd((char *)(uintptr_t)buf, (size_t)size);
}

static int64_t sys_chdir_handler(uint64_t path, uint64_t arg2, uint64_t arg3,
                                 uint64_t arg4, uint64_t arg5, uint64_t arg6) {
    (void)arg2; (void)arg3; (void)arg4; (void)arg5; (void)arg6;
    return sys_chdir((const char *)(uintptr_t)path);
}

/* Epoll syscall handlers */
static int64_t sys_epoll_create_handler(uint64_t size, uint64_t arg2, uint64_t arg3,
                                        uint64_t arg4, uint64_t arg5, uint64_t arg6) {
    (void)arg2; (void)arg3; (void)arg4; (void)arg5; (void)arg6;
    extern long sys_epoll_create(int size);
    return sys_epoll_create((int)size);
}

static int64_t sys_epoll_ctl_handler(uint64_t epfd, uint64_t op, uint64_t fd,
                                     uint64_t event, uint64_t arg5, uint64_t arg6) {
    (void)arg5; (void)arg6;
    extern long sys_epoll_ctl(int epfd, int op, int fd, void *event);
    return sys_epoll_ctl((int)epfd, (int)op, (int)fd, (void *)(uintptr_t)event);
}

static int64_t sys_epoll_wait_handler(uint64_t epfd, uint64_t events, uint64_t maxevents,
                                      uint64_t timeout, uint64_t arg5, uint64_t arg6) {
    (void)arg5; (void)arg6;
    extern long sys_epoll_wait(int epfd, void *events, int maxevents, int timeout);
    return sys_epoll_wait((int)epfd, (void *)(uintptr_t)events, (int)maxevents, (int)timeout);
}

/* madvise() syscall handler */
static int64_t sys_madvise_handler(uint64_t addr, uint64_t length, uint64_t advice,
                                   uint64_t arg4, uint64_t arg5, uint64_t arg6) {
    (void)arg4; (void)arg5; (void)arg6;
    extern long sys_madvise(void *addr, size_t length, int advice);
    return sys_madvise((void *)(uintptr_t)addr, (size_t)length, (int)advice);
}

/* Process credential syscall handlers */
static int64_t sys_getuid_handler(uint64_t arg1, uint64_t arg2, uint64_t arg3,
                                  uint64_t arg4, uint64_t arg5, uint64_t arg6) {
    (void)arg1; (void)arg2; (void)arg3; (void)arg4; (void)arg5; (void)arg6;
    extern long sys_getuid(void);
    return sys_getuid();
}

static int64_t sys_geteuid_handler(uint64_t arg1, uint64_t arg2, uint64_t arg3,
                                   uint64_t arg4, uint64_t arg5, uint64_t arg6) {
    (void)arg1; (void)arg2; (void)arg3; (void)arg4; (void)arg5; (void)arg6;
    extern long sys_geteuid(void);
    return sys_geteuid();
}

static int64_t sys_getgid_handler(uint64_t arg1, uint64_t arg2, uint64_t arg3,
                                  uint64_t arg4, uint64_t arg5, uint64_t arg6) {
    (void)arg1; (void)arg2; (void)arg3; (void)arg4; (void)arg5; (void)arg6;
    extern long sys_getgid(void);
    return sys_getgid();
}

static int64_t sys_getegid_handler(uint64_t arg1, uint64_t arg2, uint64_t arg3,
                                   uint64_t arg4, uint64_t arg5, uint64_t arg6) {
    (void)arg1; (void)arg2; (void)arg3; (void)arg4; (void)arg5; (void)arg6;
    extern long sys_getegid(void);
    return sys_getegid();
}

static int64_t sys_setuid_handler(uint64_t uid, uint64_t arg2, uint64_t arg3,
                                  uint64_t arg4, uint64_t arg5, uint64_t arg6) {
    (void)arg2; (void)arg3; (void)arg4; (void)arg5; (void)arg6;
    extern long sys_setuid(uint32_t uid);
    return sys_setuid((uint32_t)uid);
}

static int64_t sys_seteuid_handler(uint64_t euid, uint64_t arg2, uint64_t arg3,
                                   uint64_t arg4, uint64_t arg5, uint64_t arg6) {
    (void)arg2; (void)arg3; (void)arg4; (void)arg5; (void)arg6;
    extern long sys_seteuid(uint32_t euid);
    return sys_seteuid((uint32_t)euid);
}

static int64_t sys_setgid_handler(uint64_t gid, uint64_t arg2, uint64_t arg3,
                                  uint64_t arg4, uint64_t arg5, uint64_t arg6) {
    (void)arg2; (void)arg3; (void)arg4; (void)arg5; (void)arg6;
    extern long sys_setgid(uint32_t gid);
    return sys_setgid((uint32_t)gid);
}

static int64_t sys_setegid_handler(uint64_t egid, uint64_t arg2, uint64_t arg3,
                                   uint64_t arg4, uint64_t arg5, uint64_t arg6) {
    (void)arg2; (void)arg3; (void)arg4; (void)arg5; (void)arg6;
    extern long sys_setegid(uint32_t egid);
    return sys_setegid((uint32_t)egid);
}

static int64_t sys_umask_handler(uint64_t mask, uint64_t arg2, uint64_t arg3,
                                 uint64_t arg4, uint64_t arg5, uint64_t arg6) {
    (void)arg2; (void)arg3; (void)arg4; (void)arg5; (void)arg6;
    /* Use kernel sys_umask for file creation mask */
    return sys_umask((uint32_t)mask);
}

static int64_t sys_uname_handler(uint64_t buf, uint64_t arg2, uint64_t arg3,
                                 uint64_t arg4, uint64_t arg5, uint64_t arg6) {
    (void)arg2; (void)arg3; (void)arg4; (void)arg5; (void)arg6;
    /* Use kernel sys_uname for system information */
    return sys_uname((void *)(uintptr_t)buf);
}

/* Process info syscall handlers */
static int64_t sys_gettid_handler(uint64_t arg1, uint64_t arg2, uint64_t arg3,
                                   uint64_t arg4, uint64_t arg5, uint64_t arg6) {
    (void)arg1; (void)arg2; (void)arg3; (void)arg4; (void)arg5; (void)arg6;
    extern long sys_gettid(void);
    return sys_gettid();
}

static int64_t sys_getppid_handler(uint64_t arg1, uint64_t arg2, uint64_t arg3,
                                   uint64_t arg4, uint64_t arg5, uint64_t arg6) {
    (void)arg1; (void)arg2; (void)arg3; (void)arg4; (void)arg5; (void)arg6;
    extern long sys_getppid(void);
    return sys_getppid();
}

static int64_t sys_getpgrp_handler(uint64_t arg1, uint64_t arg2, uint64_t arg3,
                                   uint64_t arg4, uint64_t arg5, uint64_t arg6) {
    (void)arg1; (void)arg2; (void)arg3; (void)arg4; (void)arg5; (void)arg6;
    extern long sys_getpgrp(void);
    return sys_getpgrp();
}

static int64_t sys_getsid_handler(uint64_t pid, uint64_t arg2, uint64_t arg3,
                                  uint64_t arg4, uint64_t arg5, uint64_t arg6) {
    (void)arg2; (void)arg3; (void)arg4; (void)arg5; (void)arg6;
    extern long sys_getsid(uint64_t pid);
    return sys_getsid((uint64_t)pid);
}

static int64_t sys_setsid_handler(uint64_t arg1, uint64_t arg2, uint64_t arg3,
                                  uint64_t arg4, uint64_t arg5, uint64_t arg6) {
    (void)arg1; (void)arg2; (void)arg3; (void)arg4; (void)arg5; (void)arg6;
    extern long sys_setsid(void);
    return sys_setsid();
}

static int64_t sys_getrlimit_handler(uint64_t resource, uint64_t rlim, uint64_t arg3,
                                     uint64_t arg4, uint64_t arg5, uint64_t arg6) {
    (void)arg3; (void)arg4; (void)arg5; (void)arg6;
    extern long sys_getrlimit(int resource, struct rlimit *rlim);
    return sys_getrlimit((int)resource, (struct rlimit *)(uintptr_t)rlim);
}

static int64_t sys_setrlimit_handler(uint64_t resource, uint64_t rlim, uint64_t arg3,
                                     uint64_t arg4, uint64_t arg5, uint64_t arg6) {
    (void)arg3; (void)arg4; (void)arg5; (void)arg6;
    extern long sys_setrlimit(int resource, const struct rlimit *rlim);
    return sys_setrlimit((int)resource, (const struct rlimit *)(uintptr_t)rlim);
}

/* File manipulation syscall handlers */
static int64_t sys_rename_handler(uint64_t oldpath, uint64_t newpath, uint64_t arg3,
                                  uint64_t arg4, uint64_t arg5, uint64_t arg6) {
    (void)arg3; (void)arg4; (void)arg5; (void)arg6;
    extern long sys_rename(const char *oldpath, const char *newpath);
    return sys_rename((const char *)(uintptr_t)oldpath, (const char *)(uintptr_t)newpath);
}

static int64_t sys_chmod_handler(uint64_t path, uint64_t mode, uint64_t arg3,
                                 uint64_t arg4, uint64_t arg5, uint64_t arg6) {
    (void)arg3; (void)arg4; (void)arg5; (void)arg6;
    extern long sys_chmod(const char *path, uint32_t mode);
    return sys_chmod((const char *)(uintptr_t)path, (uint32_t)mode);
}

static int64_t sys_fchmod_handler(uint64_t fd, uint64_t mode, uint64_t arg3,
                                  uint64_t arg4, uint64_t arg5, uint64_t arg6) {
    (void)arg3; (void)arg4; (void)arg5; (void)arg6;
    extern long sys_fchmod(int fd, uint32_t mode);
    return sys_fchmod((int)fd, (uint32_t)mode);
}

static int64_t sys_chown_handler(uint64_t path, uint64_t uid, uint64_t gid,
                                 uint64_t arg4, uint64_t arg5, uint64_t arg6) {
    (void)arg4; (void)arg5; (void)arg6;
    extern long sys_chown(const char *path, uint32_t uid, uint32_t gid);
    return sys_chown((const char *)(uintptr_t)path, (uint32_t)uid, (uint32_t)gid);
}

static int64_t sys_fchown_handler(uint64_t fd, uint64_t uid, uint64_t gid,
                                  uint64_t arg4, uint64_t arg5, uint64_t arg6) {
    (void)arg4; (void)arg5; (void)arg6;
    extern long sys_fchown(int fd, uint32_t uid, uint32_t gid);
    return sys_fchown((int)fd, (uint32_t)uid, (uint32_t)gid);
}

static int64_t sys_truncate_handler(uint64_t path, uint64_t length, uint64_t arg3,
                                    uint64_t arg4, uint64_t arg5, uint64_t arg6) {
    (void)arg3; (void)arg4; (void)arg5; (void)arg6;
    extern long sys_truncate(const char *path, uint64_t length);
    return sys_truncate((const char *)(uintptr_t)path, (uint64_t)length);
}

static int64_t sys_fcntl_handler(uint64_t fd, uint64_t cmd, uint64_t arg,
                                 uint64_t arg4, uint64_t arg5, uint64_t arg6) {
    (void)arg4; (void)arg5; (void)arg6;
    extern long sys_fcntl(int fd, int cmd, uint64_t arg);
    return sys_fcntl((int)fd, (int)cmd, (uint64_t)arg);
}

static int64_t sys_flock_handler(uint64_t fd, uint64_t operation, uint64_t arg3,
                                 uint64_t arg4, uint64_t arg5, uint64_t arg6) {
    (void)arg3; (void)arg4; (void)arg5; (void)arg6;
    extern long sys_flock(int fd, int operation);
    return sys_flock((int)fd, (int)operation);
}

static int64_t sys_fsync_handler(uint64_t fd, uint64_t arg2, uint64_t arg3,
                                 uint64_t arg4, uint64_t arg5, uint64_t arg6) {
    (void)arg2; (void)arg3; (void)arg4; (void)arg5; (void)arg6;
    /* Use kernel sys_fsync for file synchronization */
    return sys_fsync((int)fd);
}

static int64_t sys_fdatasync_handler(uint64_t fd, uint64_t arg2, uint64_t arg3,
                                     uint64_t arg4, uint64_t arg5, uint64_t arg6) {
    (void)arg2; (void)arg3; (void)arg4; (void)arg5; (void)arg6;
    /* Use kernel sys_fdatasync for file data synchronization */
    return sys_fdatasync((int)fd);
}

static int64_t sys_access_handler(uint64_t path, uint64_t mode, uint64_t arg3,
                                  uint64_t arg4, uint64_t arg5, uint64_t arg6) {
    (void)arg3; (void)arg4; (void)arg5; (void)arg6;
    extern long sys_access(const char *path, int mode);
    return sys_access((const char *)(uintptr_t)path, (int)mode);
}

static int64_t sys_lseek_handler(uint64_t fd, uint64_t offset, uint64_t whence,
                                 uint64_t arg4, uint64_t arg5, uint64_t arg6) {
    (void)arg4; (void)arg5; (void)arg6;
    extern int64_t sys_lseek(int fd, int64_t offset, int whence);
    return sys_lseek((int)fd, (int64_t)offset, (int)whence);
}

static int64_t sys_gettimeofday_handler(uint64_t tv, uint64_t tz, uint64_t arg3,
                                        uint64_t arg4, uint64_t arg5, uint64_t arg6) {
    (void)arg3; (void)arg4; (void)arg5; (void)arg6;
    extern long sys_gettimeofday(fut_timeval_t *tv, void *tz);
    return sys_gettimeofday((fut_timeval_t *)(uintptr_t)tv, (void *)(uintptr_t)tz);
}

static int64_t sys_time_handler(uint64_t tloc, uint64_t arg2, uint64_t arg3,
                                uint64_t arg4, uint64_t arg5, uint64_t arg6) {
    (void)arg2; (void)arg3; (void)arg4; (void)arg5; (void)arg6;
    extern long sys_time(uint64_t *tloc);
    return sys_time((uint64_t *)(uintptr_t)tloc);
}

static int64_t sys_clock_gettime_handler(uint64_t clock_id, uint64_t tp, uint64_t arg3,
                                         uint64_t arg4, uint64_t arg5, uint64_t arg6) {
    (void)arg3; (void)arg4; (void)arg5; (void)arg6;
    extern long sys_clock_gettime(int clock_id, fut_timespec_t *tp);
    return sys_clock_gettime((int)clock_id, (fut_timespec_t *)(uintptr_t)tp);
}

/* ============================================================
 *   Syscall Table
 * ============================================================ */

/* Forward declarations for socket handlers defined later */
static int64_t sys_connect_handler(uint64_t sockfd, uint64_t addr, uint64_t addrlen,
                                   uint64_t arg4, uint64_t arg5, uint64_t arg6);
static int64_t sys_sendto_handler(uint64_t sockfd, uint64_t buf, uint64_t len,
                                  uint64_t flags, uint64_t addr, uint64_t addrlen);
static int64_t sys_recvfrom_handler(uint64_t sockfd, uint64_t buf, uint64_t len,
                                    uint64_t flags, uint64_t addr, uint64_t addrlen);

static syscall_handler_t syscall_table[MAX_SYSCALL] = {
    [SYS_read]       = sys_read_handler,
    [SYS_pread64]    = sys_pread64_handler,
    [SYS_pwrite64]   = sys_pwrite64_handler,
    [SYS_write]      = sys_write_handler,
    [SYS_open]       = sys_open_handler,
    [SYS_openat]     = sys_openat_handler,
    [SYS_close]      = sys_close_handler,
    [SYS_stat]       = sys_stat_handler,
    [SYS_fstat]      = sys_fstat_handler,
    [SYS_lstat]      = sys_lstat_handler,
    [SYS_poll]       = sys_poll_handler,
    [SYS_access]     = sys_access_handler,
    [SYS_lseek]      = sys_lseek_handler,
    [SYS_fork]       = sys_fork_handler,
    [SYS_execve]     = sys_execve_handler,
    [SYS_exit]       = sys_exit_handler,
    [SYS_wait4]      = sys_wait4_handler,
    [SYS_nanosleep]  = sys_nanosleep_handler,
    [SYS_brk]        = sys_brk_handler,
    [SYS_munmap]     = sys_munmap_handler,
    [SYS_mprotect]   = sys_mprotect_handler,
    [SYS_echo]       = sys_echo_handler,
    [SYS_ioctl]      = sys_ioctl_handler,
    [SYS_mmap]       = sys_mmap_handler,
    [SYS_pipe]       = sys_pipe_handler,
    [SYS_select]     = sys_select_handler,
    [SYS_sched_yield] = sys_sched_yield_handler,
    [SYS_dup]        = sys_dup_handler,
    [SYS_dup2]       = sys_dup2_handler,
    [SYS_pause]      = sys_pause_handler,
    [SYS_alarm]      = sys_alarm_handler,
    [SYS_fcntl]      = sys_fcntl_handler,
    [SYS_flock]      = sys_flock_handler,
    [SYS_fsync]      = sys_fsync_handler,
    [SYS_fdatasync]  = sys_fdatasync_handler,
    [SYS_truncate]   = sys_truncate_handler,
    [SYS_ftruncate]  = sys_ftruncate_handler,
    [SYS_getcwd]     = sys_getcwd_handler,
    [SYS_chdir]      = sys_chdir_handler,
    [SYS_mkdir]      = sys_mkdir_handler,
    [SYS_rmdir]      = sys_rmdir_handler,
    [SYS_unlink]     = sys_unlink_handler,
    [SYS_link]       = sys_link_handler,
    [SYS_symlink]    = sys_symlink_handler,
    [SYS_readlink]   = sys_readlink_handler,
    [SYS_rename]     = sys_rename_handler,
    [SYS_chmod]      = sys_chmod_handler,
    [SYS_fchmod]     = sys_fchmod_handler,
    [SYS_chown]      = sys_chown_handler,
    [SYS_fchown]     = sys_fchown_handler,
    [SYS_getdents64] = sys_getdents64_handler,
    [SYS_getpid]     = sys_getpid_handler,
    [SYS_sigaction]  = sys_sigaction_handler,
    [SYS_sigprocmask] = sys_sigprocmask_handler,
    [SYS_sigreturn]  = sys_sigreturn_handler,
    [SYS_kill]       = sys_kill_handler,
    [SYS_time_millis] = sys_time_millis_handler,
    [SYS_gettimeofday] = sys_gettimeofday_handler,
    [SYS_time]       = sys_time_handler,
    [SYS_clock_gettime] = sys_clock_gettime_handler,
    /* Socket operations */
    [SYS_socket]     = sys_socket_handler,
    [SYS_bind]       = sys_bind_handler,
    [SYS_listen]     = sys_listen_handler,
    [SYS_accept]     = sys_accept_handler,
    [SYS_connect]    = sys_connect_handler,
    [SYS_sendto]     = sys_sendto_handler,
    [SYS_recvfrom]   = sys_recvfrom_handler,
    /* epoll operations */
    [SYS_epoll_create] = sys_epoll_create_handler,
    [SYS_epoll_ctl]    = sys_epoll_ctl_handler,
    [SYS_epoll_wait]   = sys_epoll_wait_handler,
    /* madvise operation */
    [SYS_madvise]      = sys_madvise_handler,
    /* process credential operations */
    [SYS_getuid]       = sys_getuid_handler,
    [SYS_geteuid]      = sys_geteuid_handler,
    [SYS_getgid]       = sys_getgid_handler,
    [SYS_getegid]      = sys_getegid_handler,
    [SYS_setuid]       = sys_setuid_handler,
    [SYS_seteuid]      = sys_seteuid_handler,
    [SYS_setgid]       = sys_setgid_handler,
    [SYS_setegid]      = sys_setegid_handler,
    [SYS_umask]        = sys_umask_handler,
    [SYS_uname]        = sys_uname_handler,
    /* Process info operations */
    [SYS_gettid]       = sys_gettid_handler,
    [SYS_getppid]      = sys_getppid_handler,
    [SYS_getpgrp]      = sys_getpgrp_handler,
    /* Note: SYS_setpgrp skipped (same as SYS_setpgid=109, which conflicts with SYS_seteuid) */
    [SYS_getsid]       = sys_getsid_handler,
    [SYS_setsid]       = sys_setsid_handler,
    [SYS_getrlimit]    = sys_getrlimit_handler,
    [SYS_getrusage]    = sys_getrusage_handler,
    [SYS_times]        = sys_times_handler,
    [SYS_setrlimit]    = sys_setrlimit_handler,
    [SYS_getpriority]  = sys_getpriority_handler,
    [SYS_setpriority]  = sys_setpriority_handler,
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
        extern void fut_printf(const char *, ...);
        fut_printf("[DISPATCHER] ERROR: syscall %lu >= MAX_SYSCALL %d\n", syscall_num, MAX_SYSCALL);
        return -1;  /* ENOSYS */
    }

    /* Get handler from table */
    syscall_handler_t handler = syscall_table[syscall_num];
    if (handler == NULL) {
        handler = sys_unimplemented;
    }

    /* Call handler */
    int64_t result = handler(arg1, arg2, arg3, arg4, arg5, arg6);

    return result;
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

/**
 * Deliver a signal to a task by setting up a signal frame on the user stack
 * and modifying the interrupt frame to call the handler.
 *
 * This implements proper signal frame setup as per System V AMD64 ABI.
 * The handler receives:
 *   rdi = signal number
 *   rsi = siginfo_t *
 *   rdx = ucontext_t *
 *
 * @param current Current task
 * @param signum Signal number to deliver
 * @param frame Interrupt frame to modify
 * @return true if signal was delivered, false if handler not available
 */
static bool posix_deliver_signal(fut_task_t *current, int signum,
                                 fut_interrupt_frame_t *frame) {
    extern void fut_printf(const char *, ...);

    if (!current || !frame) {
        return false;
    }

    /* Get the handler for this signal */
    sighandler_t handler = fut_signal_get_handler(current, signum);

    /* Clear this signal from pending */
    uint64_t signal_bit = (1ULL << (signum - 1));
    current->pending_signals &= ~signal_bit;

    /* If no handler or SIG_IGN, skip delivery */
    if (!handler || handler == SIG_IGN || handler == SIG_DFL) {
        return false;
    }

    /* Get user stack pointer from frame */
    uint64_t user_rsp = frame->rsp;

    /* Allocate rt_sigframe on user stack (must be 16-byte aligned)
     * Decrement RSP to make room for frame, ensuring 16-byte alignment
     * before the RIP pushed by CALL instruction is accounted for */
    user_rsp -= sizeof(struct rt_sigframe);
    user_rsp &= ~15ULL;  /* Align to 16 bytes */

    /* Verify user stack is accessible (basic check) */
    if (user_rsp < 0x400000) {  /* Below reasonable user stack threshold */
        fut_printf("[SIGNAL] Stack underflow attempting to deliver signal %d\n", signum);
        return false;
    }

    /* Build signal frame in kernel memory */
    struct rt_sigframe sigframe = {};

    /* Fill in signal info with proper UID tracking */
    sigframe.info.si_signum = signum;
    sigframe.info.si_errno = 0;
    sigframe.info.si_code = 0;  /* SI_USER */
    sigframe.info.si_pid = current->pid;
    sigframe.info.si_uid = current->uid;  /* ✓ Now tracking actual UID */
    sigframe.info.si_status = 0;
    sigframe.info.si_addr = NULL;
    sigframe.info.si_value = 0;
    sigframe.info.si_overrun = 0;
    sigframe.info.si_timerid = 0;

    /* Fill in machine context (CPU registers at time of interruption) */
    mcontext_t *mctx = &sigframe.uc.uc_mcontext;
    mctx->gregs.r8 = frame->r8;
    mctx->gregs.r9 = frame->r9;
    mctx->gregs.r10 = frame->r10;
    mctx->gregs.r11 = frame->r11;
    mctx->gregs.r12 = frame->r12;
    mctx->gregs.r13 = frame->r13;
    mctx->gregs.r14 = frame->r14;
    mctx->gregs.r15 = frame->r15;
    mctx->gregs.rdi = frame->rdi;
    mctx->gregs.rsi = frame->rsi;
    mctx->gregs.rbp = frame->rbp;
    mctx->gregs.rbx = frame->rbx;
    mctx->gregs.rdx = frame->rdx;
    mctx->gregs.rax = frame->rax;
    mctx->gregs.rcx = frame->rcx;
    mctx->gregs.rsp = frame->rsp;  /* Original RSP before sigframe */
    mctx->gregs.rip = frame->rip;  /* Original RIP to return to */
    mctx->gregs.eflags = frame->rflags;
    mctx->gregs.cs = frame->cs;
    mctx->gregs.gs = frame->gs;
    mctx->gregs.fs = frame->fs;
    mctx->gregs.__pad0 = 0;
    mctx->gregs.err = frame->error_code;
    mctx->gregs.trapno = frame->vector;

    /* Fill in user context with signal mask tracking */
    sigframe.uc.uc_flags = 0;
    sigframe.uc.uc_link = NULL;
    sigframe.uc.uc_stack.ss_sp = NULL;
    sigframe.uc.uc_stack.ss_flags = 0;
    sigframe.uc.uc_stack.ss_size = 0;
    /* Save the CURRENT signal mask so sigreturn can restore it */
    sigframe.uc.uc_sigmask.__mask = current->signal_mask;

    /* Apply the handler's sa_mask during delivery:
     * Block additional signals specified in the handler's sa_mask */
    if (signum < _NSIG) {
        uint64_t handler_mask = current->signal_handler_masks[signum];
        uint64_t saved_mask = current->signal_mask;
        current->signal_mask |= handler_mask;  /* Block these signals during handler */

        /* Save the original mask in the frame so sigreturn can restore it */
        sigframe.uc.uc_sigmask.__mask = saved_mask;
    }

    /* Set return address (for when handler calls sigreturn) */
    sigframe.return_address = NULL;  /* Could point to user-space trampoline */
    sigframe.pad = 0;

    /* Copy frame to user stack */
    if (fut_copy_to_user((void *)user_rsp, &sigframe, sizeof(sigframe)) != 0) {
        fut_printf("[SIGNAL] Failed to copy sigframe to user stack for signal %d\n", signum);
        return false;
    }

    /* Modify interrupt frame to call handler
     * The handler will be called with:
     *   rdi = signal number
     *   rsi = siginfo_t *
     *   rdx = ucontext_t *
     *
     * Calculate offsets into the frame for siginfo_t and ucontext_t
     */
    uint64_t siginfo_addr = user_rsp + offsetof(struct rt_sigframe, info);
    uint64_t ucontext_addr = user_rsp + offsetof(struct rt_sigframe, uc);

    frame->rdi = (uint64_t)signum;
    frame->rsi = siginfo_addr;
    frame->rdx = ucontext_addr;
    frame->rip = (uint64_t)handler;
    frame->rsp = user_rsp;

    /* Apply SA_RESETHAND flag if set:
     * Reset handler to SIG_DFL after delivery */
    if (signum < _NSIG && (current->signal_handler_flags[signum] & SA_RESETHAND)) {
        fut_signal_set_handler(current, signum, SIG_DFL);
        fut_printf("[SIGNAL] Applied SA_RESETHAND for signal %d\n", signum);
    }

    fut_printf("[SIGNAL] Delivered signal %d to task %llu, handler=%p, frame=%p\n",
              signum, current->pid, (void *)(uintptr_t)handler, (void *)user_rsp);

    return true;
}

/**
 * Check for pending signals and deliver them.
 * Called from syscall return path to give pending signals a chance to execute.
 *
 * @param current Current task
 * @param frame Interrupt frame to modify for signal delivery
 * @return Signal number if one was delivered, 0 if no signals pending
 */
static int check_and_deliver_pending_signals(fut_task_t *current,
                                             fut_interrupt_frame_t *frame) {
    if (!current || !frame) {
        return 0;
    }

    /* Iterate through all possible signals and deliver the first one found */
    for (int signum = 1; signum < _NSIG; signum++) {
        if (fut_signal_is_pending(current, signum)) {
            if (posix_deliver_signal(current, signum, frame)) {
                return signum;
            }
        }
    }

    return 0;
}

long syscall_entry_c(uint64_t nr,
                     uint64_t a1, uint64_t a2, uint64_t a3,
                     uint64_t a4, uint64_t a5, uint64_t a6,
                     uint64_t *frame_ptr) {
    long ret = (long)posix_syscall_dispatch(nr, a1, a2, a3, a4, a5, a6);

    /* Check for pending signals and deliver them before returning to user */
    extern fut_task_t *fut_task_current(void);
    extern void fut_printf(const char *, ...);

    fut_task_t *current = fut_task_current();
    if (current && current->pending_signals != 0 && frame_ptr) {
        fut_interrupt_frame_t *frame = (fut_interrupt_frame_t *)frame_ptr;
        int sig_delivered = check_and_deliver_pending_signals(current, frame);
        if (sig_delivered != 0) {
            fut_printf("[SIGNAL] Signal %d will be delivered upon return to user\n",
                      sig_delivered);
            /* Return value is overwritten by signal handler, or returned if handler exits */
        }
    }

    return ret;
}
