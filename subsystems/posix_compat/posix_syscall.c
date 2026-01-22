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
#include <kernel/fut_object.h>
#include <kernel/fut_memory.h>
#include <kernel/fut_task.h>
#include <kernel/errno.h>
#include <kernel/fut_socket.h>
#include <kernel/signal.h>
#include <kernel/signal_frame.h>
#include <kernel/chrdev.h>
#include <kernel/kprintf.h>
#include <fcntl.h>

/* ============================================================
 *   Syscall Numbers
 * ============================================================ */

/* Standard POSIX syscall numbers (subset) */
#define SYS_read        0
#define SYS_write       1
#define SYS_open        2
#define SYS_close       3
#define SYS_openat      257
/* AT_FDCWD provided by fcntl.h */
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
#define SYS_readv       19
#define SYS_writev      20
#define SYS_pipe        22
#define SYS_preadv      295
#define SYS_pwritev     296
#define SYS_select      23
#define SYS_sched_yield 24
#define SYS_mremap      25
#define SYS_msync       26
#define SYS_mincore     27
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
#define SYS_connect     53  /* Note: non-standard location (42 is echo) */
#define SYS_accept      43
#define SYS_sendto      44
#define SYS_recvfrom    45
#define SYS_sendmsg     46
#define SYS_recvmsg     47
#define SYS_shutdown    48
#define SYS_bind        49
#define SYS_listen      50
#define SYS_getsockname 51
#define SYS_getpeername 52
#define SYS_setsockopt  54
#define SYS_getsockopt  55
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
#define SYS_eventfd2     290
#define SYS_epoll_create1 291
#define SYS_getpriority  140
#define SYS_setpriority  141

#ifndef SYS_time_millis
#define SYS_time_millis  400
#endif

#define SYS_msgrcv      70
#define SYS_msgsnd      69
#define SYS_msgget      68
#define SYS_msgctl      71

/* Capability-based syscall numbers (SYS_open_cap, etc.) are defined in
 * kernel/syscalls.h to avoid duplication */

#define MAX_SYSCALL     512

/* ============================================================
 *   Socket FD Mapping System
 * ============================================================ */

/** Maximum number of socket file descriptors per task */
#define MAX_SOCKET_FDS 256

/** Per-task socket FD table mapping FDs to kernel socket objects */
static fut_socket_t *socket_fd_table[MAX_SOCKET_FDS] = {NULL};

/** Owner tid for each socket fd - prevents cross-process socket closes */
static uint64_t socket_fd_owner[MAX_SOCKET_FDS] = {0};

/* Get current thread ID for socket ownership checks */
#include "../../include/kernel/fut_percpu.h"

/* ============================================================
 *   Socket File Operations for VFS Integration
 * ============================================================ */

/**
 * Socket read operation - called via VFS read() syscall
 * The socket pointer is stored in private_data
 */
static ssize_t socket_read(void *inode, void *private_data, void *u_buf, size_t n, off_t *pos) {
    (void)inode;
    (void)pos;
    fut_socket_t *socket = (fut_socket_t *)private_data;
    if (!socket) {
        return -EBADF;
    }
    ssize_t result = fut_socket_recv(socket, u_buf, n);
    return result;
}

/**
 * Socket write operation - called via VFS write() syscall
 * The socket pointer is stored in private_data
 */
static ssize_t socket_write(void *inode, void *private_data, const void *u_buf, size_t n, off_t *pos) {
    (void)inode;
    (void)pos;
    fut_socket_t *socket = (fut_socket_t *)private_data;
    if (!socket) {
        return -EBADF;
    }
    ssize_t result = fut_socket_send(socket, u_buf, n);
    return result;
}

/**
 * Socket release operation - called when FD is closed
 * The socket pointer is stored in private_data
 */
static int socket_release(void *inode, void *private_data) {
    (void)inode;
    fut_socket_t *socket = (fut_socket_t *)private_data;
    if (!socket) {
        return -EBADF;
    }
    return fut_socket_close(socket);
}

/** Socket file operations for VFS integration */
static struct fut_file_ops socket_fops = {
    .open = NULL,
    .release = socket_release,
    .read = socket_read,
    .write = socket_write,
    .ioctl = NULL,
    .mmap = NULL
};

static int64_t sys_msgget_handler(uint64_t key, uint64_t msgflg, uint64_t arg3,
                                  uint64_t arg4, uint64_t arg5, uint64_t arg6) {
    (void)key; (void)msgflg; (void)arg3; (void)arg4; (void)arg5; (void)arg6;
    fut_printf("[SYSCALL] msgget called but not implemented\n");
    return -ENOSYS;
}

static int64_t sys_msgsnd_handler(uint64_t msqid, uint64_t msgp, uint64_t msgsz,
                                  uint64_t msgflg, uint64_t arg5, uint64_t arg6) {
    (void)msqid; (void)msgp; (void)msgsz; (void)msgflg; (void)arg5; (void)arg6;
    fut_printf("[SYSCALL] msgsnd called but not implemented\n");
    return -ENOSYS;
}

static int64_t sys_msgrcv_handler(uint64_t msqid, uint64_t msgp, uint64_t msgsz,
                                  uint64_t msgtyp, uint64_t msgflg, uint64_t arg6) {
    (void)msqid; (void)msgp; (void)msgsz; (void)msgtyp; (void)msgflg; (void)arg6;
    fut_printf("[SYSCALL] msgrcv called but not implemented\n");
    return -ENOSYS;
}

static int64_t sys_msgctl_handler(uint64_t msqid, uint64_t cmd, uint64_t arg,
                                  uint64_t arg4, uint64_t arg5, uint64_t arg6) {
    (void)msqid; (void)cmd; (void)arg; (void)arg4; (void)arg5; (void)arg6;
    fut_printf("[SYSCALL] msgctl called but not implemented\n");
    return -ENOSYS;
}

static inline uint64_t get_current_tid(void) {
    fut_percpu_t *percpu = fut_percpu_get();
    if (percpu && percpu->current_thread) {
        return percpu->current_thread->tid;
    }
    return 0;
}

/**
 * Get a kernel socket object from a file descriptor.
 * Returns NULL if FD is invalid, not a socket, or belongs to another process.
 */
fut_socket_t *get_socket_from_fd(int fd) {
    if (fd < 0 || fd >= MAX_SOCKET_FDS) {
        return NULL;
    }
    if (socket_fd_table[fd] == NULL) {
        return NULL;
    }
    /* Check ownership - only allow access to sockets owned by current thread */
    uint64_t tid = get_current_tid();
    if (socket_fd_owner[fd] != tid) {
        return NULL;  /* Socket belongs to a different thread/process */
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
 *
 * Uses chrdev_alloc_fd() to register the socket in VFS file table,
 * enabling VFS read/write/close operations to work on socket FDs.
 * The socket pointer is stored as private_data and used by socket_fops.
 */
int allocate_socket_fd(fut_socket_t *socket) {
    /* Use chrdev_alloc_fd to register socket in VFS file table */
    int fd = chrdev_alloc_fd(&socket_fops, NULL, socket);
    if (fd < 0) {
        return fd;  /* Return error code from chrdev_alloc_fd */
    }

    /* Also track in socket_fd_table for get_socket_from_fd() lookups */
    uint64_t tid = get_current_tid();
    if (fd < MAX_SOCKET_FDS) {
        socket_fd_table[fd] = socket;
        socket_fd_owner[fd] = tid;
    }

    return fd;
}

/**
 * Release a socket FD and cleanup the tracking table entry.
 * NOTE: The actual socket close is handled by VFS via socket_release()
 * when using chrdev_alloc_fd. This function just clears the tracking table.
 */
int release_socket_fd(int fd) {
    if (fd < 0 || fd >= MAX_SOCKET_FDS) {
        return -EBADF;
    }

    /* Just clear the tracking table entry - VFS handles actual socket close */
    socket_fd_table[fd] = NULL;
    socket_fd_owner[fd] = 0;

    return 0;
}

/**
 * Propagate socket ownership when a file descriptor is duplicated (dup/dup2).
 * If oldfd refers to a socket, newfd also needs to be tracked as a socket
 * with the same ownership.
 *
 * @param oldfd Source file descriptor
 * @param newfd Target file descriptor (the duplicate)
 * @return 0 on success (even if not a socket), negative on error
 */
int propagate_socket_dup(int oldfd, int newfd) {
    if (oldfd < 0 || oldfd >= MAX_SOCKET_FDS || newfd < 0 || newfd >= MAX_SOCKET_FDS) {
        return 0;  /* Out of range for socket table, not an error */
    }

    /* Check if oldfd is a socket */
    if (socket_fd_table[oldfd] == NULL) {
        return 0;  /* Not a socket, nothing to propagate */
    }

    /* Propagate socket and ownership to newfd */
    socket_fd_table[newfd] = socket_fd_table[oldfd];
    socket_fd_owner[newfd] = socket_fd_owner[oldfd];

    /* Increment socket refcount since we now have two FDs referring to it */
    fut_socket_ref(socket_fd_table[oldfd]);

    return 0;
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
extern long sys_eventfd2(unsigned int initval, int flags);
extern long sys_epoll_create1(int flags);

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

static int64_t sys_eventfd2_handler(uint64_t initval, uint64_t flags, uint64_t arg3,
                                    uint64_t arg4, uint64_t arg5, uint64_t arg6) {
    (void)arg3;
    (void)arg4;
    (void)arg5;
    (void)arg6;
    return (int64_t)sys_eventfd2((unsigned int)initval, (int)flags);
}

static int64_t sys_poll_handler(uint64_t fds, uint64_t nfds, uint64_t timeout,
                                uint64_t arg4, uint64_t arg5, uint64_t arg6) {
    (void)arg4;
    (void)arg5;
    (void)arg6;
    extern long sys_poll(struct pollfd *fds, unsigned long nfds, int timeout);
    return sys_poll((struct pollfd *)(uintptr_t)fds, (unsigned long)nfds, (int)timeout);
}

int copy_user_string(const char *u_path, char *kbuf, size_t max_len) {
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
    (void)arg4; (void)arg5; (void)arg6;
    extern long sys_open(const char *pathname, int flags, int mode);
    return sys_open((const char *)(uintptr_t)pathname, (int)flags, (int)mode);
}

static int64_t sys_openat_handler(uint64_t dirfd, uint64_t pathname, uint64_t flags,
                                  uint64_t mode, uint64_t arg5, uint64_t arg6) {
    (void)arg5; (void)arg6;
    extern long sys_openat(int dirfd, const char *pathname, int flags, int mode);
    return sys_openat((int)dirfd, (const char *)(uintptr_t)pathname, (int)flags, (int)mode);
}

static int64_t sys_close_handler(uint64_t fd, uint64_t arg2, uint64_t arg3,
                                 uint64_t arg4, uint64_t arg5, uint64_t arg6) {
    (void)arg2; (void)arg3; (void)arg4; (void)arg5; (void)arg6;
    extern long sys_close(int fd);
    return sys_close((int)fd);
}

static int64_t sys_write_handler(uint64_t fd, uint64_t buf, uint64_t count,
                                 uint64_t arg4, uint64_t arg5, uint64_t arg6) {
    (void)arg4; (void)arg5; (void)arg6;
    extern ssize_t sys_write(int fd, const void *buf, size_t count);
    return sys_write((int)fd, (const void *)buf, (size_t)count);
}

static int64_t sys_read_handler(uint64_t fd, uint64_t buf, uint64_t count,
                                uint64_t arg4, uint64_t arg5, uint64_t arg6) {
    (void)arg4; (void)arg5; (void)arg6;
    extern ssize_t sys_read(int fd, void *buf, size_t count);
    return sys_read((int)fd, (void *)buf, (size_t)count);
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

static int64_t sys_readv_handler(uint64_t fd, uint64_t iov, uint64_t iovcnt,
                                 uint64_t arg4, uint64_t arg5, uint64_t arg6) {
    (void)arg4; (void)arg5; (void)arg6;
    extern ssize_t sys_readv(int fd, const struct iovec *iov, int iovcnt);
    return (int64_t)sys_readv((int)fd, (const struct iovec *)(uintptr_t)iov, (int)iovcnt);
}

static int64_t sys_writev_handler(uint64_t fd, uint64_t iov, uint64_t iovcnt,
                                  uint64_t arg4, uint64_t arg5, uint64_t arg6) {
    (void)arg4; (void)arg5; (void)arg6;
    extern ssize_t sys_writev(int fd, const struct iovec *iov, int iovcnt);
    return (int64_t)sys_writev((int)fd, (const struct iovec *)(uintptr_t)iov, (int)iovcnt);
}

static int64_t sys_preadv_handler(uint64_t fd, uint64_t iov, uint64_t iovcnt,
                                  uint64_t offset, uint64_t arg5, uint64_t arg6) {
    (void)arg5; (void)arg6;
    extern ssize_t sys_preadv(int fd, const struct iovec *iov, int iovcnt, int64_t offset);
    return (int64_t)sys_preadv((int)fd, (const struct iovec *)(uintptr_t)iov, (int)iovcnt, (int64_t)offset);
}

static int64_t sys_pwritev_handler(uint64_t fd, uint64_t iov, uint64_t iovcnt,
                                   uint64_t offset, uint64_t arg5, uint64_t arg6) {
    (void)arg5; (void)arg6;
    extern ssize_t sys_pwritev(int fd, const struct iovec *iov, int iovcnt, int64_t offset);
    return (int64_t)sys_pwritev((int)fd, (const struct iovec *)(uintptr_t)iov, (int)iovcnt, (int64_t)offset);
}

static int64_t sys_ioctl_handler(uint64_t fd, uint64_t req, uint64_t argp,
                                 uint64_t arg4, uint64_t arg5, uint64_t arg6) {
    (void)arg4; (void)arg5; (void)arg6;
    extern long sys_ioctl(int fd, unsigned long request, void *argp);
    return sys_ioctl((int)fd, (unsigned long)req, (void *)argp);
}

static int64_t sys_mmap_handler(uint64_t addr, uint64_t len, uint64_t prot,
                                uint64_t flags, uint64_t fd, uint64_t off) {
    fut_printf("[MMAP-HANDLER] addr=0x%llx len=%llu prot=%llu flags=%llu fd=%llu off=%llu\n",
               (unsigned long long)addr, (unsigned long long)len,
               (unsigned long long)prot, (unsigned long long)flags,
               (unsigned long long)fd, (unsigned long long)off);
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
    char path_buf[256];
    if (fut_copy_from_user(path_buf, (const void *)pathname, sizeof(path_buf) - 1) != 0) {
        return -EFAULT;
    }
    path_buf[sizeof(path_buf) - 1] = '\0';
    return (int64_t)fut_vfs_mkdir(path_buf, (uint32_t)mode);
}

static int64_t sys_rmdir_handler(uint64_t pathname, uint64_t arg2, uint64_t arg3,
                                  uint64_t arg4, uint64_t arg5, uint64_t arg6) {
    (void)arg2; (void)arg3; (void)arg4; (void)arg5; (void)arg6;
    char path_buf[256];
    if (fut_copy_from_user(path_buf, (const void *)pathname, sizeof(path_buf) - 1) != 0) {
        return -EFAULT;
    }
    path_buf[sizeof(path_buf) - 1] = '\0';
    return (int64_t)fut_vfs_rmdir(path_buf);
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

static int64_t sys_mremap_handler(uint64_t old_addr, uint64_t old_size, uint64_t new_size,
                                  uint64_t flags, uint64_t new_addr, uint64_t arg6) {
    (void)arg6;
    extern long sys_mremap(void *old_address, size_t old_size, size_t new_size,
                           int flags, void *new_address);
    return sys_mremap((void *)old_addr, (size_t)old_size, (size_t)new_size,
                      (int)flags, (void *)new_addr);
}

static int64_t sys_msync_handler(uint64_t addr, uint64_t length, uint64_t flags,
                                 uint64_t arg4, uint64_t arg5, uint64_t arg6) {
    (void)arg4; (void)arg5; (void)arg6;
    extern long sys_msync(void *addr, size_t length, int flags);
    return sys_msync((void *)addr, (size_t)length, (int)flags);
}

static int64_t sys_mincore_handler(uint64_t addr, uint64_t length, uint64_t vec,
                                   uint64_t arg4, uint64_t arg5, uint64_t arg6) {
    (void)arg4; (void)arg5; (void)arg6;
    extern long sys_mincore(void *addr, size_t length, unsigned char *vec);
    return sys_mincore((void *)addr, (size_t)length, (unsigned char *)(uintptr_t)vec);
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
    extern long sys_kill(int pid, int sig);
    return sys_kill((int)pid, (int)signum);
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
    extern long sys_sigaction(int signum, const struct sigaction *act, struct sigaction *oldact);
    return sys_sigaction((int)signum, (const struct sigaction *)act, (struct sigaction *)oldact);
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
    extern long sys_sigprocmask(int how, const sigset_t *set, sigset_t *oldset);
    return sys_sigprocmask((int)how, (const sigset_t *)set, (sigset_t *)oldset);
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
#ifdef __x86_64__
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
#elif defined(__aarch64__)
        struct sigcontext *ctx = &sigframe.uc.uc_mcontext.gregs;

        /* Restore all general purpose registers x0-x30 */
        for (int i = 0; i < 31; i++) {
            frame->x[i] = ctx->x[i];
        }

        /* Restore special ARM64 registers */
        frame->sp = ctx->sp;
        frame->pc = ctx->pc;
        frame->pstate = ctx->pstate;
        frame->far = ctx->fault_address;

        /* Restore NEON/FPU registers
         * sigcontext stores them as __uint128_t, but interrupt_frame stores as 2x uint64_t */
        for (int i = 0; i < 32; i++) {
            __uint128_t v = ctx->v[i];
            frame->fpu_state[2*i] = (uint64_t)(v & 0xFFFFFFFFFFFFFFFFULL);
            frame->fpu_state[2*i+1] = (uint64_t)(v >> 64);
        }

        frame->fpsr = ctx->fpsr;
        frame->fpcr = ctx->fpcr;

        fut_printf("[SIGNAL] Restored context from sigreturn: pc=0x%llx sp=0x%llx\n",
                   frame->pc, frame->sp);
#else
#error "Unsupported architecture for sigreturn"
#endif
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
    (void)arg6;
    extern long sys_select(int nfds, void *readfds, void *writefds, void *exceptfds, fut_timeval_t *timeout);
    return sys_select((int)nfds, (void *)readfds, (void *)writefds, (void *)exceptfds, (fut_timeval_t *)timeout_ptr);
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
    (void)arg4; (void)arg5; (void)arg6;
    extern long sys_socket(int domain, int type, int protocol);
    return sys_socket((int)domain, (int)type, (int)protocol);
}

static int64_t sys_bind_handler(uint64_t sockfd, uint64_t addr, uint64_t addrlen,
                                uint64_t arg4, uint64_t arg5, uint64_t arg6) {
    (void)arg4; (void)arg5; (void)arg6;
    extern long sys_bind(int sockfd, const void *addr, uint32_t addrlen);
    return sys_bind((int)sockfd, (const void *)addr, (uint32_t)addrlen);
}

static int64_t sys_listen_handler(uint64_t sockfd, uint64_t backlog, uint64_t arg3,
                                  uint64_t arg4, uint64_t arg5, uint64_t arg6) {
    (void)arg3; (void)arg4; (void)arg5; (void)arg6;
    extern long sys_listen(int sockfd, int backlog);
    return sys_listen((int)sockfd, (int)backlog);
}

static int64_t sys_shutdown_handler(uint64_t sockfd, uint64_t how, uint64_t arg3,
                                    uint64_t arg4, uint64_t arg5, uint64_t arg6) {
    (void)arg3; (void)arg4; (void)arg5; (void)arg6;
    extern long sys_shutdown(int sockfd, int how);
    return sys_shutdown((int)sockfd, (int)how);
}

static int64_t sys_getpeername_handler(uint64_t sockfd, uint64_t addr, uint64_t addrlen,
                                       uint64_t arg4, uint64_t arg5, uint64_t arg6) {
    (void)arg4; (void)arg5; (void)arg6;
    extern long sys_getpeername(int sockfd, void *addr, uint32_t *addrlen);
    return sys_getpeername((int)sockfd, (void *)(uintptr_t)addr, (uint32_t *)(uintptr_t)addrlen);
}

static int64_t sys_getsockname_handler(uint64_t sockfd, uint64_t addr, uint64_t addrlen,
                                       uint64_t arg4, uint64_t arg5, uint64_t arg6) {
    (void)arg4; (void)arg5; (void)arg6;
    extern long sys_getsockname(int sockfd, void *addr, uint32_t *addrlen);
    return sys_getsockname((int)sockfd, (void *)(uintptr_t)addr, (uint32_t *)(uintptr_t)addrlen);
}

static int64_t sys_setsockopt_handler(uint64_t sockfd, uint64_t level, uint64_t optname,
                                      uint64_t optval, uint64_t optlen, uint64_t arg6) {
    (void)arg6;
    extern long sys_setsockopt(int sockfd, int level, int optname, const void *optval, uint32_t optlen);
    return sys_setsockopt((int)sockfd, (int)level, (int)optname, (const void *)(uintptr_t)optval, (uint32_t)optlen);
}

static int64_t sys_getsockopt_handler(uint64_t sockfd, uint64_t level, uint64_t optname,
                                      uint64_t optval, uint64_t optlen, uint64_t arg6) {
    (void)arg6;
    extern long sys_getsockopt(int sockfd, int level, int optname, void *optval, uint32_t *optlen);
    return sys_getsockopt((int)sockfd, (int)level, (int)optname, (void *)(uintptr_t)optval, (uint32_t *)(uintptr_t)optlen);
}

static int64_t sys_accept_handler(uint64_t sockfd, uint64_t addr, uint64_t addrlen,
                                  uint64_t arg4, uint64_t arg5, uint64_t arg6) {
    (void)arg4; (void)arg5; (void)arg6;
    extern long sys_accept(int sockfd, void *addr, uint32_t *addrlen);
    return sys_accept((int)sockfd, (void *)(uintptr_t)addr, (uint32_t *)(uintptr_t)addrlen);
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
    extern long sys_connect(int sockfd, const void *addr, uint32_t addrlen);
    fut_printf("[CONNECT] connect(sockfd=%llu, addr=0x%llx, addrlen=%llu) entering\n",
               sockfd, addr, addrlen);
    long result = sys_connect((int)sockfd, (const void *)addr, (uint32_t)addrlen);
    fut_printf("[CONNECT] connect() -> %ld\n", result);
    return result;
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
    (void)flags; (void)addr; (void)addrlen;
    extern ssize_t sys_sendto(int sockfd, const void *buf, size_t len, int flags, const void *dest_addr, uint32_t addrlen);
    return sys_sendto((int)sockfd, (const void *)buf, (size_t)len, (int)flags, (const void *)addr, (uint32_t)addrlen);
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
    (void)flags; (void)addr; (void)addrlen;
    extern ssize_t sys_recvfrom(int sockfd, void *buf, size_t len, int flags, void *src_addr, uint32_t *addrlen);
    return sys_recvfrom((int)sockfd, (void *)buf, (size_t)len, (int)flags, (void *)addr, (uint32_t *)addrlen);
}

static int64_t sys_sendmsg_handler(uint64_t sockfd, uint64_t msg, uint64_t flags,
                                   uint64_t arg4, uint64_t arg5, uint64_t arg6) {
    (void)arg4; (void)arg5; (void)arg6;
    extern ssize_t sys_sendmsg(int sockfd, const void *msg, int flags);
    return sys_sendmsg((int)sockfd, (const void *)msg, (int)flags);
}

static int64_t sys_recvmsg_handler(uint64_t sockfd, uint64_t msg, uint64_t flags,
                                   uint64_t arg4, uint64_t arg5, uint64_t arg6) {
    (void)arg4; (void)arg5; (void)arg6;
    extern ssize_t sys_recvmsg(int sockfd, void *msg, int flags);
    return sys_recvmsg((int)sockfd, (void *)msg, (int)flags);
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

static int64_t sys_epoll_create1_handler(uint64_t flags, uint64_t arg2, uint64_t arg3,
                                         uint64_t arg4, uint64_t arg5, uint64_t arg6) {
    (void)arg2; (void)arg3; (void)arg4; (void)arg5; (void)arg6;
    return sys_epoll_create1((int)flags);
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

static int64_t sys_getpgid_handler(uint64_t pid, uint64_t arg2, uint64_t arg3,
                                   uint64_t arg4, uint64_t arg5, uint64_t arg6) {
    (void)arg2; (void)arg3; (void)arg4; (void)arg5; (void)arg6;
    extern long sys_getpgid(uint64_t pid);
    return sys_getpgid(pid);
}

static int64_t sys_setpgid_handler(uint64_t pid, uint64_t pgid, uint64_t arg3,
                                   uint64_t arg4, uint64_t arg5, uint64_t arg6) {
    (void)arg3; (void)arg4; (void)arg5; (void)arg6;
    extern long sys_setpgid(uint64_t pid, uint64_t pgid);
    return sys_setpgid(pid, pgid);
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
 *   Capability-based Syscall Handlers (Phase 1)
 * ============================================================ */

/**
 * sys_open_cap - Open a file with capability handle return.
 *
 * @param pathname Path to file
 * @param flags    Open flags (O_RDONLY, O_WRONLY, O_RDWR, etc.)
 * @param mode     File mode for creation
 * @return Capability handle on success, negative error on failure
 */
static int64_t sys_open_cap_handler(uint64_t pathname, uint64_t flags, uint64_t mode,
                                    uint64_t arg4, uint64_t arg5, uint64_t arg6) {
    (void)arg4; (void)arg5; (void)arg6;
    extern fut_handle_t fut_vfs_open_cap(const char *path, int flags, int mode);
    fut_handle_t handle = fut_vfs_open_cap((const char *)(uintptr_t)pathname,
                                            (int)flags, (int)mode);
    if (handle == FUT_INVALID_HANDLE) {
        return -EBADF;  /* Return error if open failed */
    }
    return (int64_t)handle;
}

/**
 * sys_read_cap - Read from a capability handle.
 *
 * @param handle Capability handle
 * @param buf    Buffer to read into
 * @param count  Number of bytes to read
 * @return Number of bytes read, or negative error
 */
static int64_t sys_read_cap_handler(uint64_t handle, uint64_t buf, uint64_t count,
                                    uint64_t arg4, uint64_t arg5, uint64_t arg6) {
    (void)arg4; (void)arg5; (void)arg6;
    extern long fut_vfs_read_cap(fut_handle_t handle, void *buffer, size_t count);
    return fut_vfs_read_cap((fut_handle_t)handle, (void *)(uintptr_t)buf, (size_t)count);
}

/**
 * sys_write_cap - Write to a capability handle.
 *
 * @param handle Capability handle
 * @param buf    Buffer to write from
 * @param count  Number of bytes to write
 * @return Number of bytes written, or negative error
 */
static int64_t sys_write_cap_handler(uint64_t handle, uint64_t buf, uint64_t count,
                                     uint64_t arg4, uint64_t arg5, uint64_t arg6) {
    (void)arg4; (void)arg5; (void)arg6;
    extern long fut_vfs_write_cap(fut_handle_t handle, const void *buffer, size_t count);
    return fut_vfs_write_cap((fut_handle_t)handle, (const void *)(uintptr_t)buf, (size_t)count);
}

/**
 * sys_close_cap - Close a capability handle.
 *
 * @param handle Capability handle to close
 * @return 0 on success, negative error on failure
 */
static int64_t sys_close_cap_handler(uint64_t handle, uint64_t arg2, uint64_t arg3,
                                     uint64_t arg4, uint64_t arg5, uint64_t arg6) {
    (void)arg2; (void)arg3; (void)arg4; (void)arg5; (void)arg6;
    extern int fut_vfs_close_cap(fut_handle_t handle);
    return fut_vfs_close_cap((fut_handle_t)handle);
}

/**
 * sys_lseek_cap - Seek within a capability handle.
 *
 * @param handle Capability handle
 * @param offset Seek offset
 * @param whence Seek mode (SEEK_SET, SEEK_CUR, SEEK_END)
 * @return New file offset, or negative error
 */
static int64_t sys_lseek_cap_handler(uint64_t handle, uint64_t offset, uint64_t whence,
                                     uint64_t arg4, uint64_t arg5, uint64_t arg6) {
    (void)arg4; (void)arg5; (void)arg6;
    extern long fut_vfs_lseek_cap(fut_handle_t handle, int64_t offset, int whence);
    return fut_vfs_lseek_cap((fut_handle_t)handle, (int64_t)offset, (int)whence);
}

/**
 * sys_fstat_cap - Get file statistics from capability handle.
 *
 * @param handle  Capability handle
 * @param statbuf Buffer to receive statistics
 * @return 0 on success, negative error on failure
 */
static int64_t sys_fstat_cap_handler(uint64_t handle, uint64_t statbuf, uint64_t arg3,
                                     uint64_t arg4, uint64_t arg5, uint64_t arg6) {
    (void)arg3; (void)arg4; (void)arg5; (void)arg6;
    extern int fut_vfs_fstat_cap(fut_handle_t handle, struct fut_stat *statbuf);
    return fut_vfs_fstat_cap((fut_handle_t)handle, (struct fut_stat *)(uintptr_t)statbuf);
}

/**
 * sys_fsync_cap - Sync file data to storage from capability handle.
 *
 * @param handle Capability handle
 * @return 0 on success, negative error on failure
 */
static int64_t sys_fsync_cap_handler(uint64_t handle, uint64_t arg2, uint64_t arg3,
                                     uint64_t arg4, uint64_t arg5, uint64_t arg6) {
    (void)arg2; (void)arg3; (void)arg4; (void)arg5; (void)arg6;
    extern int fut_vfs_fsync_cap(fut_handle_t handle);
    return fut_vfs_fsync_cap((fut_handle_t)handle);
}

/**
 * sys_mkdirat_cap - Create directory relative to parent handle.
 *
 * @param parent_handle Capability handle to parent directory
 * @param name          Name of directory to create
 * @param mode          Directory permissions
 * @return 0 on success, negative error on failure
 */
static int64_t sys_mkdirat_cap_handler(uint64_t parent_handle, uint64_t name, uint64_t mode,
                                       uint64_t arg4, uint64_t arg5, uint64_t arg6) {
    (void)arg4; (void)arg5; (void)arg6;
    extern int fut_vfs_mkdirat_cap(fut_handle_t parent_handle, const char *name, int mode);
    return fut_vfs_mkdirat_cap((fut_handle_t)parent_handle,
                               (const char *)(uintptr_t)name, (int)mode);
}

/**
 * sys_unlinkat_cap - Unlink file relative to parent handle.
 *
 * @param parent_handle Capability handle to parent directory
 * @param name          Name of file to unlink
 * @return 0 on success, negative error on failure
 */
static int64_t sys_unlinkat_cap_handler(uint64_t parent_handle, uint64_t name, uint64_t arg3,
                                        uint64_t arg4, uint64_t arg5, uint64_t arg6) {
    (void)arg3; (void)arg4; (void)arg5; (void)arg6;
    extern int fut_vfs_unlinkat_cap(fut_handle_t parent_handle, const char *name);
    return fut_vfs_unlinkat_cap((fut_handle_t)parent_handle, (const char *)(uintptr_t)name);
}

/**
 * sys_rmdirat_cap - Remove directory relative to parent handle.
 *
 * @param parent_handle Capability handle to parent directory
 * @param name          Name of directory to remove
 * @return 0 on success, negative error on failure
 */
static int64_t sys_rmdirat_cap_handler(uint64_t parent_handle, uint64_t name, uint64_t arg3,
                                       uint64_t arg4, uint64_t arg5, uint64_t arg6) {
    (void)arg3; (void)arg4; (void)arg5; (void)arg6;
    extern int fut_vfs_rmdirat_cap(fut_handle_t parent_handle, const char *name);
    return fut_vfs_rmdirat_cap((fut_handle_t)parent_handle, (const char *)(uintptr_t)name);
}

/**
 * sys_statat_cap - Get file statistics relative to parent handle.
 *
 * @param parent_handle Capability handle to parent directory
 * @param name          Name of file to stat
 * @param statbuf       Buffer to receive statistics
 * @return 0 on success, negative error on failure
 */
static int64_t sys_statat_cap_handler(uint64_t parent_handle, uint64_t name, uint64_t statbuf,
                                      uint64_t arg4, uint64_t arg5, uint64_t arg6) {
    (void)arg4; (void)arg5; (void)arg6;
    extern int fut_vfs_statat_cap(fut_handle_t parent_handle, const char *name,
                                  struct fut_stat *statbuf);
    return fut_vfs_statat_cap((fut_handle_t)parent_handle,
                              (const char *)(uintptr_t)name,
                              (struct fut_stat *)(uintptr_t)statbuf);
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
static int64_t sys_msgget_handler(uint64_t key, uint64_t msgflg, uint64_t arg3,
                                  uint64_t arg4, uint64_t arg5, uint64_t arg6);
static int64_t sys_msgsnd_handler(uint64_t msqid, uint64_t msgp, uint64_t msgsz,
                                  uint64_t msgflg, uint64_t arg5, uint64_t arg6);
static int64_t sys_msgrcv_handler(uint64_t msqid, uint64_t msgp, uint64_t msgsz,
                                  uint64_t msgtyp, uint64_t msgflg, uint64_t arg6);
static int64_t sys_msgctl_handler(uint64_t msqid, uint64_t cmd, uint64_t arg,
                                  uint64_t arg4, uint64_t arg5, uint64_t arg6);

static syscall_handler_t syscall_table[MAX_SYSCALL] = {
    [SYS_read]       = sys_read_handler,
    [SYS_pread64]    = sys_pread64_handler,
    [SYS_pwrite64]   = sys_pwrite64_handler,
    [SYS_readv]      = sys_readv_handler,
    [SYS_writev]     = sys_writev_handler,
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
    [SYS_mremap]     = sys_mremap_handler,
    [SYS_msync]      = sys_msync_handler,
    [SYS_mincore]    = sys_mincore_handler,
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
    [SYS_eventfd2]   = sys_eventfd2_handler,
    /* Socket operations */
    [SYS_socket]     = sys_socket_handler,
    [SYS_bind]       = sys_bind_handler,
    [SYS_listen]     = sys_listen_handler,
    [SYS_shutdown]   = sys_shutdown_handler,
    [SYS_accept]     = sys_accept_handler,
    [SYS_getsockname] = sys_getsockname_handler,
    [SYS_getpeername] = sys_getpeername_handler,
    [SYS_setsockopt] = sys_setsockopt_handler,
    [SYS_getsockopt] = sys_getsockopt_handler,
    [SYS_connect]    = sys_connect_handler,
    [SYS_sendto]     = sys_sendto_handler,
    [SYS_recvfrom]   = sys_recvfrom_handler,
    [SYS_sendmsg]    = sys_sendmsg_handler,
    [SYS_recvmsg]    = sys_recvmsg_handler,
    /* epoll operations */
    [SYS_epoll_create1] = sys_epoll_create1_handler,
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
    /* Note: SYS_setpgrp skipped (109 conflicts with SYS_seteuid) */
    [SYS_getsid]       = sys_getsid_handler,
    [SYS_setpgid]      = sys_setpgid_handler,
    [SYS_getpgid]      = sys_getpgid_handler,
    [SYS_setsid]       = sys_setsid_handler,
    [SYS_getrlimit]    = sys_getrlimit_handler,
    [SYS_getrusage]    = sys_getrusage_handler,
    [SYS_times]        = sys_times_handler,
    [SYS_setrlimit]    = sys_setrlimit_handler,
    [SYS_getpriority]  = sys_getpriority_handler,
    [SYS_setpriority]  = sys_setpriority_handler,
    [SYS_preadv]       = sys_preadv_handler,
    [SYS_pwritev]      = sys_pwritev_handler,
    [SYS_msgget]       = sys_msgget_handler,
    [SYS_msgsnd]       = sys_msgsnd_handler,
    [SYS_msgrcv]       = sys_msgrcv_handler,
    [SYS_msgctl]       = sys_msgctl_handler,
    /* Capability-based syscalls (Phase 1) */
    [SYS_open_cap]     = sys_open_cap_handler,
    [SYS_read_cap]     = sys_read_cap_handler,
    [SYS_write_cap]    = sys_write_cap_handler,
    [SYS_close_cap]    = sys_close_cap_handler,
    [SYS_lseek_cap]    = sys_lseek_cap_handler,
    [SYS_fstat_cap]    = sys_fstat_cap_handler,
    [SYS_fsync_cap]    = sys_fsync_cap_handler,
    [SYS_mkdirat_cap]  = sys_mkdirat_cap_handler,
    [SYS_unlinkat_cap] = sys_unlinkat_cap_handler,
    [SYS_rmdirat_cap]  = sys_rmdirat_cap_handler,
    [SYS_statat_cap]   = sys_statat_cap_handler,
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
        fut_printf("[DISPATCHER] ERROR: syscall %lu >= MAX_SYSCALL %d\n", syscall_num, MAX_SYSCALL);
        return -1;  /* ENOSYS */
    }

    /* Get handler from table */
    syscall_handler_t handler = syscall_table[syscall_num];
    if (handler == NULL) {
        handler = sys_unimplemented;
    }

    if (handler == sys_unimplemented) {
        fut_printf("[SYSCALL] unimplemented nr=%lu\n", syscall_num);
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

    if (!current || !frame) {
        return false;
    }

    /* Get the handler for this signal */
    sighandler_t handler = fut_signal_get_handler(current, signum);

    /* Clear this signal from pending */
    uint64_t signal_bit = (1ULL << (signum - 1));
    current->pending_signals &= ~signal_bit;

    /* Handle SIG_IGN - just ignore the signal */
    if (handler == SIG_IGN) {
        return true;  /* Signal was "handled" by ignoring it */
    }

    /* Handle SIG_DFL - perform default action */
    if (!handler || handler == SIG_DFL) {
        extern void fut_task_signal_exit(int sig);
        int action = fut_signal_get_default_action(signum);
        switch (action) {
            case 0:  /* SIG_ACTION_TERM */
            case 1:  /* SIG_ACTION_CORE */
                fut_printf("[SIGNAL] Default action: terminate task %llu on signal %d\n",
                           current->pid, signum);
                fut_task_signal_exit(signum);
                return true;
            case 2:  /* SIG_ACTION_STOP */
                fut_printf("[SIGNAL] Default action: stop task %llu on signal %d (not implemented)\n",
                           current->pid, signum);
                return true;
            case 3:  /* SIG_ACTION_CONT */
                fut_printf("[SIGNAL] Default action: continue task %llu on signal %d (not implemented)\n",
                           current->pid, signum);
                return true;
            case 4:  /* SIG_ACTION_IGN */
            default:
                return true;  /* Signal was "handled" by default ignore */
        }
    }

    /* Get user stack pointer from frame (architecture-specific) */
#ifdef __x86_64__
    uint64_t user_sp = frame->rsp;
#elif defined(__aarch64__)
    uint64_t user_sp = frame->sp;
#else
#error "Unsupported architecture for signal delivery"
#endif

    /* Allocate rt_sigframe on user stack (must be 16-byte aligned)
     * Decrement SP to make room for frame, ensuring 16-byte alignment */
    user_sp -= sizeof(struct rt_sigframe);
    user_sp &= ~15ULL;  /* Align to 16 bytes */

    /* Verify user stack is accessible (basic check) */
    if (user_sp < 0x400000) {  /* Below reasonable user stack threshold */
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
#ifdef __x86_64__
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
#elif defined(__aarch64__)
    /* ARM64: Fill in machine context with registers at time of interruption */
    mcontext_t *mctx = &sigframe.uc.uc_mcontext;

    /* Copy all general purpose registers x0-x30 */
    for (int i = 0; i < 31; i++) {
        mctx->gregs.x[i] = frame->x[i];
    }

    /* Copy special ARM64 registers */
    mctx->gregs.sp = frame->sp;            /* Stack pointer (SP_EL0) */
    mctx->gregs.pc = frame->pc;            /* Program counter (ELR_EL1) */
    mctx->gregs.pstate = frame->pstate;    /* Processor state (SPSR_EL1) */
    mctx->gregs.fault_address = frame->far; /* Fault address (FAR_EL1) */

    /* Copy NEON/FPU registers
     * frame->fpu_state stores them as 2x uint64_t per register,
     * but sigcontext stores them as __uint128_t */
    for (int i = 0; i < 32; i++) {
        __uint128_t v = ((__uint128_t)frame->fpu_state[2*i+1] << 64) | frame->fpu_state[2*i];
        mctx->gregs.v[i] = v;
    }

    mctx->gregs.fpsr = frame->fpsr;  /* Floating-point status register */
    mctx->gregs.fpcr = frame->fpcr;  /* Floating-point control register */
#else
#error "Unsupported architecture for signal delivery"
#endif

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
    if (signum > 0 && signum < _NSIG) {
        uint64_t handler_mask = current->signal_handler_masks[signum - 1];
        uint64_t saved_mask = current->signal_mask;
        current->signal_mask |= handler_mask;  /* Block these signals during handler */

        /* Save the original mask in the frame so sigreturn can restore it */
        sigframe.uc.uc_sigmask.__mask = saved_mask;
    }

    /* Set return address (for when handler calls sigreturn) */
    sigframe.return_address = NULL;  /* Could point to user-space trampoline */
    sigframe.pad = 0;

    /* Copy frame to user stack */
    if (fut_copy_to_user((void *)user_sp, &sigframe, sizeof(sigframe)) != 0) {
        fut_printf("[SIGNAL] Failed to copy sigframe to user stack for signal %d\n", signum);
        return false;
    }

    /* Modify interrupt frame to call handler */
    uint64_t siginfo_addr = user_sp + offsetof(struct rt_sigframe, info);
    uint64_t ucontext_addr = user_sp + offsetof(struct rt_sigframe, uc);

#ifdef __x86_64__
    /* x86_64 calling convention:
     *   rdi = signal number
     *   rsi = siginfo_t *
     *   rdx = ucontext_t *
     */
    frame->rdi = (uint64_t)signum;
    frame->rsi = siginfo_addr;
    frame->rdx = ucontext_addr;
    frame->rip = (uint64_t)handler;
    frame->rsp = user_sp;
#elif defined(__aarch64__)
    /* ARM64 calling convention:
     *   x0 = signal number
     *   x1 = siginfo_t *
     *   x2 = ucontext_t *
     */
    frame->x[0] = (uint64_t)signum;
    frame->x[1] = siginfo_addr;
    frame->x[2] = ucontext_addr;
    frame->pc = (uint64_t)handler;
    frame->sp = user_sp;
#else
#error "Unsupported architecture for signal frame modification"
#endif

    /* Apply SA_RESETHAND flag if set:
     * Reset handler to SIG_DFL after delivery */
    if (signum < _NSIG && (current->signal_handler_flags[signum] & SA_RESETHAND)) {
        fut_signal_set_handler(current, signum, SIG_DFL);
        fut_printf("[SIGNAL] Applied SA_RESETHAND for signal %d\n", signum);
    }

    fut_printf("[SIGNAL] Delivered signal %d to task %llu, handler=%p, frame=%p\n",
              signum, current->pid, (void *)(uintptr_t)handler, (void *)user_sp);

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
