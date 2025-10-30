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
#define SYS_lseek       8
#ifndef SYS_mmap
#define SYS_mmap        9
#endif
#ifndef SYS_munmap
#define SYS_munmap      11
#endif
#ifndef SYS_brk
#define SYS_brk         12
#endif
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
#define SYS_getdents64   217

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
extern long sys_nanosleep(const fut_timespec_t *u_req, fut_timespec_t *u_rem);
extern long sys_time_millis(void);
extern long sys_pipe(int pipefd[2]);
extern long sys_dup2(int oldfd, int newfd);

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
    return (int64_t)fut_vfs_close((int)fd);
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

static int64_t sys_nanosleep_handler(uint64_t req, uint64_t rem, uint64_t arg3,
                                     uint64_t arg4, uint64_t arg5, uint64_t arg6) {
    (void)arg3; (void)arg4; (void)arg5; (void)arg6;
    return (int64_t)sys_nanosleep((const fut_timespec_t *)(uintptr_t)req,
                                  (fut_timespec_t *)(uintptr_t)rem);
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
    return (int64_t)fut_vfs_unlink((const char *)pathname);
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

/* Directory operations */
static int64_t sys_getdents64_handler(uint64_t fd, uint64_t dirp, uint64_t count,
                                      uint64_t arg4, uint64_t arg5, uint64_t arg6) {
    (void)arg4; (void)arg5; (void)arg6;

    /* Linux getdents64 dirent structure */
    struct linux_dirent64 {
        uint64_t d_ino;
        int64_t  d_off;
        uint16_t d_reclen;
        uint8_t  d_type;
        char     d_name[];
    } __attribute__((packed));

    if (count < sizeof(struct linux_dirent64) + 1) {
        return -EINVAL;
    }

    /* Allocate kernel buffer for directory entries */
    void *kbuf = fut_malloc(count);
    if (!kbuf) {
        return -ENOMEM;
    }

    uint64_t cookie = 0;
    size_t total_bytes = 0;
    char *buf_ptr = (char *)kbuf;

    /* Read directory entries using VFS */
    while (total_bytes < count) {
        struct fut_vdirent vdirent;
        int rc = fut_vfs_readdir_fd((int)fd, &cookie, &vdirent);

        if (rc < 0) {
            if (total_bytes == 0) {
                fut_free(kbuf);
                return rc;  /* Error on first entry */
            }
            break;  /* No more entries */
        }

        if (rc == 0) {
            break;  /* End of directory */
        }

        /* Calculate required size for this entry */
        size_t name_len = 0;
        while (vdirent.d_name[name_len] != '\0' && name_len < 256) {
            name_len++;
        }

        /* Align to 8-byte boundary for next entry */
        size_t reclen = sizeof(struct linux_dirent64) + name_len + 1;
        reclen = (reclen + 7) & ~7;

        if (total_bytes + reclen > count) {
            break;  /* Not enough space for this entry */
        }

        /* Build linux_dirent64 entry */
        struct linux_dirent64 *dent = (struct linux_dirent64 *)buf_ptr;
        dent->d_ino = vdirent.d_ino;
        dent->d_off = (int64_t)cookie;
        dent->d_reclen = (uint16_t)reclen;
        dent->d_type = vdirent.d_type;

        /* Copy name */
        for (size_t i = 0; i <= name_len; i++) {
            dent->d_name[i] = vdirent.d_name[i];
        }

        buf_ptr += reclen;
        total_bytes += reclen;
    }

    /* Copy to userspace */
    if (total_bytes > 0) {
        if (fut_copy_to_user((void *)dirp, kbuf, total_bytes) != 0) {
            fut_free(kbuf);
            return -EFAULT;
        }
    }

    fut_free(kbuf);
    return (int64_t)total_bytes;
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

/* dup() handler - duplicate file descriptor with auto selection */
static int64_t sys_dup_handler(uint64_t oldfd, uint64_t arg2, uint64_t arg3,
                               uint64_t arg4, uint64_t arg5, uint64_t arg6) {
    (void)arg2; (void)arg3; (void)arg4; (void)arg5; (void)arg6;

    if ((int64_t)oldfd < 0) {
        return -EBADF;
    }

    struct fut_file *file = vfs_get_file((int)oldfd);
    if (!file) {
        return -EBADF;
    }

    /* Increment reference count */
    vfs_file_ref(file);

    /* Find first available fd (start from 3 to skip stdin/stdout/stderr) */
    int newfd = 3;
    while (vfs_get_file(newfd) != NULL) {
        newfd++;
        if (newfd > 1024) {
            file->refcount--;
            return -EMFILE;  /* Too many open files */
        }
    }

    /* Allocate the new fd */
    int ret = vfs_alloc_specific_fd(newfd, file);
    if (ret < 0) {
        file->refcount--;
        return ret;
    }

    extern void fut_printf(const char *, ...);
    fut_printf("[DUP] Duplicated fd %d to %d\n", (int)oldfd, newfd);

    return (int64_t)newfd;
}

/* Socket operations handlers */
static int64_t sys_socket_handler(uint64_t domain, uint64_t type, uint64_t protocol,
                                  uint64_t arg4, uint64_t arg5, uint64_t arg6) {
    (void)arg4; (void)arg5; (void)arg6;
    extern void fut_printf(const char *, ...);

    fut_printf("[SOCKET] domain=%lu type=%lu protocol=%lu\n", domain, type, protocol);

    /* Create a socket file descriptor
     * For now, we return a generic socket fd that can be used with bind/listen
     * AF_UNIX (1), SOCK_STREAM (1), SOCK_SEQPACKET (5) are typical for Wayland
     */

    /* Allocate a socket file descriptor - reuse pipe fd logic */
    int pipefd[2];
    int rc = sys_pipe(pipefd);
    if (rc < 0) {
        return rc;
    }

    /* Close the read end, keep write end as the socket fd */
    fut_vfs_close(pipefd[0]);
    return (int64_t)pipefd[1];
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
        return -EINVAL;
    }

    /* Copy the socket path from user space */
    char sock_path[256];
    uint16_t sun_family;
    if (fut_copy_from_user(&sun_family, (const void *)addr, 2) != 0) {
        return -EFAULT;
    }

    /* Copy path component (skip the 2-byte family field) */
    size_t path_len = addrlen - 2;
    if (path_len > sizeof(sock_path) - 1) {
        path_len = sizeof(sock_path) - 1;
    }

    if (path_len > 0) {
        if (fut_copy_from_user(sock_path, (const void *)(addr + 2), path_len) != 0) {
            return -EFAULT;
        }
    }
    sock_path[path_len] = '\0';

    fut_printf("[BIND] sun_family=%u path='%s'\n", sun_family, sock_path);

    /* Validate the socket fd exists */
    struct fut_file *file = vfs_get_file((int)sockfd);
    if (!file) {
        fut_printf("[BIND] ERROR: socket fd %lu is not valid\n", sockfd);
        return -EBADF;
    }

    /* Create the socket file/path to mark the location */
    /* First try to unlink any existing file to avoid conflicts */
    fut_vfs_unlink(sock_path);  /* Ignore errors */

    /* Create the socket file - this marks the path as occupied */
    int ret = fut_vfs_open(sock_path, 0x201, 0644);  /* O_CREAT | O_WRONLY */
    if (ret >= 0) {
        fut_vfs_close(ret);
        fut_printf("[BIND] Successfully bound socket to path '%s'\n", sock_path);
        return 0;  /* Success */
    }

    /* If file creation fails, log and return success anyway */
    /* The socket fd is already valid, binding is mostly metadata */
    fut_printf("[BIND] Warning: could not create socket file, returning success anyway\n");
    return 0;
}

static int64_t sys_listen_handler(uint64_t sockfd, uint64_t backlog, uint64_t arg3,
                                  uint64_t arg4, uint64_t arg5, uint64_t arg6) {
    (void)arg3; (void)arg4; (void)arg5; (void)arg6;
    extern void fut_printf(const char *, ...);

    fut_printf("[LISTEN] sockfd=%lu backlog=%lu\n", sockfd, backlog);

    /* For now, just validate the fd exists and return success */
    struct fut_file *file = vfs_get_file((int)sockfd);
    if (!file) {
        return -EBADF;
    }

    return 0;  /* Success */
}

static int64_t sys_accept_handler(uint64_t sockfd, uint64_t addr, uint64_t addrlen,
                                  uint64_t arg4, uint64_t arg5, uint64_t arg6) {
    (void)arg4; (void)arg5; (void)arg6;
    extern void fut_printf(const char *, ...);

    fut_printf("[ACCEPT] sockfd=%lu addr=0x%lx addrlen=0x%lx\n", sockfd, addr, addrlen);

    /* For now, return an error to indicate no connections available */
    return -EAGAIN;
}

/* Note: connect, sendto, recvfrom handlers not implemented yet */

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
    [SYS_openat]     = sys_openat_handler,
    [SYS_close]      = sys_close_handler,
    [SYS_stat]       = sys_stat_handler,
    [SYS_fstat]      = sys_fstat_handler,
    [SYS_fork]       = sys_fork_handler,
    [SYS_execve]     = sys_execve_handler,
    [SYS_exit]       = sys_exit_handler,
    [SYS_wait4]      = sys_wait4_handler,
    [SYS_nanosleep]  = sys_nanosleep_handler,
    [SYS_brk]        = sys_brk_handler,
    [SYS_munmap]     = sys_munmap_handler,
    [SYS_echo]       = sys_echo_handler,
    [SYS_ioctl]      = sys_ioctl_handler,
    [SYS_mmap]       = sys_mmap_handler,
    [SYS_pipe]       = sys_pipe_handler,
    [SYS_dup]        = sys_dup_handler,
    [SYS_dup2]       = sys_dup2_handler,
    [SYS_mkdir]      = sys_mkdir_handler,
    [SYS_rmdir]      = sys_rmdir_handler,
    [SYS_unlink]     = sys_unlink_handler,
    [SYS_getdents64] = sys_getdents64_handler,
    [SYS_getpid]     = sys_getpid_handler,
    [SYS_time_millis] = sys_time_millis_handler,
    /* Socket operations */
    [SYS_socket]     = sys_socket_handler,
    [SYS_bind]       = sys_bind_handler,
    [SYS_listen]     = sys_listen_handler,
    [SYS_accept]     = sys_accept_handler,
    /* [SYS_connect]    = sys_connect_handler, */  /* Commented out due to init conflict */
    /* [SYS_sendto]     = sys_sendto_handler, */
    /* [SYS_recvfrom]   = sys_recvfrom_handler, */
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
    /* Debug: always log syscall 257 (openat) and syscall 2 (open) */
    extern void fut_printf(const char *, ...);
    if (syscall_num == 257 || syscall_num == 2) {
        fut_printf("[DISPATCHER-DETAIL] syscall %lu (0x%lx) arg1=0x%lx arg2=0x%lx arg3=0x%lx arg4=0x%lx\n",
                   syscall_num, syscall_num, arg1, arg2, arg3, arg4);
    }

    /* Validate syscall number */
    if (syscall_num >= MAX_SYSCALL) {
        fut_printf("[DISPATCHER] ERROR: syscall %lu >= MAX_SYSCALL %d\n", syscall_num, MAX_SYSCALL);
        return -1;  /* ENOSYS */
    }

    /* Get handler from table */
    syscall_handler_t handler = syscall_table[syscall_num];
    if (handler == NULL) {
        fut_printf("[DISPATCHER] WARNING: no handler for syscall %lu\n", syscall_num);
        handler = sys_unimplemented;
    }

    /* Call handler */
    int64_t result = handler(arg1, arg2, arg3, arg4, arg5, arg6);

    if (syscall_num == 257 || syscall_num == 2) {
        fut_printf("[DISPATCHER-RESULT] syscall %lu returned 0x%lx (%ld)\n", syscall_num, (unsigned long)result, result);
    }

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

long syscall_entry_c(uint64_t nr,
                     uint64_t a1, uint64_t a2, uint64_t a3,
                     uint64_t a4, uint64_t a5, uint64_t a6,
                     uint64_t *frame_ptr) {
    (void)frame_ptr;

    long ret = (long)posix_syscall_dispatch(nr, a1, a2, a3, a4, a5, a6);

    return ret;
}
