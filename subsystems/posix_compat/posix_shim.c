/* posix_shim.c - Futura OS POSIX Compatibility Layer Implementation
 *
 * Copyright (c) 2025 Kelsi Davis
 * Licensed under the MPL v2.0 — see LICENSE for details.
 *
 * Phase 1: Stub implementations for POSIX compatibility.
 * These stubs provide the API structure for future expansion.
 */

#include "posix_shim.h"
#include "../../include/kernel/fut_object.h"
#include "../../include/kernel/fut_memory.h"
#include "../../include/kernel/fut_vfs.h"
#include <stdint.h>

/* ============================================================
 *   File Descriptor Table (Internal)
 * ============================================================ */

#define MAX_FDS 256

/* Mapping from POSIX fd to Futura handle */
static fut_handle_t fd_table[MAX_FDS];

/* Initialize FD table */
static void init_fd_table(void) {
    static bool initialized = false;
    if (!initialized) {
        for (int i = 0; i < MAX_FDS; ++i) {
            fd_table[i] = FUT_INVALID_HANDLE;
        }
        initialized = true;
    }
}

/* Allocate a new FD */
__attribute__((unused)) static posix_fd_t alloc_fd(fut_handle_t handle) {
    init_fd_table();
    for (int i = 3; i < MAX_FDS; ++i) {  // Reserve 0,1,2 for stdin/stdout/stderr
        if (fd_table[i] == FUT_INVALID_HANDLE) {
            fd_table[i] = handle;
            return i;
        }
    }
    return -1;  // Out of FDs
}

/* Free an FD */
static void free_fd(posix_fd_t fd) {
    if (fd >= 0 && fd < MAX_FDS) {
        fd_table[fd] = FUT_INVALID_HANDLE;
    }
}

/* Get Futura handle from FD */
static fut_handle_t fd_to_handle(posix_fd_t fd) {
    if (fd < 0 || fd >= MAX_FDS) {
        return FUT_INVALID_HANDLE;
    }
    return fd_table[fd];
}

/* ============================================================
 *   File Operations (Stubs)
 * ============================================================ */

posix_fd_t posix_open(const char *pathname, int flags, int mode) {
    // Phase 1: Stub implementation
    // Future: Translate pathname to Futura namespace, create file object
    (void)pathname;
    (void)flags;
    (void)mode;
    return -1;  // Not implemented
}

ssize_t posix_read(posix_fd_t fd, void *buf, size_t count) {
    // Phase 1: Stub implementation
    // Future: Translate to fut_object_receive() or async read
    fut_handle_t handle = fd_to_handle(fd);
    if (handle == FUT_INVALID_HANDLE) {
        return -1;
    }

    (void)buf;
    (void)count;
    return -1;  // Not implemented
}

ssize_t posix_write(posix_fd_t fd, const void *buf, size_t count) {
    // Phase 1: Stub implementation
    // Future: Translate to fut_object_send() or async write
    fut_handle_t handle = fd_to_handle(fd);
    if (handle == FUT_INVALID_HANDLE) {
        return -1;
    }

    (void)buf;
    (void)count;
    return -1;  // Not implemented
}

int posix_close(posix_fd_t fd) {
    // Phase 1: Stub implementation
    // Future: Call fut_object_destroy()
    fut_handle_t handle = fd_to_handle(fd);
    if (handle == FUT_INVALID_HANDLE) {
        return -1;
    }

    free_fd(fd);
    return fut_object_destroy(handle);
}

/* External pipe implementation */
extern long sys_pipe(int pipefd[2]);

int posix_pipe(int pipefd[2]) {
    long ret = sys_pipe(pipefd);
    return (int)ret;
}

/* External dup2 implementation */
extern long sys_dup2(int oldfd, int newfd);

int posix_dup2(int oldfd, int newfd) {
    long ret = sys_dup2(oldfd, newfd);
    return (int)ret;
}

/* ============================================================
 *   Process Management (Stubs)
 * ============================================================ */

/* External fork implementation */
extern long sys_fork(void);

posix_pid_t posix_fork(void) {
    return (posix_pid_t)sys_fork();
}

/* External execve implementation */
extern long sys_execve(const char *pathname, char *const argv[], char *const envp[]);

int posix_execve(const char *pathname, char *const argv[], char *const envp[]) {
    return (int)sys_execve(pathname, argv, envp);
}

posix_pid_t posix_wait(int *status) {
    // Phase 1: Stub implementation
    // Future: Wait on child task object
    (void)status;
    return -1;  // Not implemented
}

void posix_exit(int status) {
    // Phase 1: Stub implementation
    // Future: Terminate current task
    (void)status;
    for (;;);  // Hang (should call task termination)
}

/* ============================================================
 *   File System Operations (Stubs)
 * ============================================================ */

int posix_stat(const char *pathname, struct posix_stat *statbuf) {
    if (!pathname || !statbuf) {
        return -1;
    }

    /* Get stat info from VFS */
    struct fut_stat vfs_stat = {0};
    int ret = fut_vfs_stat(pathname, &vfs_stat);
    if (ret < 0) {
        return -1;  /* VFS error */
    }

    /* Convert fut_stat to posix_stat */
    statbuf->st_dev = vfs_stat.st_dev;
    statbuf->st_ino = vfs_stat.st_ino;
    statbuf->st_mode = vfs_stat.st_mode;
    statbuf->st_nlink = vfs_stat.st_nlink;
    statbuf->st_uid = vfs_stat.st_uid;
    statbuf->st_gid = vfs_stat.st_gid;
    statbuf->st_size = vfs_stat.st_size;
    statbuf->st_atime = vfs_stat.st_atime;
    statbuf->st_mtime = vfs_stat.st_mtime;
    statbuf->st_ctime = vfs_stat.st_ctime;

    return 0;
}

int posix_fstat(posix_fd_t fd, struct posix_stat *statbuf) {
    if (!statbuf) {
        return -1;
    }

    /* Get the file from fd */
    struct fut_file *file = fut_vfs_get_file((int)fd);
    if (!file) {
        return -1;  /* Invalid fd */
    }

    /* If it's a regular file with a vnode, get stat via vnode */
    if (file->vnode && file->vnode->ops && file->vnode->ops->getattr) {
        struct fut_stat vfs_stat = {0};
        int ret = file->vnode->ops->getattr(file->vnode, &vfs_stat);
        if (ret < 0) {
            return -1;
        }

        /* Convert fut_stat to posix_stat */
        statbuf->st_dev = vfs_stat.st_dev;
        statbuf->st_ino = vfs_stat.st_ino;
        statbuf->st_mode = vfs_stat.st_mode;
        statbuf->st_nlink = vfs_stat.st_nlink;
        statbuf->st_uid = vfs_stat.st_uid;
        statbuf->st_gid = vfs_stat.st_gid;
        statbuf->st_size = vfs_stat.st_size;
        statbuf->st_atime = vfs_stat.st_atime;
        statbuf->st_mtime = vfs_stat.st_mtime;
        statbuf->st_ctime = vfs_stat.st_ctime;

        return 0;
    }

    /* For character devices and other file types without standard stat */
    if (file->chr_inode) {
        /* Character device - provide minimal stat info */
        statbuf->st_dev = 6;      /* Device file device */
        statbuf->st_ino = (uint64_t)(uintptr_t)file->chr_inode;
        statbuf->st_mode = 020666;  /* Character device, rw for all (octal: 0o20666) */
        statbuf->st_nlink = 1;
        statbuf->st_uid = 0;
        statbuf->st_gid = 0;
        statbuf->st_size = 0;
        statbuf->st_atime = 0;
        statbuf->st_mtime = 0;
        statbuf->st_ctime = 0;
        return 0;
    }

    return -1;  /* Unknown file type */
}

/* ============================================================
 *   Memory Management (Redirect to Futura)
 * ============================================================ */

void *posix_malloc(size_t size) {
    return fut_malloc(size);
}

void posix_free(void *ptr) {
    fut_free(ptr);
}

void *posix_realloc(void *ptr, size_t size) {
    return fut_realloc(ptr, size);
}
