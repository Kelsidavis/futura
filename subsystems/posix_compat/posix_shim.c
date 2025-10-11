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

/* ============================================================
 *   Process Management (Stubs)
 * ============================================================ */

posix_pid_t posix_fork(void) {
    // Phase 1: Stub implementation
    // Future: Clone current task, copy address space
    return -1;  // Not implemented
}

int posix_execve(const char *pathname, char *const argv[], char *const envp[]) {
    // Phase 1: Stub implementation
    // Future: Load executable, setup new address space
    (void)pathname;
    (void)argv;
    (void)envp;
    return -1;  // Not implemented
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
    // Phase 1: Stub implementation
    // Future: Query file metadata from VFS
    (void)pathname;
    (void)statbuf;
    return -1;  // Not implemented
}

int posix_fstat(posix_fd_t fd, struct posix_stat *statbuf) {
    // Phase 1: Stub implementation
    // Future: Query file metadata from object
    (void)fd;
    (void)statbuf;
    return -1;  // Not implemented
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
