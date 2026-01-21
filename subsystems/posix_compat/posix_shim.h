/* posix_shim.h - Futura OS POSIX Compatibility Layer
 *
 * Copyright (c) 2025 Kelsi Davis
 * Licensed under the MPL v2.0 — see LICENSE for details.
 *
 * POSIX API emulation layer that redirects standard Unix calls to
 * Futura-native object system and async I/O.
 *
 * This compatibility layer allows standard Unix software to run on
 * Futura OS with minimal modifications.
 */

#pragma once

#include <stddef.h>
#include <stdint.h>

/* Define ssize_t for freestanding environment */
#ifndef __ssize_t_defined
#define __ssize_t_defined 1
typedef int64_t ssize_t;
#endif

/* ============================================================
 *   File Descriptor Compatibility
 * ============================================================ */

/* POSIX file descriptor type (maps to fut_handle_t internally) */
typedef int posix_fd_t;

/**
 * Open a file.
 *
 * @param pathname Path to file
 * @param flags Open flags (O_RDONLY, O_WRONLY, O_RDWR, etc.)
 * @param mode File mode (for creation)
 * @return File descriptor, or -1 on error
 */
posix_fd_t posix_open(const char *pathname, int flags, int mode);

/**
 * Read from a file descriptor.
 *
 * @param fd File descriptor
 * @param buf Buffer to read into
 * @param count Number of bytes to read
 * @return Number of bytes read, or -1 on error
 */
ssize_t posix_read(posix_fd_t fd, void *buf, size_t count);

/**
 * Write to a file descriptor.
 *
 * @param fd File descriptor
 * @param buf Buffer to write from
 * @param count Number of bytes to write
 * @return Number of bytes written, or -1 on error
 */
ssize_t posix_write(posix_fd_t fd, const void *buf, size_t count);

/**
 * Close a file descriptor.
 *
 * @param fd File descriptor
 * @return 0 on success, -1 on error
 */
int posix_close(posix_fd_t fd);

/**
 * Create a pipe for inter-process communication.
 *
 * @param pipefd Array to receive two file descriptors (pipefd[0]=read, pipefd[1]=write)
 * @return 0 on success, -1 on error
 */
int posix_pipe(int pipefd[2]);

/**
 * Duplicate file descriptor to a specific number.
 *
 * @param oldfd Source file descriptor
 * @param newfd Target file descriptor number
 * @return newfd on success, -1 on error
 */
int posix_dup2(int oldfd, int newfd);

/* ============================================================
 *   Process Management Compatibility
 * ============================================================ */

/* POSIX process ID type */
typedef int posix_pid_t;

/**
 * Fork current process (creates new process).
 *
 * @return Child PID in parent, 0 in child, or -1 on error
 */
posix_pid_t posix_fork(void);

/**
 * Execute a program.
 *
 * @param pathname Path to executable
 * @param argv Argument vector
 * @param envp Environment vector
 * @return Does not return on success, -1 on error
 */
int posix_execve(const char *pathname, char *const argv[], char *const envp[]);

/**
 * Wait for child process to terminate.
 *
 * @param status Pointer to status variable
 * @return Child PID, or -1 on error
 */
posix_pid_t posix_wait(int *status);

/**
 * Exit current process.
 *
 * @param status Exit status
 */
void posix_exit(int status) __attribute__((noreturn));

/* ============================================================
 *   File System Compatibility
 * ============================================================ */

/* POSIX stat structure (simplified) */
struct posix_stat {
    uint64_t st_dev;        // Device ID
    uint64_t st_ino;        // Inode number
    uint32_t st_mode;       // File mode
    uint32_t st_nlink;      // Number of hard links
    uint32_t st_uid;        // User ID
    uint32_t st_gid;        // Group ID
    uint64_t st_size;       // File size in bytes
    uint64_t st_atime;      // Last access time
    uint64_t st_mtime;      // Last modification time
    uint64_t st_ctime;      // Last status change time
};

/**
 * Get file status.
 *
 * @param pathname Path to file
 * @param statbuf Pointer to stat structure
 * @return 0 on success, -1 on error
 */
int posix_stat(const char *pathname, struct posix_stat *statbuf);

/**
 * Get file status (file descriptor version).
 *
 * @param fd File descriptor
 * @param statbuf Pointer to stat structure
 * @return 0 on success, -1 on error
 */
int posix_fstat(posix_fd_t fd, struct posix_stat *statbuf);

/* ============================================================
 *   Memory Management Compatibility
 * ============================================================ */

/**
 * Allocate memory.
 *
 * @param size Number of bytes to allocate
 * @return Pointer to allocated memory, or NULL on error
 */
void *posix_malloc(size_t size);

/**
 * Free memory.
 *
 * @param ptr Pointer to memory to free
 */
void posix_free(void *ptr);

/**
 * Reallocate memory.
 *
 * @param ptr Existing allocation
 * @param size New size
 * @return Pointer to reallocated memory, or NULL on error
 */
void *posix_realloc(void *ptr, size_t size);

/* ============================================================
 *   Standard Streams
 * ============================================================ */

#define STDIN_FILENO  0
#define STDOUT_FILENO 1
#define STDERR_FILENO 2

/* ============================================================
 *   Open Flags (subset)
 * ============================================================ */

#define O_RDONLY    0x0000
#define O_WRONLY    0x0001
#define O_RDWR      0x0002
#define O_CREAT     0x0040
#define O_TRUNC     0x0200
#define O_APPEND    0x0400

/* ============================================================
 *   File Mode Bits (subset)
 * ============================================================ */

#define S_IRUSR     0000400    // User read
#define S_IWUSR     0000200    // User write
#define S_IXUSR     0000100    // User execute
#define S_IRWXU     0000700    // User RWX

#define S_IRGRP     0000040    // Group read
#define S_IWGRP     0000020    // Group write
#define S_IXGRP     0000010    // Group execute
#define S_IRWXG     0000070    // Group RWX

#define S_IROTH     0000004    // Other read
#define S_IWOTH     0000002    // Other write
#define S_IXOTH     0000001    // Other execute
#define S_IRWXO     0000007    // Other RWX
