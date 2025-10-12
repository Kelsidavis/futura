/* futura_posix.h - POSIX Daemon Protocol
 *
 * Copyright (c) 2025 Kelsi Davis
 * Licensed under the MPL v2.0 — see LICENSE for details.
 *
 * Protocol for communicating with posixd, the POSIX runtime daemon.
 * Translates POSIX syscalls into FIPC requests.
 */

#pragma once

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>
#include <kernel/fut_fipc.h>

/* ============================================================
 *   POSIX Types (for freestanding environment)
 * ============================================================ */

#ifndef __POSIX_TYPES_DEFINED
#define __POSIX_TYPES_DEFINED

typedef int64_t ssize_t;
typedef int64_t off_t;
typedef uint32_t mode_t;
typedef uint32_t uid_t;
typedef uint32_t gid_t;
typedef uint64_t dev_t;
typedef uint64_t ino_t;
typedef uint32_t nlink_t;
typedef uint32_t blksize_t;
typedef uint64_t blkcnt_t;
typedef int64_t time_t;
typedef int32_t pid_t;

#endif /* __POSIX_TYPES_DEFINED */

/* ============================================================
 *   POSIX Daemon Message Types
 * ============================================================ */

/* Message type range: 0x3000 - 0x3FFF */

/* File operations */
#define POSIXD_MSG_OPEN       0x3001
#define POSIXD_MSG_CLOSE      0x3002
#define POSIXD_MSG_READ       0x3003
#define POSIXD_MSG_WRITE      0x3004
#define POSIXD_MSG_LSEEK      0x3005
#define POSIXD_MSG_STAT       0x3006
#define POSIXD_MSG_FSTAT      0x3007
#define POSIXD_MSG_IOCTL      0x3008
#define POSIXD_MSG_DUP        0x3009
#define POSIXD_MSG_DUP2       0x300A

/* Directory operations */
#define POSIXD_MSG_OPENDIR    0x3010
#define POSIXD_MSG_READDIR    0x3011
#define POSIXD_MSG_CLOSEDIR   0x3012
#define POSIXD_MSG_MKDIR      0x3013
#define POSIXD_MSG_RMDIR      0x3014
#define POSIXD_MSG_CHDIR      0x3015
#define POSIXD_MSG_GETCWD     0x3016
#define POSIXD_MSG_UNLINK     0x3017

/* Process management */
#define POSIXD_MSG_FORK       0x3020
#define POSIXD_MSG_EXEC       0x3021
#define POSIXD_MSG_WAIT       0x3022
#define POSIXD_MSG_EXIT       0x3023
#define POSIXD_MSG_GETPID     0x3024
#define POSIXD_MSG_KILL       0x3025

/* Pipes and IPC */
#define POSIXD_MSG_PIPE       0x3030
#define POSIXD_MSG_PIPE2      0x3031

/* Memory management */
#define POSIXD_MSG_BRK        0x3040
#define POSIXD_MSG_MMAP       0x3041
#define POSIXD_MSG_MUNMAP     0x3042

/* ============================================================
 *   Constants
 * ============================================================ */

#define POSIX_PATH_MAX 4096
#define POSIX_NAME_MAX 255

/* ============================================================
 *   File Operation Messages
 * ============================================================ */

struct posixd_open_req {
    char path[POSIX_PATH_MAX];
    int flags;
    mode_t mode;
};

struct posixd_open_resp {
    int fd;              /* File descriptor, or -errno */
};

struct posixd_close_req {
    int fd;
};

struct posixd_close_resp {
    int result;          /* 0 on success, -errno on error */
};

struct posixd_read_req {
    int fd;
    size_t count;
    uint64_t buffer_region_id;  /* FIPC shared buffer for data */
};

struct posixd_read_resp {
    ssize_t bytes_read;  /* Bytes read, or -errno */
};

struct posixd_write_req {
    int fd;
    size_t count;
    uint64_t buffer_region_id;  /* FIPC shared buffer with data */
};

struct posixd_write_resp {
    ssize_t bytes_written;  /* Bytes written, or -errno */
};

struct posixd_lseek_req {
    int fd;
    off_t offset;
    int whence;          /* SEEK_SET, SEEK_CUR, SEEK_END */
};

struct posixd_lseek_resp {
    off_t new_offset;    /* New offset, or -errno */
};

struct posixd_stat_req {
    char path[POSIX_PATH_MAX];
};

struct posixd_stat_resp {
    int result;          /* 0 on success, -errno on error */
    struct {
        dev_t st_dev;
        ino_t st_ino;
        mode_t st_mode;
        nlink_t st_nlink;
        uid_t st_uid;
        gid_t st_gid;
        dev_t st_rdev;
        off_t st_size;
        blksize_t st_blksize;
        blkcnt_t st_blocks;
        time_t st_atime;
        time_t st_mtime;
        time_t st_ctime;
    } stat;
};

struct posixd_fstat_req {
    int fd;
};

/* posixd_fstat_resp uses same structure as posixd_stat_resp */
typedef struct posixd_stat_resp posixd_fstat_resp;

/* ============================================================
 *   Directory Operation Messages
 * ============================================================ */

struct posixd_opendir_req {
    char path[POSIX_PATH_MAX];
};

struct posixd_opendir_resp {
    int result;          /* 0 on success, -errno on error */
    int64_t dir_handle;  /* Directory handle */
};

struct posixd_readdir_req {
    int64_t dir_handle;
};

struct posixd_readdir_resp {
    int result;          /* 0 on success, -errno on error */
    bool has_entry;      /* false if end of directory */
    struct {
        ino_t d_ino;
        off_t d_off;
        unsigned short d_reclen;
        unsigned char d_type;
        char d_name[POSIX_NAME_MAX + 1];
    } entry;
};

struct posixd_closedir_req {
    int64_t dir_handle;
};

struct posixd_closedir_resp {
    int result;
};

struct posixd_mkdir_req {
    char path[POSIX_PATH_MAX];
    mode_t mode;
};

struct posixd_mkdir_resp {
    int result;
};

struct posixd_unlink_req {
    char path[POSIX_PATH_MAX];
};

struct posixd_unlink_resp {
    int result;
};

struct posixd_getcwd_req {
    size_t size;
};

struct posixd_getcwd_resp {
    int result;
    char path[POSIX_PATH_MAX];
};

/* ============================================================
 *   Process Management Messages
 * ============================================================ */

struct posixd_fork_req {
    /* No parameters */
};

struct posixd_fork_resp {
    pid_t pid;           /* Child PID in parent, 0 in child, -errno on error */
};

struct posixd_exec_req {
    char path[POSIX_PATH_MAX];
    int argc;
    int envc;
    /* Followed by argv strings, then envp strings in payload */
};

struct posixd_exec_resp {
    int result;          /* Does not return on success, -errno on error */
};

struct posixd_wait_req {
    pid_t pid;           /* -1 for any child */
    int options;
};

struct posixd_wait_resp {
    pid_t pid;           /* Waited child PID, or -errno */
    int status;
};

struct posixd_exit_req {
    int status;
};

/* exit does not return */

struct posixd_getpid_req {
    /* No parameters */
};

struct posixd_getpid_resp {
    pid_t pid;
};

struct posixd_kill_req {
    pid_t pid;
    int sig;
};

struct posixd_kill_resp {
    int result;
};

/* ============================================================
 *   Pipe Messages
 * ============================================================ */

struct posixd_pipe_req {
    int flags;
};

struct posixd_pipe_resp {
    int result;
    int pipefd[2];       /* Read and write file descriptors */
};

/* ============================================================
 *   Memory Management Messages
 * ============================================================ */

struct posixd_brk_req {
    void *addr;
};

struct posixd_brk_resp {
    void *new_brk;       /* New break, or (void *)-errno */
};

struct posixd_mmap_req {
    void *addr;
    size_t length;
    int prot;
    int flags;
    int fd;
    off_t offset;
};

struct posixd_mmap_resp {
    void *addr;          /* Mapped address, or MAP_FAILED */
};

struct posixd_munmap_req {
    void *addr;
    size_t length;
};

struct posixd_munmap_resp {
    int result;
};

/* ============================================================
 *   Client API
 * ============================================================ */

/**
 * Connect to POSIX daemon.
 *
 * @return FIPC channel to posixd, or NULL on error
 */
struct fut_fipc_channel *posixd_connect(void);

/**
 * Disconnect from POSIX daemon.
 *
 * @param channel Channel to close
 */
void posixd_disconnect(struct fut_fipc_channel *channel);

/* ============================================================
 *   LibFutura Wrappers
 * ============================================================ */

/* These functions are implemented in libfutura and wrap the FIPC protocol */

int futura_open(const char *pathname, int flags, ...);
int futura_close(int fd);
ssize_t futura_read(int fd, void *buf, size_t count);
ssize_t futura_write(int fd, const void *buf, size_t count);
off_t futura_lseek(int fd, off_t offset, int whence);
/* Phase 3: Implement stat functions */
/* int futura_stat(const char *pathname, struct stat *statbuf); */
/* int futura_fstat(int fd, struct stat *statbuf); */

pid_t futura_fork(void);
int futura_execve(const char *pathname, char *const argv[], char *const envp[]);
pid_t futura_waitpid(pid_t pid, int *status, int options);
void futura_exit(int status) __attribute__((noreturn));
pid_t futura_getpid(void);
int futura_kill(pid_t pid, int sig);

int futura_pipe(int pipefd[2]);
int futura_pipe2(int pipefd[2], int flags);

void *futura_brk(void *addr);
void *futura_mmap(void *addr, size_t length, int prot, int flags, int fd, off_t offset);
int futura_munmap(void *addr, size_t length);
