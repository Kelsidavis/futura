/* posix.c - POSIX API Wrappers for Futura OS
 *
 * Copyright (c) 2025 Kelsi Davis
 * Licensed under the MPL v2.0 — see LICENSE for details.
 *
 * POSIX-compatible functions that communicate with posixd via FIPC.
 */

#include <stdint.h>
#include <stddef.h>
#include <errno.h>
#include <kernel/fut_fipc.h>
#include <user/futura_posix.h>
#include <user/libfutura.h>
#include <user/sys.h>
#include <stdlib.h>
#include "timerfd_internal.h"
#include "signalfd_internal.h"
#include "eventfd_internal.h"
#include "socket_unix.h"
#include "fd.h"
#include "memory_map.h"

extern int __fut_epoll_close(int fd);

/* Connection to posixd daemon */
static struct fut_fipc_channel *posixd_channel = NULL;

struct fut_dir {
    int64_t handle;
};

/**
 * Initialize POSIX subsystem (connect to posixd).
 */
int posix_init(void) {
    /* Phase 3: Connect to posixd via FIPC */
    if (!posixd_channel) {
        posixd_channel = fipc_connect("posixd");
    }
    return posixd_channel ? 0 : -1;
}

/**
 * Open a file.
 */
int open(const char *path, int flags, ...) {
    if (!posixd_channel || !path) {
        if (posix_init() < 0) {
            return -1;
        }
        if (!posixd_channel) {
            return -1;
        }
    }

    /* Build request */
    struct {
        struct posixd_open_req req;
    } msg;

    /* Copy path */
    size_t i;
    for (i = 0; i < POSIX_PATH_MAX - 1 && path[i]; i++) {
        msg.req.path[i] = path[i];
    }
    msg.req.path[i] = '\0';

    msg.req.flags = flags;
    msg.req.mode = 0644;  /* Default mode */

    /* Send request to posixd */
    int ret = fut_fipc_send(posixd_channel, POSIXD_MSG_OPEN,
                            &msg.req, sizeof(msg.req));
    if (ret < 0) {
        return -1;
    }

    /* Receive response */
    uint8_t resp_buffer[256];
    ssize_t recv_ret = fut_fipc_recv(posixd_channel, resp_buffer, sizeof(resp_buffer));
    if (recv_ret < 0) {
        return -1;
    }

    struct fut_fipc_msg *resp_msg = (struct fut_fipc_msg *)resp_buffer;
    struct posixd_open_resp *resp = (struct posixd_open_resp *)resp_msg->payload;

    return resp->fd;
}

/**
 * Close a file descriptor.
 */
int close(int fd) {
    if (__fut_epoll_close(fd) == 0) {
        fut_fd_release(fd);
        return 0;
    }

    if (__fut_timerfd_close(fd) == 0) {
        fut_fd_release(fd);
        return 0;
    }

    if (__fut_signalfd_close(fd) == 0) {
        fut_fd_release(fd);
        return 0;
    }

    if (__fut_eventfd_close(fd) == 0) {
        fut_fd_release(fd);
        return 0;
    }

    if (__fut_unix_socket_close(fd) == 0) {
        fut_fd_release(fd);
        return 0;
    }

    if (!posixd_channel && posix_init() < 0) {
        fut_fd_path_forget(fd);
        return (int)sys_close(fd);
    }

    if (!posixd_channel) {
        fut_fd_path_forget(fd);
        return (int)sys_close(fd);
    }

    struct posixd_close_req req = { .fd = fd };

    /* Send request */
    int ret = fut_fipc_send(posixd_channel, POSIXD_MSG_CLOSE,
                            &req, sizeof(req));

    /* Phase 3: Wait for response */
    fut_fd_path_forget(fd);
    return ret;
}

/**
 * Read from file descriptor.
 */
ssize_t read(int fd, void *buf, size_t count) {
    if (!buf) {
        return -1;
    }

    if (__fut_timerfd_is_timer(fd)) {
        return __fut_timerfd_read(fd, buf, count);
    }

    if (__fut_signalfd_is(fd)) {
        return __fut_signalfd_read(fd, buf, count);
    }

    if (__fut_eventfd_is(fd)) {
        return __fut_eventfd_read(fd, buf, count);
    }

    if (__fut_unix_socket_is(fd)) {
        ssize_t sock_ret = __fut_unix_socket_read(fd, buf, count);
        if (sock_ret >= 0) {
            return sock_ret;
        }
    }

    if (!posixd_channel && posix_init() < 0) {
        return -1;
    }

    /* Phase 3: Would use shared memory region for zero-copy:
     * 1. Create/reuse shared buffer
     * 2. Send read request with buffer region ID
     * 3. Wait for response
     * 4. Copy from shared buffer to user buffer
     */

    struct posixd_read_req req = {
        .fd = fd,
        .count = count,
        .buffer_region_id = 0,  /* Phase 3: shared buffer */
    };

    /* Send request */
    int ret = fut_fipc_send(posixd_channel, POSIXD_MSG_READ,
                            &req, sizeof(req));
    if (ret < 0) {
        return -1;
    }

    /* Receive response */
    uint8_t resp_buffer[4096];
    ssize_t recv_ret = fut_fipc_recv(posixd_channel, resp_buffer, sizeof(resp_buffer));
    if (recv_ret < 0) {
        return -1;
    }

    struct fut_fipc_msg *resp_msg = (struct fut_fipc_msg *)resp_buffer;
    struct posixd_read_resp *resp = (struct posixd_read_resp *)resp_msg->payload;

    /* Copy data */
    if (resp->bytes_read > 0 && (size_t)resp->bytes_read <= count) {
        for (ssize_t i = 0; i < resp->bytes_read; i++) {
            ((char *)buf)[i] = ((char *)(resp + 1))[i];
        }
    }

    return resp->bytes_read;
}

/**
 * Write to file descriptor.
 */
ssize_t write(int fd, const void *buf, size_t count) {
    if ((!posixd_channel && posix_init() < 0) || !buf) {
        return -1;
    }

    if (__fut_eventfd_is(fd)) {
        return __fut_eventfd_write(fd, buf, count);
    }

    if (__fut_unix_socket_is(fd)) {
        ssize_t sock_ret = __fut_unix_socket_write(fd, buf, count);
        if (sock_ret >= 0) {
            return sock_ret;
        }
    }

    /* Phase 3: Would use shared memory for zero-copy */

    struct {
        struct posixd_write_req req;
        uint8_t data[4096];
    } msg;

    msg.req.fd = fd;
    msg.req.count = count > 4096 ? 4096 : count;
    msg.req.buffer_region_id = 0;

    /* Copy data to message */
    for (size_t i = 0; i < msg.req.count; i++) {
        msg.data[i] = ((const uint8_t *)buf)[i];
    }

    /* Send request */
    int ret = fut_fipc_send(posixd_channel, POSIXD_MSG_WRITE,
                            &msg, sizeof(msg.req) + msg.req.count);
    if (ret < 0) {
        return -1;
    }

    /* Receive response */
    uint8_t resp_buffer[256];
    ssize_t recv_ret = fut_fipc_recv(posixd_channel, resp_buffer, sizeof(resp_buffer));
    if (recv_ret < 0) {
        return -1;
    }

    struct fut_fipc_msg *resp_msg = (struct fut_fipc_msg *)resp_buffer;
    struct posixd_write_resp *resp = (struct posixd_write_resp *)resp_msg->payload;

    return resp->bytes_written;
}

void *mmap(void *addr, size_t length, int prot, int flags, int fd, off_t offset) {
    long ret = sys_mmap(addr, (long)length, prot, flags, fd, offset);
    if (ret < 0) {
        errno = (int)-ret;
        return (void *)-1;
    }
    void *mapped = (void *)ret;
    const char *path_ptr = NULL;
    char path_buf[128];
    if (fd >= 0 && fut_fd_path_lookup(fd, path_buf, sizeof(path_buf)) == 0) {
        path_ptr = path_buf;
    }
    fut_maprec_insert(mapped, length, fd, offset, prot, flags, path_ptr);
    return mapped;
}

void *mmap64(void *addr, size_t length, int prot, int flags, int fd, off_t offset)
    __attribute__((weak, alias("mmap")));

int munmap(void *addr, size_t length) {
    long ret = sys_munmap_call(addr, (long)length);
    if (ret < 0) {
        errno = (int)-ret;
        return -1;
    }
    fut_maprec_remove(addr);
    return 0;
}

int flock(int fd, int operation) {
    return (int)sys_call2(SYS_flock, fd, operation);
}

int unlink(const char *path) {
    if ((!posixd_channel && posix_init() < 0) || !path) {
        return -1;
    }

    struct posixd_unlink_req req;
    size_t i;
    for (i = 0; i < POSIX_PATH_MAX - 1 && path[i]; i++) {
        req.path[i] = path[i];
    }
    req.path[i] = '\0';

    int ret = fut_fipc_send(posixd_channel, POSIXD_MSG_UNLINK, &req, sizeof(req));
    if (ret < 0) {
        return ret;
    }

    uint8_t resp_buffer[256];
    ssize_t recv_ret = fut_fipc_recv(posixd_channel, resp_buffer, sizeof(resp_buffer));
    if (recv_ret < 0) {
        return (int)recv_ret;
    }

    struct fut_fipc_msg *resp_msg = (struct fut_fipc_msg *)resp_buffer;
    struct posixd_unlink_resp *resp = (struct posixd_unlink_resp *)resp_msg->payload;
    return resp->result;
}

int mkdir(const char *path, mode_t mode) {
    if ((!posixd_channel && posix_init() < 0) || !path) {
        return -1;
    }

    struct posixd_mkdir_req req;
    size_t i;
    for (i = 0; i < POSIX_PATH_MAX - 1 && path[i]; i++) {
        req.path[i] = path[i];
    }
    req.path[i] = '\0';
    req.mode = mode;

    int ret = fut_fipc_send(posixd_channel, POSIXD_MSG_MKDIR, &req, sizeof(req));
    if (ret < 0) {
        return ret;
    }

    uint8_t resp_buffer[256];
    ssize_t recv_ret = fut_fipc_recv(posixd_channel, resp_buffer, sizeof(resp_buffer));
    if (recv_ret < 0) {
        return (int)recv_ret;
    }

    struct fut_fipc_msg *resp_msg = (struct fut_fipc_msg *)resp_buffer;
    struct posixd_mkdir_resp *resp = (struct posixd_mkdir_resp *)resp_msg->payload;
    return resp->result;
}

int rmdir(const char *path) {
    if ((!posixd_channel && posix_init() < 0) || !path) {
        return -1;
    }

    struct posixd_unlink_req req;
    size_t i;
    for (i = 0; i < POSIX_PATH_MAX - 1 && path[i]; i++) {
        req.path[i] = path[i];
    }
    req.path[i] = '\0';

    int ret = fut_fipc_send(posixd_channel, POSIXD_MSG_RMDIR, &req, sizeof(req));
    if (ret < 0) {
        return ret;
    }

    uint8_t resp_buffer[256];
    ssize_t recv_ret = fut_fipc_recv(posixd_channel, resp_buffer, sizeof(resp_buffer));
    if (recv_ret < 0) {
        return (int)recv_ret;
    }

    struct fut_fipc_msg *resp_msg = (struct fut_fipc_msg *)resp_buffer;
    struct posixd_unlink_resp *resp = (struct posixd_unlink_resp *)resp_msg->payload;
    return resp->result;
}

fut_dir_t *opendir(const char *path) {
    if ((!posixd_channel && posix_init() < 0) || !path) {
        return NULL;
    }

    struct posixd_opendir_req req;
    size_t i;
    for (i = 0; i < POSIX_PATH_MAX - 1 && path[i]; i++) {
        req.path[i] = path[i];
    }
    req.path[i] = '\0';

    int ret = fut_fipc_send(posixd_channel, POSIXD_MSG_OPENDIR, &req, sizeof(req));
    if (ret < 0) {
        return NULL;
    }

    uint8_t resp_buffer[256];
    ssize_t recv_ret = fut_fipc_recv(posixd_channel, resp_buffer, sizeof(resp_buffer));
    if (recv_ret < 0) {
        return NULL;
    }

    struct fut_fipc_msg *resp_msg = (struct fut_fipc_msg *)resp_buffer;
    struct posixd_opendir_resp *resp = (struct posixd_opendir_resp *)resp_msg->payload;
    if (resp->result < 0 || resp->dir_handle < 0) {
        return NULL;
    }

    fut_dir_t *dir = malloc(sizeof(*dir));
    if (!dir) {
        struct posixd_closedir_req creq = { .dir_handle = resp->dir_handle };
        fut_fipc_send(posixd_channel, POSIXD_MSG_CLOSEDIR, &creq, sizeof(creq));
        return NULL;
    }
    dir->handle = resp->dir_handle;
    return dir;
}

int closedir(fut_dir_t *dir) {
    if (!dir || (!posixd_channel && posix_init() < 0)) {
        return -1;
    }

    struct posixd_closedir_req req = { .dir_handle = dir->handle };
    int ret = fut_fipc_send(posixd_channel, POSIXD_MSG_CLOSEDIR, &req, sizeof(req));
    if (ret < 0) {
        return ret;
    }

    uint8_t resp_buffer[256];
    ssize_t recv_ret = fut_fipc_recv(posixd_channel, resp_buffer, sizeof(resp_buffer));
    if (recv_ret < 0) {
        return (int)recv_ret;
    }

    struct fut_fipc_msg *resp_msg = (struct fut_fipc_msg *)resp_buffer;
    struct posixd_closedir_resp *resp = (struct posixd_closedir_resp *)resp_msg->payload;
    free(dir);
    return resp->result;
}

int readdir(fut_dir_t *dir, struct fut_dirent *entry) {
    if (!dir || !entry || (!posixd_channel && posix_init() < 0)) {
        return -1;
    }

    struct posixd_readdir_req req = { .dir_handle = dir->handle };
    entry->d_name[0] = '\0';
    int ret = fut_fipc_send(posixd_channel, POSIXD_MSG_READDIR, &req, sizeof(req));
    if (ret < 0) {
        return ret;
    }

    uint8_t resp_buffer[sizeof(struct fut_fipc_msg) + sizeof(struct posixd_readdir_resp)] = {0};
    ssize_t recv_ret = fut_fipc_recv(posixd_channel, resp_buffer, sizeof(resp_buffer));
    if (recv_ret < 0) {
        return (int)recv_ret;
    }

    struct fut_fipc_msg *resp_msg = (struct fut_fipc_msg *)resp_buffer;
    struct posixd_readdir_resp *resp = (struct posixd_readdir_resp *)resp_msg->payload;
    if (resp->result < 0) {
        return resp->result;
    }

    if (!resp->has_entry) {
        return 0; /* End of directory */
    }

    entry->d_ino = resp->entry.d_ino;
    entry->d_off = resp->entry.d_off;
    entry->d_reclen = resp->entry.d_reclen;
    entry->d_type = resp->entry.d_type;

    size_t name_len = 0;
    while (name_len < POSIX_NAME_MAX && resp->entry.d_name[name_len]) {
        entry->d_name[name_len] = resp->entry.d_name[name_len];
        name_len++;
    }
    entry->d_name[name_len] = '\0';

    return 1;
}

/**
 * Fork process.
 */
int fork(void) {
    if (!posixd_channel) {
        return -1;
    }

    /* Send fork request */
    struct posixd_fork_req req;
    int ret = fut_fipc_send(posixd_channel, POSIXD_MSG_FORK,
                            &req, sizeof(req));
    if (ret < 0) {
        return -1;
    }

    /* Receive response */
    uint8_t resp_buffer[256];
    ssize_t recv_ret = fut_fipc_recv(posixd_channel, resp_buffer, sizeof(resp_buffer));
    if (recv_ret < 0) {
        return -1;
    }

    struct fut_fipc_msg *resp_msg = (struct fut_fipc_msg *)resp_buffer;
    struct posixd_fork_resp *resp = (struct posixd_fork_resp *)resp_msg->payload;

    return resp->pid;
}

/**
 * Execute program.
 */
int execve(const char *path, char *const argv[], char *const envp[]) {
    if (!posixd_channel || !path) {
        return -1;
    }

    /* Build exec request */
    struct {
        struct posixd_exec_req req;
    } msg;

    /* Copy path */
    size_t i;
    for (i = 0; i < POSIX_PATH_MAX - 1 && path[i]; i++) {
        msg.req.path[i] = path[i];
    }
    msg.req.path[i] = '\0';

    /* Phase 3: Properly serialize argv and envp */
    (void)argv;
    (void)envp;

    /* Send request */
    fut_fipc_send(posixd_channel, POSIXD_MSG_EXEC,
                  &msg.req, sizeof(msg.req));

    /* exec doesn't return on success */
    return -1;
}

/**
 * Wait for child process.
 */
int waitpid(int pid, int *status, int options) {
    if (!posixd_channel) {
        return -1;
    }

    struct posixd_wait_req req = {
        .pid = pid,
        .options = options,
    };

    /* Send request */
    int ret = fut_fipc_send(posixd_channel, POSIXD_MSG_WAIT,
                            &req, sizeof(req));
    if (ret < 0) {
        return -1;
    }

    /* Receive response */
    uint8_t resp_buffer[256];
    ssize_t recv_ret = fut_fipc_recv(posixd_channel, resp_buffer, sizeof(resp_buffer));
    if (recv_ret < 0) {
        return -1;
    }

    struct fut_fipc_msg *resp_msg = (struct fut_fipc_msg *)resp_buffer;
    struct posixd_wait_resp *resp = (struct posixd_wait_resp *)resp_msg->payload;

    if (status) {
        *status = resp->status;
    }

    return resp->pid;
}

/**
 * Get process ID.
 */
int getpid(void) {
    /* Phase 3: Would query posixd or use cached value */
    return 1;  /* Stub */
}

/**
 * Get parent process ID.
 */
int getppid(void) {
    /* Phase 3: Would query posixd */
    return 0;  /* Stub */
}
