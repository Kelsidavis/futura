/* posix.c - POSIX API Wrappers for Futura OS
 *
 * Copyright (c) 2025 Kelsi Davis
 * Licensed under the MPL v2.0 — see LICENSE for details.
 *
 * POSIX-compatible functions that communicate with posixd via FIPC.
 */

#include <stdint.h>
#include <stddef.h>
#include <kernel/fut_fipc.h>
#include <user/futura_posix.h>
#include <user/libfutura.h>

/* Connection to posixd daemon */
static struct fut_fipc_channel *posixd_channel = NULL;

/* Temporary directory handle placeholder */
struct fut_dir {
    int64_t handle;
};

/**
 * Initialize POSIX subsystem (connect to posixd).
 */
int posix_init(void) {
    /* Phase 3: Connect to posixd via FIPC */
    /* posixd_channel = fipc_connect("posixd"); */
    return posixd_channel ? 0 : -1;
}

/**
 * Open a file.
 */
int open(const char *path, int flags, ...) {
    if (!posixd_channel || !path) {
        return -1;
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
    if (!posixd_channel) {
        return -1;
    }

    struct posixd_close_req req = { .fd = fd };

    /* Send request */
    int ret = fut_fipc_send(posixd_channel, POSIXD_MSG_CLOSE,
                            &req, sizeof(req));

    /* Phase 3: Wait for response */
    return ret;
}

/**
 * Read from file descriptor.
 */
ssize_t read(int fd, void *buf, size_t count) {
    if (!posixd_channel || !buf) {
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
    if (!posixd_channel || !buf) {
        return -1;
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

int unlink(const char *path) {
    (void)path;
    return -1;
}

int mkdir(const char *path, mode_t mode) {
    (void)path;
    (void)mode;
    return -1;
}

int rmdir(const char *path) {
    (void)path;
    return -1;
}

fut_dir_t *opendir(const char *path) {
    (void)path;
    return NULL;
}

int closedir(fut_dir_t *dir) {
    (void)dir;
    return -1;
}

int readdir(fut_dir_t *dir, struct fut_dirent *entry) {
    (void)dir;
    (void)entry;
    return -1;
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
