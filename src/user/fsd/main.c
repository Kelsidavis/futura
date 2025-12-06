/* main.c - Filesystem Daemon (fsd)
 *
 * Copyright (c) 2025 Kelsi Davis
 * Licensed under the MPL v2.0 — see LICENSE for details.
 *
 * User-space filesystem daemon - relays filesystem operations from clients
 * to the kernel via syscalls. Provides filesystem services via FIPC.
 *
 * Features:
 * - Per-client file descriptor tracking and namespace isolation
 * - Client registration and lifecycle management
 * - FD mapping between client and kernel file descriptors
 * - Automatic resource cleanup on client disconnection
 */

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>
#include <string.h>
#include <errno.h>
#include <user/sys.h>

/* FIPC message header structure (matches kernel definition) */
struct fsd_fipc_msg {
    uint32_t type;
    uint32_t length;
    uint64_t timestamp;
    uint32_t src_pid;
    uint32_t dst_pid;
    uint64_t capability;
    uint8_t payload[];
};

/* FIPC channel flags (matches kernel definition) */
#define FSD_FIPC_BLOCKING     0x00000001
#define FSD_FIPC_NONBLOCKING  0x00000002

/* FIPC events */
#define FSD_FIPC_EVENT_MESSAGE 0x01

/* Message types for fsd */
#define FSD_MSG_REGISTER    0x4001
#define FSD_MSG_UNREGISTER  0x4002
#define FSD_MSG_OPEN        0x4003
#define FSD_MSG_CLOSE       0x4004
#define FSD_MSG_READ        0x4005
#define FSD_MSG_WRITE       0x4006
#define FSD_MSG_MKDIR       0x4007
#define FSD_MSG_RMDIR       0x4008
#define FSD_MSG_STAT        0x4009
#define FSD_MSG_LSEEK       0x400a
#define FSD_MSG_READDIR     0x400b
#define FSD_MSG_UNLINK      0x400c
#define FSD_MSG_FSYNC       0x400d
#define FSD_MSG_CHMOD       0x400e
#define FSD_MSG_CHOWN       0x400f

/* Well-known file for publishing FSD channel ID */
#define FSD_CHANNEL_FILE "/run/fsd.channel"

/* Per-client FD tracking structure
 * Maps client file descriptors to kernel file descriptors.
 * This allows the FSD to maintain separate FD namespaces for each client.
 */
#define FSD_MAX_CLIENTS 64
#define FSD_MAX_FDS_PER_CLIENT 256

struct fsd_client_fd {
    int kernel_fd;      /* FD from kernel syscall */
    int client_fd;      /* FD as seen by client */
    int flags;          /* Open flags (O_RDONLY, O_WRONLY, O_RDWR, etc.) */
    bool valid;         /* Whether this entry is in use */
};

struct fsd_client {
    uint64_t client_id;                         /* Unique client identifier (from FIPC) */
    struct fsd_client_fd fds[FSD_MAX_FDS_PER_CLIENT];  /* Per-client FD table */
    int next_fd;                                /* Next FD index to allocate */
    bool active;                                /* Whether this client is active */
};

/* Request structures */
struct fsd_open_req {
    char path[256];
    int flags;
    int mode;
};

struct fsd_close_req {
    int fd;
};

struct fsd_read_req {
    int fd;
    size_t count;
};

struct fsd_write_req {
    int fd;
    size_t count;
    /* data follows immediately after this struct in the message */
};

struct fsd_mkdir_req {
    char path[256];
    int mode;
};

struct fsd_rmdir_req {
    char path[256];
};

struct fsd_unlink_req {
    char path[256];
};

struct fsd_stat_req {
    char path[256];
};

struct fsd_lseek_req {
    int fd;
    int64_t offset;
    int whence;
};

struct fsd_fsync_req {
    int fd;
};

struct fsd_chmod_req {
    char path[256];
    int mode;
};

struct fsd_chown_req {
    char path[256];
    int uid;
    int gid;
};

/* Global state */
static bool running = true;
static long listen_channel_id = -1;
static struct fsd_client clients[FSD_MAX_CLIENTS] = {0};

/* Message buffer */
#define FSD_MSG_BUFFER_SIZE 8192
static uint8_t msg_buffer[FSD_MSG_BUFFER_SIZE];

/**
 * Simple printf-like output for daemon logging
 */
static void fsd_log(const char *msg) {
    size_t len = 0;
    while (msg[len]) len++;
    sys_write(2, msg, len);  /* Write to stderr */
}

static void fsd_log_num(const char *prefix, long num) {
    fsd_log(prefix);
    char buf[32];
    int i = 0;
    if (num < 0) {
        buf[i++] = '-';
        num = -num;
    }
    if (num == 0) {
        buf[i++] = '0';
    } else {
        char digits[20];
        int d = 0;
        while (num > 0) {
            digits[d++] = '0' + (num % 10);
            num /= 10;
        }
        while (d > 0) {
            buf[i++] = digits[--d];
        }
    }
    buf[i++] = '\n';
    sys_write(2, buf, i);
}

/**
 * Register a new client with the FSD.
 * Allocates a client slot and initializes the FD table.
 *
 * @return: Client index on success, -1 on failure
 */
static int fsd_client_register(uint64_t client_id) {
    for (int i = 0; i < FSD_MAX_CLIENTS; i++) {
        if (!clients[i].active) {
            clients[i].client_id = client_id;
            clients[i].active = true;
            clients[i].next_fd = 3;  /* Start after stdin, stdout, stderr */
            /* Clear FD table */
            for (int j = 0; j < FSD_MAX_FDS_PER_CLIENT; j++) {
                clients[i].fds[j].kernel_fd = -1;
                clients[i].fds[j].client_fd = -1;
                clients[i].fds[j].valid = false;
            }
            fsd_log_num("[FSD] Registered client at index ", i);
            return i;
        }
    }
    fsd_log("[FSD] Cannot register client: table full\n");
    return -1;
}

/**
 * Find a client by ID.
 *
 * @return: Client index on success, -1 if not found
 */
static int fsd_client_find(uint64_t client_id) {
    for (int i = 0; i < FSD_MAX_CLIENTS; i++) {
        if (clients[i].active && clients[i].client_id == client_id) {
            return i;
        }
    }
    return -1;
}

/**
 * Allocate a new FD for a client.
 * Maps a kernel FD to a client FD.
 *
 * @return: Client FD on success, -1 on failure
 */
static int fsd_client_fd_alloc(int client_idx, int kernel_fd, int flags) {
    if (client_idx < 0 || client_idx >= FSD_MAX_CLIENTS || !clients[client_idx].active) {
        return -1;
    }

    struct fsd_client *client = &clients[client_idx];

    /* Find next available FD slot */
    for (int i = client->next_fd; i < FSD_MAX_FDS_PER_CLIENT; i++) {
        if (!client->fds[i].valid) {
            client->fds[i].kernel_fd = kernel_fd;
            client->fds[i].client_fd = i;
            client->fds[i].flags = flags;
            client->fds[i].valid = true;

            if (i >= client->next_fd) {
                client->next_fd = i + 1;
            }

            return i;  /* Return the FD as seen by client */
        }
    }

    fsd_log("[FSD] Cannot allocate FD: table full\n");
    return -1;
}

/**
 * Get the kernel FD corresponding to a client FD.
 *
 * @return: Kernel FD on success, -1 if not found
 */
static int fsd_client_fd_get_kernel(int client_idx, int client_fd) {
    if (client_idx < 0 || client_idx >= FSD_MAX_CLIENTS) {
        return -1;
    }

    struct fsd_client *client = &clients[client_idx];

    if (client_fd < 0 || client_fd >= FSD_MAX_FDS_PER_CLIENT) {
        return -1;
    }

    if (!client->fds[client_fd].valid) {
        return -1;
    }

    return client->fds[client_fd].kernel_fd;
}

/**
 * Free a client FD and close the kernel FD.
 *
 * @return: 0 on success, -1 on failure
 */
static int fsd_client_fd_free(int client_idx, int client_fd) {
    if (client_idx < 0 || client_idx >= FSD_MAX_CLIENTS) {
        return -1;
    }

    struct fsd_client *client = &clients[client_idx];

    if (client_fd < 0 || client_fd >= FSD_MAX_FDS_PER_CLIENT) {
        return -1;
    }

    if (!client->fds[client_fd].valid) {
        return -1;
    }

    int kernel_fd = client->fds[client_fd].kernel_fd;
    client->fds[client_fd].valid = false;
    client->fds[client_fd].kernel_fd = -1;

    /* Close the kernel FD */
    if (kernel_fd >= 0) {
        sys_close(kernel_fd);
    }

    return 0;
}

/**
 * Unregister a client and clean up its resources.
 */
static void fsd_client_unregister(int client_idx) {
    if (client_idx < 0 || client_idx >= FSD_MAX_CLIENTS || !clients[client_idx].active) {
        return;
    }

    struct fsd_client *client = &clients[client_idx];

    /* Close all open FDs for this client */
    for (int i = 0; i < FSD_MAX_FDS_PER_CLIENT; i++) {
        if (client->fds[i].valid) {
            fsd_client_fd_free(client_idx, i);
        }
    }

    client->active = false;
    fsd_log_num("[FSD] Unregistered client at index ", client_idx);
}

/**
 * Send response back to client via FIPC syscall
 */
static void fsd_send_response(uint32_t type, const void *payload, size_t size) {
    if (listen_channel_id >= 0) {
        sys_fipc_send(listen_channel_id, type, payload, size);
    }
}

/**
 * Handle client registration request
 */
static void handle_register(struct fsd_fipc_msg *msg) {
    int32_t result = -EINVAL;

    if (msg) {
        int idx = fsd_client_register(msg->src_pid);
        if (idx >= 0) {
            result = idx;
        }
    }

    fsd_send_response(FSD_MSG_REGISTER, &result, sizeof(result));
}

/**
 * Handle client unregistration request
 */
static void handle_unregister(struct fsd_fipc_msg *msg) {
    int32_t result = -EINVAL;

    if (msg) {
        int idx = fsd_client_find(msg->src_pid);
        if (idx >= 0) {
            fsd_client_unregister(idx);
            result = 0;
        }
    }

    fsd_send_response(FSD_MSG_UNREGISTER, &result, sizeof(result));
}

/**
 * Handle file open request via syscall
 */
static void handle_open(struct fsd_fipc_msg *msg) {
    int32_t result = -EINVAL;

    if (!msg || msg->length < sizeof(struct fsd_open_req)) {
        fsd_send_response(FSD_MSG_OPEN, &result, sizeof(result));
        return;
    }

    const struct fsd_open_req *req = (const struct fsd_open_req *)msg->payload;
    if (!req->path[0]) {
        fsd_send_response(FSD_MSG_OPEN, &result, sizeof(result));
        return;
    }

    /* Find or register client */
    int client_idx = fsd_client_find(msg->src_pid);
    if (client_idx < 0) {
        client_idx = fsd_client_register(msg->src_pid);
    }

    if (client_idx < 0) {
        result = -ENOMEM;
        fsd_send_response(FSD_MSG_OPEN, &result, sizeof(result));
        return;
    }

    /* Use syscall to open file */
    long kernel_fd = sys_open(req->path, req->flags, req->mode);
    if (kernel_fd < 0) {
        result = (int32_t)kernel_fd;
        fsd_send_response(FSD_MSG_OPEN, &result, sizeof(result));
        return;
    }

    /* Allocate client FD */
    int client_fd = fsd_client_fd_alloc(client_idx, (int)kernel_fd, req->flags);
    if (client_fd < 0) {
        sys_close(kernel_fd);
        result = -ENOMEM;
        fsd_send_response(FSD_MSG_OPEN, &result, sizeof(result));
        return;
    }

    result = client_fd;
    fsd_send_response(FSD_MSG_OPEN, &result, sizeof(result));
}

/**
 * Handle file read request via syscall
 */
static void handle_read(struct fsd_fipc_msg *msg) {
    struct {
        int32_t bytes_read;
        uint8_t data[4000];
    } resp = { .bytes_read = -EINVAL };

    if (!msg || msg->length < sizeof(struct fsd_read_req)) {
        fsd_send_response(FSD_MSG_READ, &resp, sizeof(resp.bytes_read));
        return;
    }

    const struct fsd_read_req *req = (const struct fsd_read_req *)msg->payload;

    /* Find client and get kernel FD */
    int client_idx = fsd_client_find(msg->src_pid);
    if (client_idx < 0) {
        fsd_send_response(FSD_MSG_READ, &resp, sizeof(resp.bytes_read));
        return;
    }

    int kernel_fd = fsd_client_fd_get_kernel(client_idx, req->fd);
    if (kernel_fd < 0) {
        resp.bytes_read = -EBADF;
        fsd_send_response(FSD_MSG_READ, &resp, sizeof(resp.bytes_read));
        return;
    }

    /* Limit read size to response buffer capacity */
    size_t read_size = req->count;
    if (read_size > sizeof(resp.data)) {
        read_size = sizeof(resp.data);
    }

    /* Use syscall to read file */
    long bytes_read = sys_read(kernel_fd, resp.data, read_size);
    resp.bytes_read = (int32_t)bytes_read;

    /* Send response with data */
    size_t response_size = sizeof(resp.bytes_read);
    if (bytes_read > 0) {
        response_size += (size_t)bytes_read;
    }

    fsd_send_response(FSD_MSG_READ, &resp, response_size);
}

/**
 * Handle file write request via syscall
 */
static void handle_write(struct fsd_fipc_msg *msg) {
    int32_t result = -EINVAL;

    if (!msg || msg->length < sizeof(struct fsd_write_req)) {
        fsd_send_response(FSD_MSG_WRITE, &result, sizeof(result));
        return;
    }

    const struct fsd_write_req *req = (const struct fsd_write_req *)msg->payload;

    /* Find client and get kernel FD */
    int client_idx = fsd_client_find(msg->src_pid);
    if (client_idx < 0) {
        fsd_send_response(FSD_MSG_WRITE, &result, sizeof(result));
        return;
    }

    int kernel_fd = fsd_client_fd_get_kernel(client_idx, req->fd);
    if (kernel_fd < 0) {
        result = -EBADF;
        fsd_send_response(FSD_MSG_WRITE, &result, sizeof(result));
        return;
    }

    /* Extract write data from message payload (after request header) */
    const uint8_t *write_data = msg->payload + sizeof(struct fsd_write_req);

    /* Calculate available data size in message */
    size_t available_data = msg->length - sizeof(struct fsd_write_req);
    size_t write_size = (req->count < available_data) ? req->count : available_data;

    /* Use syscall to write file */
    long bytes_written = sys_write(kernel_fd, write_data, write_size);
    result = (int32_t)bytes_written;

    fsd_send_response(FSD_MSG_WRITE, &result, sizeof(result));
}

/**
 * Handle file close request via syscall
 */
static void handle_close(struct fsd_fipc_msg *msg) {
    int32_t result = -EINVAL;

    if (!msg || msg->length < sizeof(struct fsd_close_req)) {
        fsd_send_response(FSD_MSG_CLOSE, &result, sizeof(result));
        return;
    }

    const struct fsd_close_req *req = (const struct fsd_close_req *)msg->payload;

    /* Find client */
    int client_idx = fsd_client_find(msg->src_pid);
    if (client_idx < 0) {
        fsd_send_response(FSD_MSG_CLOSE, &result, sizeof(result));
        return;
    }

    /* Free the client FD (this also closes the kernel FD) */
    int ret = fsd_client_fd_free(client_idx, req->fd);
    result = (ret == 0) ? 0 : -EBADF;

    fsd_send_response(FSD_MSG_CLOSE, &result, sizeof(result));
}

/**
 * Handle mkdir request via syscall
 */
static void handle_mkdir(struct fsd_fipc_msg *msg) {
    int32_t result = -EINVAL;

    if (!msg || msg->length < sizeof(struct fsd_mkdir_req)) {
        fsd_send_response(FSD_MSG_MKDIR, &result, sizeof(result));
        return;
    }

    const struct fsd_mkdir_req *req = (const struct fsd_mkdir_req *)msg->payload;
    if (!req->path[0]) {
        fsd_send_response(FSD_MSG_MKDIR, &result, sizeof(result));
        return;
    }

    result = (int32_t)sys_mkdir_call(req->path, req->mode);
    fsd_send_response(FSD_MSG_MKDIR, &result, sizeof(result));
}

/**
 * Handle rmdir request via syscall
 */
static void handle_rmdir(struct fsd_fipc_msg *msg) {
    int32_t result = -EINVAL;

    if (!msg || msg->length < sizeof(struct fsd_rmdir_req)) {
        fsd_send_response(FSD_MSG_RMDIR, &result, sizeof(result));
        return;
    }

    const struct fsd_rmdir_req *req = (const struct fsd_rmdir_req *)msg->payload;
    if (!req->path[0]) {
        fsd_send_response(FSD_MSG_RMDIR, &result, sizeof(result));
        return;
    }

    result = (int32_t)sys_rmdir_call(req->path);
    fsd_send_response(FSD_MSG_RMDIR, &result, sizeof(result));
}

/**
 * Handle unlink request via syscall
 */
static void handle_unlink(struct fsd_fipc_msg *msg) {
    int32_t result = -EINVAL;

    if (!msg || msg->length < sizeof(struct fsd_unlink_req)) {
        fsd_send_response(FSD_MSG_UNLINK, &result, sizeof(result));
        return;
    }

    const struct fsd_unlink_req *req = (const struct fsd_unlink_req *)msg->payload;
    if (!req->path[0]) {
        fsd_send_response(FSD_MSG_UNLINK, &result, sizeof(result));
        return;
    }

    result = (int32_t)sys_unlink(req->path);
    fsd_send_response(FSD_MSG_UNLINK, &result, sizeof(result));
}

/**
 * Handle stat request via syscall
 */
static void handle_stat(struct fsd_fipc_msg *msg) {
    struct {
        int32_t result;
        uint8_t stat_buf[128];  /* Space for struct stat */
    } resp = { .result = -EINVAL };

    if (!msg || msg->length < sizeof(struct fsd_stat_req)) {
        fsd_send_response(FSD_MSG_STAT, &resp, sizeof(resp.result));
        return;
    }

    const struct fsd_stat_req *req = (const struct fsd_stat_req *)msg->payload;
    if (!req->path[0]) {
        fsd_send_response(FSD_MSG_STAT, &resp, sizeof(resp.result));
        return;
    }

    resp.result = (int32_t)sys_stat_call(req->path, resp.stat_buf);

    if (resp.result == 0) {
        fsd_send_response(FSD_MSG_STAT, &resp, sizeof(resp));
    } else {
        fsd_send_response(FSD_MSG_STAT, &resp, sizeof(resp.result));
    }
}

/**
 * Handle lseek request via syscall
 */
static void handle_lseek(struct fsd_fipc_msg *msg) {
    int64_t result = -EINVAL;

    if (!msg || msg->length < sizeof(struct fsd_lseek_req)) {
        fsd_send_response(FSD_MSG_LSEEK, &result, sizeof(result));
        return;
    }

    const struct fsd_lseek_req *req = (const struct fsd_lseek_req *)msg->payload;

    /* Find client and get kernel FD */
    int client_idx = fsd_client_find(msg->src_pid);
    if (client_idx < 0) {
        fsd_send_response(FSD_MSG_LSEEK, &result, sizeof(result));
        return;
    }

    int kernel_fd = fsd_client_fd_get_kernel(client_idx, req->fd);
    if (kernel_fd < 0) {
        result = -EBADF;
        fsd_send_response(FSD_MSG_LSEEK, &result, sizeof(result));
        return;
    }

    result = sys_lseek_call(kernel_fd, req->offset, req->whence);
    fsd_send_response(FSD_MSG_LSEEK, &result, sizeof(result));
}

/**
 * Handle fsync request via syscall
 */
static void handle_fsync(struct fsd_fipc_msg *msg) {
    int32_t result = -EINVAL;

    if (!msg || msg->length < sizeof(struct fsd_fsync_req)) {
        fsd_send_response(FSD_MSG_FSYNC, &result, sizeof(result));
        return;
    }

    const struct fsd_fsync_req *req = (const struct fsd_fsync_req *)msg->payload;

    /* Find client and get kernel FD */
    int client_idx = fsd_client_find(msg->src_pid);
    if (client_idx < 0) {
        fsd_send_response(FSD_MSG_FSYNC, &result, sizeof(result));
        return;
    }

    int kernel_fd = fsd_client_fd_get_kernel(client_idx, req->fd);
    if (kernel_fd < 0) {
        result = -EBADF;
        fsd_send_response(FSD_MSG_FSYNC, &result, sizeof(result));
        return;
    }

    result = (int32_t)sys_fsync_call(kernel_fd);
    fsd_send_response(FSD_MSG_FSYNC, &result, sizeof(result));
}

/**
 * Handle chmod request via syscall
 */
static void handle_chmod(struct fsd_fipc_msg *msg) {
    int32_t result = -EINVAL;

    if (!msg || msg->length < sizeof(struct fsd_chmod_req)) {
        fsd_send_response(FSD_MSG_CHMOD, &result, sizeof(result));
        return;
    }

    const struct fsd_chmod_req *req = (const struct fsd_chmod_req *)msg->payload;
    if (!req->path[0]) {
        fsd_send_response(FSD_MSG_CHMOD, &result, sizeof(result));
        return;
    }

    result = (int32_t)sys_chmod_call(req->path, req->mode);
    fsd_send_response(FSD_MSG_CHMOD, &result, sizeof(result));
}

/**
 * Handle chown request via syscall
 */
static void handle_chown(struct fsd_fipc_msg *msg) {
    int32_t result = -EINVAL;

    if (!msg || msg->length < sizeof(struct fsd_chown_req)) {
        fsd_send_response(FSD_MSG_CHOWN, &result, sizeof(result));
        return;
    }

    const struct fsd_chown_req *req = (const struct fsd_chown_req *)msg->payload;
    if (!req->path[0]) {
        fsd_send_response(FSD_MSG_CHOWN, &result, sizeof(result));
        return;
    }

    result = (int32_t)sys_chown_call(req->path, req->uid, req->gid);
    fsd_send_response(FSD_MSG_CHOWN, &result, sizeof(result));
}

/**
 * Main event loop - receive and dispatch FIPC messages
 */
static void fsd_main_loop(void) {
    fsd_log("[FSD] Entering main event loop\n");

    while (running) {
        if (listen_channel_id < 0) {
            fsd_log("[FSD] No listen channel, exiting\n");
            break;
        }

        /* Receive message via FIPC syscall */
        long received = sys_fipc_recv(listen_channel_id, msg_buffer, FSD_MSG_BUFFER_SIZE);

        if (received > 0) {
            struct fsd_fipc_msg *msg = (struct fsd_fipc_msg *)msg_buffer;

            /* Route to appropriate handler */
            switch (msg->type) {
            case FSD_MSG_REGISTER:
                handle_register(msg);
                break;
            case FSD_MSG_UNREGISTER:
                handle_unregister(msg);
                break;
            case FSD_MSG_OPEN:
                handle_open(msg);
                break;
            case FSD_MSG_CLOSE:
                handle_close(msg);
                break;
            case FSD_MSG_READ:
                handle_read(msg);
                break;
            case FSD_MSG_WRITE:
                handle_write(msg);
                break;
            case FSD_MSG_MKDIR:
                handle_mkdir(msg);
                break;
            case FSD_MSG_RMDIR:
                handle_rmdir(msg);
                break;
            case FSD_MSG_UNLINK:
                handle_unlink(msg);
                break;
            case FSD_MSG_STAT:
                handle_stat(msg);
                break;
            case FSD_MSG_LSEEK:
                handle_lseek(msg);
                break;
            case FSD_MSG_FSYNC:
                handle_fsync(msg);
                break;
            case FSD_MSG_CHMOD:
                handle_chmod(msg);
                break;
            case FSD_MSG_CHOWN:
                handle_chown(msg);
                break;
            default:
                fsd_log_num("[FSD] Unknown message type: ", msg->type);
                break;
            }
        } else if (received == -EAGAIN) {
            /* Non-blocking mode, no message available */
            /* Could yield here or do other work */
            sys_sched_yield();
        } else if (received < 0) {
            /* Error */
            fsd_log_num("[FSD] recv error: ", received);
        }
    }
}

/**
 * Publish channel ID to well-known file
 */
static int fsd_publish_channel(long channel_id) {
    /* Create /run directory if it doesn't exist */
    sys_mkdir_call("/run", 0755);

    /* Write channel ID to file */
    long fd = sys_open(FSD_CHANNEL_FILE, 0x0241 /* O_CREAT | O_TRUNC | O_WRONLY */, 0644);
    if (fd < 0) {
        fsd_log("[FSD] Failed to create channel file\n");
        return -1;
    }

    /* Convert channel ID to string */
    char buf[32];
    int i = 0;
    long num = channel_id;
    if (num == 0) {
        buf[i++] = '0';
    } else {
        char digits[20];
        int d = 0;
        while (num > 0) {
            digits[d++] = '0' + (num % 10);
            num /= 10;
        }
        while (d > 0) {
            buf[i++] = digits[--d];
        }
    }
    buf[i++] = '\n';

    sys_write(fd, buf, i);
    sys_close(fd);

    fsd_log_num("[FSD] Published channel ID: ", channel_id);
    return 0;
}

/**
 * Initialization - create FIPC channel and publish it
 */
static int fsd_init(void) {
    fsd_log("[FSD] Filesystem daemon starting...\n");

    /* Create FIPC channel for listening to requests */
    listen_channel_id = sys_fipc_create(FSD_FIPC_BLOCKING, 16384);
    if (listen_channel_id < 0) {
        fsd_log("[FSD] Failed to create FIPC channel\n");
        return -1;
    }

    fsd_log_num("[FSD] Created FIPC channel: ", listen_channel_id);

    /* Publish channel ID so clients can connect */
    if (fsd_publish_channel(listen_channel_id) < 0) {
        fsd_log("[FSD] Failed to publish channel\n");
        sys_fipc_close(listen_channel_id);
        listen_channel_id = -1;
        return -1;
    }

    fsd_log("[FSD] Initialization complete\n");
    return 0;
}

/**
 * Shutdown - cleanup resources
 */
static void fsd_shutdown(void) {
    fsd_log("[FSD] Shutting down...\n");

    /* Unregister all clients */
    for (int i = 0; i < FSD_MAX_CLIENTS; i++) {
        if (clients[i].active) {
            fsd_client_unregister(i);
        }
    }

    /* Close FIPC channel */
    if (listen_channel_id >= 0) {
        sys_fipc_close(listen_channel_id);
        listen_channel_id = -1;
    }

    /* Remove channel file */
    sys_unlink(FSD_CHANNEL_FILE);

    running = false;
    fsd_log("[FSD] Shutdown complete\n");
}

/**
 * Entry point
 */
int main(int argc, char *argv[]) {
    (void)argc;
    (void)argv;

    if (fsd_init() < 0) {
        return 1;
    }

    fsd_main_loop();
    fsd_shutdown();

    return 0;
}
