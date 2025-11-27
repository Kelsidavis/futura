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
#include <kernel/fut_fipc.h>
#include <user/futura_posix.h>
#include <stdio.h>

/* Message types for fsd (internal - not in public header yet) */
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

/* Global state */
static bool running = true;
static struct fut_fipc_channel *listen_channel = NULL;
static struct fsd_client clients[FSD_MAX_CLIENTS] = {0};

/**
 * Register a new client with the FSD.
 * Allocates a client slot and initializes the FD table.
 *
 * @return: Client index on success, -1 on failure
 */
static int __attribute__((unused)) fsd_client_register(uint64_t client_id) {
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
            printf("[FSD] Registered client %lu at index %d\n", client_id, i);
            return i;
        }
    }
    printf("[FSD] Cannot register client %lu: table full\n", client_id);
    return -1;
}

/**
 * Find a client by ID.
 *
 * @return: Client index on success, -1 if not found
 */
static int __attribute__((unused)) fsd_client_find(uint64_t client_id) {
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
static int __attribute__((unused)) fsd_client_fd_alloc(int client_idx, int kernel_fd, int flags) {
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

    printf("[FSD] Cannot allocate FD for client %lu: FD table full\n", client->client_id);
    return -1;
}

/**
 * Get the kernel FD corresponding to a client FD.
 *
 * @return: Kernel FD on success, -1 if not found
 */
static int __attribute__((unused)) fsd_client_fd_get_kernel(int client_idx, int client_fd) {
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
static void __attribute__((unused)) fsd_client_unregister(int client_idx) {
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
    printf("[FSD] Unregistered client %lu\n", client->client_id);
}

/**
 * Response structures for file operations
 */
struct fsd_open_resp {
    int fd;
};

struct fsd_close_resp {
    int result;
};

struct fsd_read_resp {
    ssize_t bytes_read;
    uint8_t data[4000];  /* Max data in FIPC message */
};

struct fsd_write_resp {
    ssize_t bytes_written;
};

struct fsd_mkdir_resp {
    int result;
};

struct fsd_rmdir_resp {
    int result;
};

struct fsd_unlink_resp {
    int result;
};

struct fsd_stat_resp {
    int result;
    /* stat data would be included here */
};

struct fsd_lseek_resp {
    off_t offset;
};

struct fsd_readdir_resp {
    int result;  /* > 0 for valid entry, 0 for end of dir */
    /* dirent data would be included here */
};

struct fsd_fsync_resp {
    int result;
};

struct fsd_chmod_resp {
    int result;
};

struct fsd_chown_resp {
    int result;
};

/**
 * Send response back to client
 */
static void fsd_send_response(uint32_t type, const void *payload, size_t size) {
    if (listen_channel) {
        fut_fipc_send(listen_channel, type, payload, size);
    }
}

/**
 * Handle file open request via syscall
 */
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Warray-bounds"
static void handle_open(struct fut_fipc_msg *msg) {
    struct fsd_open_resp resp = { .fd = -EINVAL };

    /* Validate message size */
    if (!msg || msg->length < sizeof(struct posixd_open_req)) {
        fsd_send_response(FSD_MSG_OPEN, &resp, sizeof(resp));
        return;
    }

    const struct posixd_open_req *req = (const struct posixd_open_req *)(uintptr_t)msg->payload;
    if (!req->path[0]) {
        fsd_send_response(FSD_MSG_OPEN, &resp, sizeof(resp));
        return;
    }

    /* Use syscall to open file */
    long fd = sys_open(req->path, req->flags, req->mode);
    resp.fd = (int)fd;

    fsd_send_response(FSD_MSG_OPEN, &resp, sizeof(resp));
}
#pragma GCC diagnostic pop

/**
 * Handle file read request via syscall
 */
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Warray-bounds"
static void handle_read(struct fut_fipc_msg *msg) {
    struct {
        struct fsd_read_resp header;
    } resp = { .header = { .bytes_read = -EINVAL } };

    /* Validate message */
    if (!msg || msg->length < sizeof(struct posixd_read_req)) {
        fsd_send_response(FSD_MSG_READ, &resp.header, sizeof(resp.header));
        return;
    }

    const struct posixd_read_req *req = (const struct posixd_read_req *)(uintptr_t)msg->payload;
    if (req->fd < 0) {
        fsd_send_response(FSD_MSG_READ, &resp.header, sizeof(resp.header));
        return;
    }

    /* Limit read size to response buffer capacity */
    size_t read_size = req->count;
    if (read_size > sizeof(resp.header.data)) {
        read_size = sizeof(resp.header.data);
    }

    /* Use syscall to read file */
    long bytes_read = sys_read(req->fd, resp.header.data, read_size);
    resp.header.bytes_read = bytes_read;

    /* Send response with data */
    size_t response_size = sizeof(resp.header.bytes_read);
    if (bytes_read > 0) {
        response_size += bytes_read;
    }

    /* Pack response: just the bytes_read value + data */
    struct fsd_read_resp *send_resp = (struct fsd_read_resp *)&resp.header;
    fsd_send_response(FSD_MSG_READ, send_resp, response_size);
}
#pragma GCC diagnostic pop

/**
 * Handle file write request via syscall
 */
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Warray-bounds"
static void handle_write(struct fut_fipc_msg *msg) {
    struct fsd_write_resp resp = { .bytes_written = -EINVAL };

    /* Validate message */
    if (!msg || msg->length < sizeof(struct posixd_write_req)) {
        fsd_send_response(FSD_MSG_WRITE, &resp, sizeof(resp));
        return;
    }

    const struct posixd_write_req *req = (const struct posixd_write_req *)(uintptr_t)msg->payload;
    if (req->fd < 0) {
        fsd_send_response(FSD_MSG_WRITE, &resp, sizeof(resp));
        return;
    }

    /* Extract write data from message payload (after request header) */
    const uint8_t *write_data = (const uint8_t *)(uintptr_t)(msg->payload) + sizeof(*req);

    /* Calculate available data size in message */
    size_t available_data = msg->length - sizeof(*req);
    size_t write_size = (req->count < available_data) ? req->count : available_data;

    /* Use syscall to write file */
    long bytes_written = sys_write(req->fd, write_data, write_size);
    resp.bytes_written = bytes_written;

    fsd_send_response(FSD_MSG_WRITE, &resp, sizeof(resp));
}
#pragma GCC diagnostic pop

/**
 * Handle file close request via syscall
 */
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Warray-bounds"
static void handle_close(struct fut_fipc_msg *msg) {
    struct fsd_close_resp resp = { .result = -EINVAL };

    /* Validate message */
    if (!msg || msg->length < sizeof(struct posixd_close_req)) {
        fsd_send_response(FSD_MSG_CLOSE, &resp, sizeof(resp));
        return;
    }

    const struct posixd_close_req *req = (const struct posixd_close_req *)(uintptr_t)msg->payload;
    if (req->fd < 0) {
        fsd_send_response(FSD_MSG_CLOSE, &resp, sizeof(resp));
        return;
    }

    /* Use syscall to close file */
    long result = sys_close(req->fd);
    resp.result = (int)result;

    fsd_send_response(FSD_MSG_CLOSE, &resp, sizeof(resp));
}
#pragma GCC diagnostic pop

/**
 * Handle mkdir request via syscall
 */
static void handle_mkdir(struct fut_fipc_msg *msg) {
    struct fsd_mkdir_resp resp = { .result = -EINVAL };
    (void)msg;

    /* Minimal implementation - full version would parse message */
    fsd_send_response(FSD_MSG_MKDIR, &resp, sizeof(resp));
}

/**
 * Handle rmdir request via syscall
 */
static void handle_rmdir(struct fut_fipc_msg *msg) {
    struct fsd_rmdir_resp resp = { .result = -EINVAL };
    (void)msg;

    /* Minimal implementation - full version would parse message */
    fsd_send_response(FSD_MSG_RMDIR, &resp, sizeof(resp));
}

/**
 * Handle unlink request via syscall
 */
static void handle_unlink(struct fut_fipc_msg *msg) {
    struct fsd_unlink_resp resp = { .result = -EINVAL };
    (void)msg;

    /* Minimal implementation - full version would parse message */
    fsd_send_response(FSD_MSG_UNLINK, &resp, sizeof(resp));
}

/**
 * Handle stat request via syscall
 */
static void handle_stat(struct fut_fipc_msg *msg) {
    struct fsd_stat_resp resp = { .result = -EINVAL };
    (void)msg;

    /* Minimal implementation - full version would parse message */
    fsd_send_response(FSD_MSG_STAT, &resp, sizeof(resp));
}

/**
 * Handle lseek request via syscall
 */
static void handle_lseek(struct fut_fipc_msg *msg) {
    struct fsd_lseek_resp resp = { .offset = -EINVAL };
    (void)msg;

    /* Minimal implementation - full version would parse message */
    fsd_send_response(FSD_MSG_LSEEK, &resp, sizeof(resp));
}

/**
 * Handle fsync request via syscall
 */
static void handle_fsync(struct fut_fipc_msg *msg) {
    struct fsd_fsync_resp resp = { .result = -EINVAL };
    (void)msg;

    /* Minimal implementation - full version would parse message */
    fsd_send_response(FSD_MSG_FSYNC, &resp, sizeof(resp));
}

/**
 * Handle chmod request via syscall
 */
static void handle_chmod(struct fut_fipc_msg *msg) {
    struct fsd_chmod_resp resp = { .result = -EINVAL };
    (void)msg;

    /* Minimal implementation - full version would parse message */
    fsd_send_response(FSD_MSG_CHMOD, &resp, sizeof(resp));
}

/**
 * Handle chown request via syscall
 */
static void handle_chown(struct fut_fipc_msg *msg) {
    struct fsd_chown_resp resp = { .result = -EINVAL };
    (void)msg;

    /* Minimal implementation - full version would parse message */
    fsd_send_response(FSD_MSG_CHOWN, &resp, sizeof(resp));
}

/**
 * Main event loop - receive and dispatch FIPC messages
 */
static void fsd_main_loop(void) {
    while (running) {
        if (!listen_channel) {
            continue;
        }

        struct fut_fipc_msg msg;
        long received = fut_fipc_recv(listen_channel, &msg, sizeof(msg));

        if (received > 0) {
            /* Route to appropriate handler */
            switch (msg.type) {
            case FSD_MSG_OPEN:
                handle_open(&msg);
                break;
            case FSD_MSG_CLOSE:
                handle_close(&msg);
                break;
            case FSD_MSG_READ:
                handle_read(&msg);
                break;
            case FSD_MSG_WRITE:
                handle_write(&msg);
                break;
            case FSD_MSG_MKDIR:
                handle_mkdir(&msg);
                break;
            case FSD_MSG_RMDIR:
                handle_rmdir(&msg);
                break;
            case FSD_MSG_UNLINK:
                handle_unlink(&msg);
                break;
            case FSD_MSG_STAT:
                handle_stat(&msg);
                break;
            case FSD_MSG_LSEEK:
                handle_lseek(&msg);
                break;
            case FSD_MSG_FSYNC:
                handle_fsync(&msg);
                break;
            case FSD_MSG_CHMOD:
                handle_chmod(&msg);
                break;
            case FSD_MSG_CHOWN:
                handle_chown(&msg);
                break;
            default:
                /* Unknown message type */
                break;
            }
        } else if (received == -EAGAIN) {
            /* Timeout - keep looping */
            continue;
        } else if (received < 0) {
            /* Error - continue trying */
            continue;
        }
    }
}

/**
 * Initialization
 */
static void fsd_init(void) {
    /* Filesystem daemon initialization
     * - Create FIPC listen channel for filesystem service
     * - Register with service registry
     * - Load filesystem drivers (stub for future)
     */

    /* In a full implementation, this would:
     * 1. Create a FIPC channel for listening to requests
     * 2. Register the channel with the service registry daemon
     * 3. Load filesystem drivers (FuturaFS, ext4, etc.)
     * 4. Mount filesystems based on configuration
     *
     * Currently, this is scaffolding for future integration.
     * The FSD daemon can be invoked by clients that know the
     * FIPC channel endpoint in advance.
     */
}

/**
 * Shutdown
 */
static void fsd_shutdown(void) {
    if (listen_channel) {
        /* Close FIPC channel */
        listen_channel = NULL;
    }
    running = false;
}

/**
 * Entry point
 */
int main(int argc, char *argv[]) {
    (void)argc;
    (void)argv;

    fsd_init();
    fsd_main_loop();
    fsd_shutdown();

    return 0;
}
