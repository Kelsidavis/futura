/* main.c - Filesystem Daemon (fsd)
 *
 * Copyright (c) 2025 Kelsi Davis
 * Licensed under the MPL v2.0 — see LICENSE for details.
 *
 * User-space filesystem daemon - relays filesystem operations from clients
 * to the kernel via syscalls. Provides filesystem services via FIPC.
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

/* Global state */
static bool running = true;
static struct fut_fipc_channel *listen_channel = NULL;

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
     * In the future, fsd will:
     * - Create FIPC listen channel for filesystem service
     * - Register with service registry
     * - Load filesystem drivers
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
