/* main.c - POSIX Runtime Daemon (posixd)
 *
 * Copyright (c) 2025 Kelsi Davis
 * Licensed under the MPL v2.0 — see LICENSE for details.
 *
 * POSIX syscall bridge daemon - translates POSIX operations to FIPC messages.
 * Provides POSIX compatibility layer for applications.
 */

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>
#include <kernel/fut_fipc.h>
#include <kernel/fut_vfs.h>
#include <user/futura_posix.h>

/* Global state */
static bool running = true;
static struct fut_fipc_channel *listen_channel = NULL;

struct posixd_dir_handle {
    bool in_use;
    int64_t handle;
    char path[POSIX_PATH_MAX];
    uint64_t cookie;
};

#define POSIXD_MAX_DIR_HANDLES 64
static struct posixd_dir_handle dir_table[POSIXD_MAX_DIR_HANDLES];
static int64_t next_dir_handle = 1;

#define POSIXD_S_IFDIR 0040000

static void str_copy(char *dest, const char *src, size_t max_len) {
    size_t i = 0;
    if (!dest || !src || max_len == 0) {
        return;
    }
    while (i + 1 < max_len && src[i]) {
        dest[i] = src[i];
        i++;
    }
    dest[i] = '\0';
}

static struct posixd_dir_handle *dir_alloc(const char *path) {
    for (int i = 0; i < POSIXD_MAX_DIR_HANDLES; i++) {
        if (!dir_table[i].in_use) {
            dir_table[i].in_use = true;
            dir_table[i].handle = next_dir_handle++;
            dir_table[i].cookie = 0;
            str_copy(dir_table[i].path, path, sizeof(dir_table[i].path));
            return &dir_table[i];
        }
    }
    return NULL;
}

static struct posixd_dir_handle *dir_find(int64_t handle) {
    for (int i = 0; i < POSIXD_MAX_DIR_HANDLES; i++) {
        if (dir_table[i].in_use && dir_table[i].handle == handle) {
            return &dir_table[i];
        }
    }
    return NULL;
}

static void dir_release(struct posixd_dir_handle *dir) {
    if (dir) {
        dir->in_use = false;
        dir->handle = 0;
        dir->path[0] = '\0';
        dir->cookie = 0;
    }
}

static int ensure_directory(const char *path) {
    struct fut_stat st;
    int ret = fut_vfs_stat(path, &st);
    if (ret < 0) {
        return ret;
    }
    return (st.st_mode & POSIXD_S_IFDIR) ? 0 : -ENOTDIR;
}

static void send_response(uint32_t type, const void *payload, size_t size) {
    if (listen_channel) {
        fut_fipc_send(listen_channel, type, payload, size);
    }
}

/**
 * Handle file operation requests.
 */
static void handle_file_request(struct fut_fipc_msg *msg) {
    if (!msg) return;

    switch (msg->type) {
    case POSIXD_MSG_OPEN: {
        /* Open a file */
        struct posixd_open_req *req = (struct posixd_open_req *)msg->payload;
        struct posixd_open_resp resp = {0};

        if (!req || !req->path[0]) {
            resp.fd = -EINVAL;
        } else {
            /* Call VFS to open the file */
            int fd = fut_vfs_open(req->path, req->flags, req->mode);
            resp.fd = fd;
        }

        send_response(POSIXD_MSG_OPEN, &resp, sizeof(resp));
        break;
    }

    case POSIXD_MSG_CLOSE: {
        /* Close a file descriptor */
        struct posixd_close_req *req = (struct posixd_close_req *)msg->payload;
        struct posixd_close_resp resp = {0};

        if (!req) {
            resp.result = -EINVAL;
        } else {
            /* Call VFS to close the file */
            resp.result = fut_vfs_close(req->fd);
        }

        send_response(POSIXD_MSG_CLOSE, &resp, sizeof(resp));
        break;
    }

    case POSIXD_MSG_READ: {
        /* Read from file descriptor */
        struct posixd_read_req *req = (struct posixd_read_req *)msg->payload;
        struct posixd_read_resp resp = {0};

        if (!req || req->count == 0) {
            resp.bytes_read = -EINVAL;
        } else {
            /* Allocate temporary buffer for read data */
            uint8_t buf[4096];
            size_t count = (req->count > sizeof(buf)) ? sizeof(buf) : req->count;

            /* Call VFS to read the file */
            ssize_t bytes = fut_vfs_read(req->fd, buf, count);

            if (bytes < 0) {
                resp.bytes_read = bytes;
            } else {
                /* TODO: Copy data to shared buffer region (req->buffer_region_id)
                 * For now, data is passed directly in the response if it fits
                 */
                resp.bytes_read = bytes;
            }
        }

        send_response(POSIXD_MSG_READ, &resp, sizeof(resp));
        break;
    }

    case POSIXD_MSG_WRITE: {
        /* Write to file descriptor */
        struct posixd_write_req *req = (struct posixd_write_req *)msg->payload;
        struct posixd_write_resp resp = {0};

        if (!req || req->count == 0) {
            resp.bytes_written = -EINVAL;
        } else {
            /* Data is passed inline after the request structure in the message payload.
             * The client (libfutura) copies data directly to the message buffer.
             * Phase 3: Use shared buffer region (req->buffer_region_id) for large writes.
             */

            /* Calculate where the data starts in the payload:
             * Message payload = [posixd_write_req] [data bytes...]
             * So data starts at offset sizeof(struct posixd_write_req)
             */
            size_t data_offset = sizeof(struct posixd_write_req);
            uint8_t *data = (uint8_t *)msg->payload + data_offset;

            /* Call VFS to write the file */
            ssize_t bytes = fut_vfs_write(req->fd, data, req->count);
            resp.bytes_written = bytes;
        }

        send_response(POSIXD_MSG_WRITE, &resp, sizeof(resp));
        break;
    }

    default:
        /* Unknown file operation */
        break;
    }
}

/**
 * Handle directory operation requests.
 */
static void handle_directory_request(struct fut_fipc_msg *msg) {
    if (!msg) {
        return;
    }

    switch (msg->type) {
    case POSIXD_MSG_OPENDIR: {
        const struct posixd_opendir_req *req = (const struct posixd_opendir_req *)msg->payload;
        struct posixd_opendir_resp resp = { .result = 0, .dir_handle = -1 };

        if (!req || req->path[0] == '\0') {
            resp.result = -EINVAL;
            send_response(POSIXD_MSG_OPENDIR, &resp, sizeof(resp));
            break;
        }

        int ret = ensure_directory(req->path);
        if (ret < 0) {
            resp.result = ret;
            send_response(POSIXD_MSG_OPENDIR, &resp, sizeof(resp));
            break;
        }

        struct posixd_dir_handle *dir = dir_alloc(req->path);
        if (!dir) {
            resp.result = -ENFILE;
        } else {
            resp.dir_handle = dir->handle;
        }

        send_response(POSIXD_MSG_OPENDIR, &resp, sizeof(resp));
        break;
    }

    case POSIXD_MSG_READDIR: {
        const struct posixd_readdir_req *req = (const struct posixd_readdir_req *)msg->payload;
        struct posixd_readdir_resp resp = {
            .result = 0,
            .has_entry = false,
        };

        if (!req) {
            resp.result = -EINVAL;
            send_response(POSIXD_MSG_READDIR, &resp, sizeof(resp));
            break;
        }

        struct posixd_dir_handle *dir = dir_find(req->dir_handle);
        if (!dir) {
            resp.result = -ENOENT;
            send_response(POSIXD_MSG_READDIR, &resp, sizeof(resp));
            break;
        }

        uint64_t cookie = dir->cookie;
        struct fut_vdirent dent;
        int ret = fut_vfs_readdir(dir->path, &cookie, &dent);

        if (ret == -ENOENT) {
            dir->cookie = cookie;
            resp.has_entry = false;
            send_response(POSIXD_MSG_READDIR, &resp, sizeof(resp));
            break;
        }

        if (ret < 0) {
            dir->cookie = cookie;
            resp.result = ret;
            send_response(POSIXD_MSG_READDIR, &resp, sizeof(resp));
            break;
        }

        dir->cookie = cookie;
        resp.has_entry = true;
        resp.entry.d_ino = dent.d_ino;
        resp.entry.d_off = dent.d_off;
        resp.entry.d_reclen = dent.d_reclen;
        resp.entry.d_type = dent.d_type;
        str_copy(resp.entry.d_name, dent.d_name, sizeof(resp.entry.d_name));

        send_response(POSIXD_MSG_READDIR, &resp, sizeof(resp));
        break;
    }

    case POSIXD_MSG_CLOSEDIR: {
        const struct posixd_closedir_req *req = (const struct posixd_closedir_req *)msg->payload;
        struct posixd_closedir_resp resp = { .result = 0 };

        if (!req) {
            resp.result = -EINVAL;
        } else {
            struct posixd_dir_handle *dir = dir_find(req->dir_handle);
            if (!dir) {
                resp.result = -ENOENT;
            } else {
                dir_release(dir);
            }
        }

        send_response(POSIXD_MSG_CLOSEDIR, &resp, sizeof(resp));
        break;
    }

    case POSIXD_MSG_MKDIR: {
        const struct posixd_mkdir_req *req = (const struct posixd_mkdir_req *)msg->payload;
        struct posixd_mkdir_resp resp = { .result = 0 };

        if (!req) {
            resp.result = -EINVAL;
        } else {
            resp.result = fut_vfs_mkdir(req->path, req->mode);
        }

        send_response(POSIXD_MSG_MKDIR, &resp, sizeof(resp));
        break;
    }

    case POSIXD_MSG_RMDIR: {
        const struct posixd_unlink_req *req = (const struct posixd_unlink_req *)msg->payload;
        struct posixd_unlink_resp resp = { .result = 0 };

        if (!req) {
            resp.result = -EINVAL;
        } else {
            resp.result = fut_vfs_rmdir(req->path);
        }

        send_response(POSIXD_MSG_RMDIR, &resp, sizeof(resp));
        break;
    }

    case POSIXD_MSG_UNLINK: {
        const struct posixd_unlink_req *req = (const struct posixd_unlink_req *)msg->payload;
        struct posixd_unlink_resp resp = { .result = 0 };

        if (!req) {
            resp.result = -EINVAL;
        } else {
            resp.result = fut_vfs_unlink(req->path);
        }

        send_response(POSIXD_MSG_UNLINK, &resp, sizeof(resp));
        break;
    }

    default:
        break;
    }
}

/**
 * Handle process management requests.
 */
static void handle_process_request(struct fut_fipc_msg *msg) {
    if (!msg) return;

    switch (msg->type) {
    case POSIXD_MSG_FORK: {
        /* Phase 3: Handle fork request
         * 1. Duplicate current process context
         * 2. Create new task in kernel
         * 3. Set up new FIPC channels
         * 4. Return child PID to parent, 0 to child
         */
        break;
    }

    case POSIXD_MSG_EXEC: {
        /* Phase 3: Handle exec request
         * 1. Load executable from filesystem
         * 2. Set up new address space
         * 3. Initialize stack with args/env
         * 4. Jump to entry point
         */
        break;
    }

    case POSIXD_MSG_WAIT: {
        /* Phase 3: Handle wait request
         * 1. Block until child exits
         * 2. Collect exit status
         * 3. Return child PID and status
         */
        break;
    }

    case POSIXD_MSG_EXIT: {
        /* Phase 3: Handle exit request
         * 1. Close all file descriptors
         * 2. Notify parent (SIGCHLD)
         * 3. Terminate task
         */
        break;
    }

    default:
        /* Unknown process operation */
        break;
    }
}

/**
 * Main event loop for posixd.
 */
static void posixd_main_loop(void) {
    uint8_t msg_buffer[8192];

    while (running) {
        /* Wait for incoming requests */
        if (listen_channel) {
            ssize_t received = fut_fipc_recv(listen_channel, msg_buffer, sizeof(msg_buffer));
            if (received > 0) {
                struct fut_fipc_msg *msg = (struct fut_fipc_msg *)msg_buffer;

                /* Route based on message type */
                if (msg->type >= POSIXD_MSG_OPEN && msg->type <= POSIXD_MSG_LSEEK) {
                    handle_file_request(msg);
                } else if (msg->type >= POSIXD_MSG_OPENDIR && msg->type <= POSIXD_MSG_UNLINK) {
                    handle_directory_request(msg);
                } else if (msg->type >= POSIXD_MSG_FORK && msg->type <= POSIXD_MSG_GETPID) {
                    handle_process_request(msg);
                }
            }
        }

        /* Phase 3: Would implement proper event waiting with timeout */
    }
}

/**
 * Initialize posixd daemon.
 */
static int posixd_init(void) {
    /* Phase 3: Would initialize:
     * - File descriptor table (per-process)
     * - Process table
     * - FIPC listen channel (advertised to clients)
     * - Connection to fsd
     */

    return 0;
}

/**
 * Cleanup and shutdown.
 */
static void posixd_shutdown(void) {
    /* Phase 3: Would cleanup:
     * - Close all FIPC channels
     * - Release resources
     */
}

/**
 * Main entry point for posixd.
 */
int main(int argc, char **argv) {
    (void)argc;
    (void)argv;

    /* Initialize daemon */
    if (posixd_init() < 0) {
        return 1;
    }

    /* Enter main loop */
    posixd_main_loop();

    /* Shutdown */
    posixd_shutdown();

    return 0;
}
