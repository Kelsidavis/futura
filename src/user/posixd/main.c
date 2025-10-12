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
        /* Phase 3: Parse open request from payload
         * struct posixd_open_req *req = (struct posixd_open_req *)msg->payload;
         * 1. Forward to fsd (filesystem daemon)
         * 2. Allocate file descriptor
         * 3. Send response with fd
         */
        break;
    }

    case POSIXD_MSG_CLOSE: {
        /* Phase 3: Parse close request
         * 1. Find file descriptor
         * 2. Forward close to fsd
         * 3. Release fd
         */
        break;
    }

    case POSIXD_MSG_READ: {
        /* Phase 3: Parse read request
         * 1. Validate fd
         * 2. Forward read to fsd with shared buffer region
         * 3. Send response with bytes read
         */
        break;
    }

    case POSIXD_MSG_WRITE: {
        /* Phase 3: Parse write request
         * 1. Validate fd
         * 2. Forward write to fsd with shared buffer
         * 3. Send response with bytes written
         */
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
