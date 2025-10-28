/* main.c - Filesystem Daemon (fsd)
 *
 * Copyright (c) 2025 Kelsi Davis
 * Licensed under the MPL v2.0 — see LICENSE for details.
 *
 * User-space filesystem daemon - manages VFS, mount points, and file operations.
 * Provides filesystem services via FIPC.
 */

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>
#include <kernel/fut_fipc.h>
#include <kernel/fut_vfs.h>
#include <kernel/fut_object.h>
#include <user/futura_posix.h>

/* Message types for fsd (internal - not in public header yet) */
#define FSD_MSG_MOUNT       0x4001
#define FSD_MSG_UNMOUNT     0x4002
#define FSD_MSG_OPEN        0x4003
#define FSD_MSG_CLOSE       0x4004
#define FSD_MSG_READ        0x4005
#define FSD_MSG_WRITE       0x4006
#define FSD_MSG_STAT        0x4007
#define FSD_MSG_OPENDIR     0x4008
#define FSD_MSG_READDIR     0x4009
#define FSD_MSG_CLOSEDIR    0x400A
#define FSD_MSG_MKDIR       0x400B
#define FSD_MSG_RMDIR       0x400C
#define FSD_MSG_UNLINK      0x400D

/* Global state */
static bool running = true;
static struct fut_fipc_channel *listen_channel = NULL;

struct fsd_dir_handle {
    bool in_use;
    int64_t handle;
    char path[POSIX_PATH_MAX];
    uint64_t cookie;
};

#define FSD_MAX_DIR_HANDLES 64
static struct fsd_dir_handle dir_table[FSD_MAX_DIR_HANDLES];
static int64_t next_dir_handle = 1;

#define FSD_S_IFDIR 0040000

struct fsd_opendir_req {
    char path[POSIX_PATH_MAX];
};

struct fsd_opendir_resp {
    int result;
    int64_t dir_handle;
};

struct fsd_readdir_req {
    int64_t dir_handle;
};

struct fsd_path_req {
    char path[POSIX_PATH_MAX];
};

struct fsd_result_resp {
    int result;
};

struct fsd_mount_req {
    char device[256];
    char mountpoint[256];
    char fstype[64];
    uint32_t flags;
    fut_handle_t block_device_handle;
};

struct fsd_mount_resp {
    int result;
};

static void fsd_str_copy(char *dest, const char *src, size_t max_len) {
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

static struct fsd_dir_handle *fsd_dir_alloc(const char *path) {
    for (int i = 0; i < FSD_MAX_DIR_HANDLES; i++) {
        if (!dir_table[i].in_use) {
            dir_table[i].in_use = true;
            dir_table[i].handle = next_dir_handle++;
            dir_table[i].cookie = 0;
            fsd_str_copy(dir_table[i].path, path, sizeof(dir_table[i].path));
            return &dir_table[i];
        }
    }
    return NULL;
}

static struct fsd_dir_handle *fsd_dir_find(int64_t handle) {
    for (int i = 0; i < FSD_MAX_DIR_HANDLES; i++) {
        if (dir_table[i].in_use && dir_table[i].handle == handle) {
            return &dir_table[i];
        }
    }
    return NULL;
}

static void fsd_dir_release(struct fsd_dir_handle *dir) {
    if (dir) {
        dir->in_use = false;
        dir->handle = 0;
        dir->path[0] = '\0';
        dir->cookie = 0;
    }
}

static void fsd_send_response(uint32_t type, const void *payload, size_t size) {
    if (listen_channel) {
        fut_fipc_send(listen_channel, type, payload, size);
    }
}

static int fsd_is_directory(const char *path) {
    struct fut_stat st;
    int ret = fut_vfs_stat(path, &st);
    if (ret < 0) {
        return ret;
    }
    return (st.st_mode & FSD_S_IFDIR) ? 0 : -ENOTDIR;
}

/**
 * Handle mount request.
 */
static void handle_mount(struct fut_fipc_msg *msg) {
    const struct fsd_mount_req *req = (const struct fsd_mount_req *)msg->payload;
    struct fsd_mount_resp resp = { .result = 0 };

    /* Validate request */
    if (!req || req->mountpoint[0] == '\0' || req->fstype[0] == '\0') {
        resp.result = -EINVAL;
        fsd_send_response(FSD_MSG_MOUNT, &resp, sizeof(resp));
        return;
    }

    /* Validate capability handle if present */
    if (req->block_device_handle != FUT_INVALID_HANDLE) {
        /* Block devices require READ and WRITE rights */
        fut_rights_t required_rights = FUT_RIGHT_READ | FUT_RIGHT_WRITE;

        if (!fut_object_has_rights(req->block_device_handle, required_rights)) {
            /* Capability validation failed - insufficient rights */
            resp.result = -EACCES;
            fsd_send_response(FSD_MSG_MOUNT, &resp, sizeof(resp));
            return;
        }
    }

    /* Call VFS mount with capability handle */
    const char *device = (req->device[0] != '\0') ? req->device : NULL;
    int ret = fut_vfs_mount(device, req->mountpoint, req->fstype,
                           req->flags, NULL, req->block_device_handle);

    resp.result = ret;
    fsd_send_response(FSD_MSG_MOUNT, &resp, sizeof(resp));
}

/**
 * Handle file open request.
 */
static void handle_open(struct fut_fipc_msg *msg) {
    (void)msg;

    /* Phase 3: Parse open request:
     * 1. Resolve path to vnode
     * 2. Check permissions
     * 3. Call kernel fut_vfs_open()
     * 4. Return file descriptor
     */
}

/**
 * Handle file read request.
 */
static void handle_read(struct fut_fipc_msg *msg) {
    (void)msg;

    /* Phase 3: Parse read request:
     * 1. Validate file descriptor
     * 2. Get shared buffer region from request
     * 3. Call kernel fut_vfs_read() into shared buffer
     * 4. Send response with bytes read
     */
}

/**
 * Handle file write request.
 */
static void handle_write(struct fut_fipc_msg *msg) {
    (void)msg;

    /* Phase 3: Parse write request:
     * 1. Validate file descriptor
     * 2. Get data from shared buffer region
     * 3. Call kernel fut_vfs_write()
     * 4. Send response with bytes written
     */
}

static void handle_opendir_msg(struct fut_fipc_msg *msg) {
    const struct fsd_opendir_req *req = (const struct fsd_opendir_req *)msg->payload;
    struct fsd_opendir_resp resp = { .result = 0, .dir_handle = -1 };

    if (!req || req->path[0] == '\0') {
        resp.result = -EINVAL;
        fsd_send_response(FSD_MSG_OPENDIR, &resp, sizeof(resp));
        return;
    }

    int ret = fsd_is_directory(req->path);
    if (ret < 0) {
        resp.result = ret;
        fsd_send_response(FSD_MSG_OPENDIR, &resp, sizeof(resp));
        return;
    }

    struct fsd_dir_handle *dir = fsd_dir_alloc(req->path);
    if (!dir) {
        resp.result = -ENFILE;
    } else {
        resp.dir_handle = dir->handle;
    }

    fsd_send_response(FSD_MSG_OPENDIR, &resp, sizeof(resp));
}

static void handle_readdir_msg(struct fut_fipc_msg *msg) {
    const struct fsd_readdir_req *req = (const struct fsd_readdir_req *)msg->payload;
    struct posixd_readdir_resp resp = {
        .result = 0,
        .has_entry = false,
    };

    if (!req) {
        resp.result = -EINVAL;
        fsd_send_response(FSD_MSG_READDIR, &resp, sizeof(resp));
        return;
    }

    struct fsd_dir_handle *dir = fsd_dir_find(req->dir_handle);
    if (!dir) {
        resp.result = -ENOENT;
        fsd_send_response(FSD_MSG_READDIR, &resp, sizeof(resp));
        return;
    }

    uint64_t cookie = dir->cookie;
    struct fut_vdirent dent;
    int ret = fut_vfs_readdir(dir->path, &cookie, &dent);

    if (ret == -ENOENT) {
        dir->cookie = cookie;
        resp.result = 0;
        resp.has_entry = false;
        fsd_send_response(FSD_MSG_READDIR, &resp, sizeof(resp));
        return;
    }

    if (ret < 0) {
        dir->cookie = cookie;
        resp.result = ret;
        fsd_send_response(FSD_MSG_READDIR, &resp, sizeof(resp));
        return;
    }

    dir->cookie = cookie;
    resp.has_entry = true;
    resp.entry.d_ino = dent.d_ino;
    resp.entry.d_off = dent.d_off;
    resp.entry.d_reclen = dent.d_reclen;
    resp.entry.d_type = dent.d_type;
    fsd_str_copy(resp.entry.d_name, dent.d_name, sizeof(resp.entry.d_name));

    fsd_send_response(FSD_MSG_READDIR, &resp, sizeof(resp));
}

static void handle_closedir_msg(struct fut_fipc_msg *msg) {
    const struct posixd_closedir_req *req = (const struct posixd_closedir_req *)msg->payload;
    struct fsd_result_resp resp = { .result = 0 };

    if (!req) {
        resp.result = -EINVAL;
        fsd_send_response(FSD_MSG_CLOSEDIR, &resp, sizeof(resp));
        return;
    }

    struct fsd_dir_handle *dir = fsd_dir_find(req->dir_handle);
    if (!dir) {
        resp.result = -ENOENT;
    } else {
        fsd_dir_release(dir);
    }

    fsd_send_response(FSD_MSG_CLOSEDIR, &resp, sizeof(resp));
}

static void handle_mkdir_msg(struct fut_fipc_msg *msg) {
    const struct posixd_mkdir_req *req = (const struct posixd_mkdir_req *)msg->payload;
    struct fsd_result_resp resp = { .result = 0 };

    if (!req) {
        resp.result = -EINVAL;
    } else {
        resp.result = fut_vfs_mkdir(req->path, req->mode);
    }

    fsd_send_response(FSD_MSG_MKDIR, &resp, sizeof(resp));
}

static void handle_rmdir_msg(struct fut_fipc_msg *msg) {
    const struct posixd_unlink_req *req = (const struct posixd_unlink_req *)msg->payload;
    struct fsd_result_resp resp = { .result = 0 };

    if (!req || req->path[0] == '\0') {
        resp.result = -EINVAL;
    } else {
        resp.result = fut_vfs_rmdir(req->path);
    }

    fsd_send_response(FSD_MSG_RMDIR, &resp, sizeof(resp));
}

static void handle_unlink_msg(struct fut_fipc_msg *msg) {
    const struct posixd_unlink_req *req = (const struct posixd_unlink_req *)msg->payload;
    struct fsd_result_resp resp = { .result = 0 };

    if (!req || req->path[0] == '\0') {
        resp.result = -EINVAL;
    } else {
        resp.result = fut_vfs_unlink(req->path);
    }

    fsd_send_response(FSD_MSG_UNLINK, &resp, sizeof(resp));
}

/**
 * Main event loop for fsd.
 */
static void fsd_main_loop(void) {
    uint8_t msg_buffer[8192];

    while (running) {
        /* Wait for incoming requests */
        if (listen_channel) {
            ssize_t received = fut_fipc_recv(listen_channel, msg_buffer, sizeof(msg_buffer));
            if (received > 0) {
                struct fut_fipc_msg *msg = (struct fut_fipc_msg *)msg_buffer;

                /* Route based on message type */
                switch (msg->type) {
                case FSD_MSG_MOUNT:
                    handle_mount(msg);
                    break;
                case FSD_MSG_UNMOUNT:
                    /* Phase 3: Handle unmount */
                    break;
                case FSD_MSG_OPEN:
                    handle_open(msg);
                    break;
                case FSD_MSG_CLOSE:
                    /* Phase 3: Handle close */
                    break;
                case FSD_MSG_READ:
                    handle_read(msg);
                    break;
                case FSD_MSG_WRITE:
                    handle_write(msg);
                    break;
                case FSD_MSG_STAT:
                    /* Phase 3: Handle stat */
                    break;
                case FSD_MSG_OPENDIR:
                    handle_opendir_msg(msg);
                    break;
                case FSD_MSG_READDIR:
                    handle_readdir_msg(msg);
                    break;
                case FSD_MSG_CLOSEDIR:
                    handle_closedir_msg(msg);
                    break;
                case FSD_MSG_MKDIR:
                    handle_mkdir_msg(msg);
                    break;
                case FSD_MSG_RMDIR:
                    handle_rmdir_msg(msg);
                    break;
                case FSD_MSG_UNLINK:
                    handle_unlink_msg(msg);
                    break;
                default:
                    /* Unknown request */
                    break;
                }
            }
        }

        /* Phase 3: Would implement proper event waiting */
    }
}

/**
 * Initialize fsd daemon.
 */
static int fsd_init(void) {
    /* Phase 3: Would initialize:
     * - VFS subsystem (fut_vfs_init())
     * - Register built-in filesystems (ramfs, devfs, etc.)
     * - Mount root filesystem
     * - Create FIPC listen channel
     */

    /* Phase 3: Mount root filesystem */
    /* fut_vfs_mount(NULL, "/", "ramfs", 0, NULL); */

    return 0;
}

/**
 * Cleanup and shutdown.
 */
static void fsd_shutdown(void) {
    /* Phase 3: Would cleanup:
     * - Unmount all filesystems
     * - Close FIPC channels
     * - Release resources
     */
}

/**
 * Main entry point for fsd.
 */
int main(int argc, char **argv) {
    (void)argc;
    (void)argv;

    /* Initialize daemon */
    if (fsd_init() < 0) {
        return 1;
    }

    /* Enter main loop */
    fsd_main_loop();

    /* Shutdown */
    fsd_shutdown();

    return 0;
}
