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
#include <user/errno.h>
#include <user/libfutura.h>
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
        /* Read from file descriptor with optional shared buffer support */
        struct posixd_read_req *req = (struct posixd_read_req *)msg->payload;
        struct posixd_read_resp resp = {0};

        if (!req || req->count == 0) {
            resp.bytes_read = -EINVAL;
        } else {
            /* Allocate temporary buffer for read data (support up to 64KB) */
            const size_t MAX_READ_BUF = 65536;
            uint8_t *buf = NULL;
            size_t buf_size = (req->count > MAX_READ_BUF) ? MAX_READ_BUF : req->count;
            buf = (uint8_t *)malloc(buf_size);

            if (!buf) {
                resp.bytes_read = -ENOMEM;
            } else {
                /* Call VFS to read the file */
                ssize_t bytes = fut_vfs_read(req->fd, buf, buf_size);

                if (bytes < 0) {
                    resp.bytes_read = bytes;
                } else {
                    /* Check if client requested shared buffer region */
                    if (req->buffer_region_id != 0) {
                        /* FIPC shared buffer support (Phase 3):
                         * The client has allocated a shared memory region.
                         * In a full implementation, we would:
                         * 1. Look up the region by buffer_region_id
                         * 2. Map it into our address space
                         * 3. Copy the data into it
                         * 4. Return the region ID and byte count
                         *
                         * For now, we fall back to inline transmission
                         * if the data is small enough to fit in the response.
                         */
                        /* Large read - would need shared buffer */
                        resp.bytes_read = -ENOTSUP;  /* Not yet implemented */
                        bytes = 0;
                    } else {
                        /* No shared buffer - inline copy not implemented yet */
                        resp.bytes_read = -ENOTSUP;  /* Not yet implemented */
                        bytes = 0;
                    }

                    resp.bytes_read = bytes;
                }

                free(buf);
            }
        }

        send_response(POSIXD_MSG_READ, &resp, sizeof(resp));
        break;
    }

    case POSIXD_MSG_WRITE: {
        /* Write to file descriptor with optional shared buffer support */
        struct posixd_write_req *req = (struct posixd_write_req *)msg->payload;
        struct posixd_write_resp resp = {0};

        if (!req || req->count == 0) {
            resp.bytes_written = -EINVAL;
        } else {
            uint8_t *data = NULL;

            /* Check if client is using shared buffer region */
            if (req->buffer_region_id != 0) {
                /* FIPC shared buffer support (Phase 3):
                 * The client has allocated a shared memory region containing write data.
                 * In a full implementation, we would:
                 * 1. Look up the region by buffer_region_id
                 * 2. Map it into our address space if not already mapped
                 * 3. Read the data from the region
                 * 4. Write to file
                 *
                 * For now, we don't support large shared buffer writes.
                 */
                resp.bytes_written = -ENOTSUP;  /* Not yet implemented */
            } else {
                /* Data is passed inline after the request structure in the message payload.
                 * Calculate where the data starts in the payload:
                 * Message payload = [posixd_write_req] [data bytes...]
                 */
                size_t data_offset = sizeof(struct posixd_write_req);
                data = (uint8_t *)msg->payload + data_offset;

                /* Call VFS to write the file */
                ssize_t bytes = fut_vfs_write(req->fd, data, req->count);
                resp.bytes_written = bytes;
            }
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
        /* Handle fork request: Duplicate current process context */
        struct posixd_fork_resp resp = {0};

        /* Call kernel fork syscall */
        extern long sys_fork_call(void);
        long fork_result = sys_fork_call();

        if (fork_result < 0) {
            /* Error in fork */
            resp.pid = (pid_t)fork_result;
        } else {
            /* Success: fork_result is child PID in parent, 0 in child */
            resp.pid = (pid_t)fork_result;
        }

        send_response(POSIXD_MSG_FORK, &resp, sizeof(resp));
        break;
    }

    case POSIXD_MSG_EXEC: {
        /* Handle exec request: Load executable from filesystem with arguments */
        struct posixd_exec_req *req = (struct posixd_exec_req *)msg->payload;
        struct posixd_exec_resp resp = {0};

        if (!req || !req->path[0]) {
            resp.result = -EINVAL;
            send_response(POSIXD_MSG_EXEC, &resp, sizeof(resp));
            break;
        }

        /* Parse argv and envp from message payload
         * Message layout:
         *   [posixd_exec_req] (contains argc, envc)
         *   [argv string 0, argv string 1, ..., argv string argc-1]
         *   [envp string 0, envp string 1, ..., envp string envc-1]
         *
         * Each string is null-terminated, and we build arrays of pointers to them.
         */

        /* Allocate arrays on stack (safe for modest argc/envc)
         * Add 1 for NULL terminator in each array */
        #define MAX_ARGS 256
        char *argv_ptrs[MAX_ARGS] = {0};
        char *envp_ptrs[MAX_ARGS] = {0};

        /* Bounds check argc and envc */
        if (req->argc >= MAX_ARGS || req->envc >= MAX_ARGS || req->argc < 0 || req->envc < 0) {
            resp.result = -EINVAL;
            send_response(POSIXD_MSG_EXEC, &resp, sizeof(resp));
            break;
        }

        /* Calculate where strings start in the message payload.
         * Strings start right after the posixd_exec_req structure.
         * Note: We can't use sizeof(posixd_exec_req) directly due to padding,
         * so we calculate based on known offsets.
         */
        size_t req_header_size = sizeof(char) * POSIX_PATH_MAX + sizeof(int) * 2;
        char *strings_start = (char *)msg->payload + req_header_size;
        char *current_str = strings_start;

        /* Parse argv strings */
        for (int i = 0; i < req->argc; i++) {
            argv_ptrs[i] = current_str;
            /* Find next null terminator */
            while (*current_str != '\0') {
                current_str++;
            }
            current_str++;  /* Skip the null terminator */
        }
        argv_ptrs[req->argc] = NULL;  /* NULL terminate argv array */

        /* Parse envp strings */
        for (int i = 0; i < req->envc; i++) {
            envp_ptrs[i] = current_str;
            /* Find next null terminator */
            while (*current_str != '\0') {
                current_str++;
            }
            current_str++;  /* Skip the null terminator */
        }
        envp_ptrs[req->envc] = NULL;  /* NULL terminate envp array */

        /* Call kernel execve with parsed arguments and environment */
        extern long sys_execve_call(const char *pathname, char *const *argv, char *const *envp);
        long exec_result = sys_execve_call(
            req->path,
            (char *const *)argv_ptrs,
            (char *const *)envp_ptrs
        );

        /* execve doesn't return on success; only on error */
        resp.result = (int)exec_result;
        send_response(POSIXD_MSG_EXEC, &resp, sizeof(resp));
        break;
    }

    case POSIXD_MSG_WAIT: {
        /* Handle wait request: Block until child exits */
        struct posixd_wait_req *req = (struct posixd_wait_req *)msg->payload;
        struct posixd_wait_resp resp = {0};

        if (!req) {
            resp.pid = -EINVAL;
            send_response(POSIXD_MSG_WAIT, &resp, sizeof(resp));
            break;
        }

        /* Call kernel wait4 syscall via syscall wrapper
         * wait4(pid, &status, options, NULL)
         */
        extern long sys_wait4_call(long pid, int *wstatus, long options, void *rusage);
        int status = 0;
        long wait_result = sys_wait4_call((long)req->pid, &status, (long)req->options, NULL);

        if (wait_result < 0) {
            resp.pid = (pid_t)wait_result;
            resp.status = 0;
        } else {
            resp.pid = (pid_t)wait_result;
            resp.status = status;
        }

        send_response(POSIXD_MSG_WAIT, &resp, sizeof(resp));
        break;
    }

    case POSIXD_MSG_EXIT: {
        /* Handle exit request: Terminate current process */
        struct posixd_exit_req *req = (struct posixd_exit_req *)msg->payload;

        if (!req) {
            extern long sys_exit(long code);
            sys_exit(-EINVAL);
            return;  /* Never reached */
        }

        /* Call kernel exit syscall - this terminates the process */
        extern long sys_exit(long code);
        sys_exit((long)req->status);
        /* Never returns */
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
