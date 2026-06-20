/* posix.c - POSIX API Wrappers for Futura OS
 *
 * Copyright (c) 2025 Kelsi Davis
 * Licensed under the MPL v2.0 — see LICENSE for details.
 *
 * POSIX-compatible functions that communicate with posixd via FIPC.
 */

#include <stdarg.h>
#include <stdint.h>
#include <stddef.h>
#include <errno.h>
#include <fcntl.h>
#include <kernel/fut_fipc.h>
#include <user/futura_posix.h>
#include <user/libfutura.h>
#include <user/sys.h>
/* stdlib.h not available in freestanding environment */
#include "timerfd_internal.h"
#include "signalfd_internal.h"
#include "eventfd_internal.h"
#include "socket_unix.h"
#include "fd.h"
#include "memory_map.h"

/* Connection to posixd daemon */
static struct fut_fipc_channel *posixd_channel = NULL;

struct fut_dir {
    int64_t handle;
};

/* The posixd protocol and the kernel both report failure as a negative
 * -errno value (see the struct comments in <user/futura_posix.h>). POSIX
 * userland must instead return -1 and set errno to the positive code, so
 * funnel daemon/kernel results through this helper. */
static long posix_result(long value) {
    if (value < 0) {
        errno = (int)-value;
        return -1;
    }
    return value;
}

/* Transport-level failure (a FIPC send/recv that fails or is truncated)
 * carries no errno of its own; surface it as EIO under the same
 * return-(-1) contract. */
static int posix_transport_fail(void) {
    errno = EIO;
    return -1;
}

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
    /* NULL path is a programmer error / EFAULT. The original combined
     * check (!posixd_channel || !path) just bounced through posix_init
     * and then dereferenced path anyway. */
    if (!path) {
        errno = EFAULT;
        return -1;
    }
    if (!posixd_channel) {
        if (posix_init() < 0 || !posixd_channel) {
            return posix_transport_fail();
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

    /* The mode arg is variadic and only meaningful when O_CREAT or
     * O_TMPFILE is set. Hardcoding 0644 ignored callers' intent —
     * libwayland's wl_os_create_anonymous_file passes 0600 specifically
     * to keep the file private; we silently overrode it to world-
     * readable. */
    int mode = 0;
    if (flags & (O_CREAT | 020000000 /* O_TMPFILE */)) {
        va_list ap;
        va_start(ap, flags);
        mode = va_arg(ap, int);
        va_end(ap);
    }
    msg.req.mode = mode;

    /* Send request to posixd */
    int ret = fut_fipc_send(posixd_channel, POSIXD_MSG_OPEN,
                            &msg.req, sizeof(msg.req));
    if (ret < 0) {
        return posix_transport_fail();
    }

    /* Receive response */
    uint8_t resp_buffer[256];
    ssize_t recv_ret = fut_fipc_recv(posixd_channel, resp_buffer, sizeof(resp_buffer));
    if (recv_ret < (ssize_t)(sizeof(struct fut_fipc_msg) + sizeof(struct posixd_open_resp))) {
        return posix_transport_fail();
    }

    struct fut_fipc_msg *resp_msg = (struct fut_fipc_msg *)resp_buffer;
    struct posixd_open_resp *resp = (struct posixd_open_resp *)resp_msg->payload;

    /* resp->fd is the descriptor, or a negative -errno on failure. */
    return (int)posix_result(resp->fd);
}

/**
 * Close a file descriptor.
 */
int close(int fd) {
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

    /* No posixd available — close directly via the kernel. sys_close
     * returns 0 or a negative -errno. */
    if (!posixd_channel && posix_init() < 0) {
        fut_fd_path_forget(fd);
        return (int)posix_result(sys_close(fd));
    }
    if (!posixd_channel) {
        fut_fd_path_forget(fd);
        return (int)posix_result(sys_close(fd));
    }

    struct posixd_close_req req = { .fd = fd };

    /* Send request */
    int ret = fut_fipc_send(posixd_channel, POSIXD_MSG_CLOSE,
                            &req, sizeof(req));
    fut_fd_path_forget(fd);
    if (ret < 0) {
        return posix_transport_fail();
    }

    /* Read the daemon's reply: leaving it unread would desync the channel
     * for the next request, and the close result itself was being dropped. */
    uint8_t resp_buffer[256];
    ssize_t recv_ret = fut_fipc_recv(posixd_channel, resp_buffer, sizeof(resp_buffer));
    if (recv_ret < (ssize_t)(sizeof(struct fut_fipc_msg) + sizeof(struct posixd_close_resp))) {
        return posix_transport_fail();
    }

    struct fut_fipc_msg *resp_msg = (struct fut_fipc_msg *)resp_buffer;
    struct posixd_close_resp *resp = (struct posixd_close_resp *)resp_msg->payload;
    return (int)posix_result(resp->result);
}

/**
 * Read from file descriptor.
 */
ssize_t read(int fd, void *buf, size_t count) {
    if (!buf) {
        errno = EFAULT;
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
        return posix_transport_fail();
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
        return posix_transport_fail();
    }

    /* Receive response */
    uint8_t resp_buffer[4096];
    ssize_t recv_ret = fut_fipc_recv(posixd_channel, resp_buffer, sizeof(resp_buffer));
    if (recv_ret < (ssize_t)(sizeof(struct fut_fipc_msg) + sizeof(struct posixd_read_resp))) {
        return posix_transport_fail();
    }

    struct fut_fipc_msg *resp_msg = (struct fut_fipc_msg *)resp_buffer;
    struct posixd_read_resp *resp = (struct posixd_read_resp *)resp_msg->payload;

    /* Copy data with bounds checks against both user buffer and received bytes */
    if (resp->bytes_read > 0 && (size_t)resp->bytes_read <= count) {
        /* Verify the inline data fits within what we actually received */
        size_t available_data = (size_t)recv_ret
            - sizeof(struct fut_fipc_msg) - sizeof(struct posixd_read_resp);
        size_t safe_copy = (size_t)resp->bytes_read;
        if (safe_copy > available_data) {
            safe_copy = available_data;
        }
        for (size_t i = 0; i < safe_copy; i++) {
            ((char *)buf)[i] = ((char *)(resp + 1))[i];
        }
        return (ssize_t)safe_copy;
    }

    /* bytes_read is 0 at EOF, or a negative -errno on failure. */
    return (ssize_t)posix_result(resp->bytes_read);
}

/**
 * Write to file descriptor.
 */
ssize_t write(int fd, const void *buf, size_t count) {
    if (!buf) {
        errno = EFAULT;
        return -1;
    }
    if (!posixd_channel && posix_init() < 0) {
        return posix_transport_fail();
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
        return posix_transport_fail();
    }

    /* Receive response */
    uint8_t resp_buffer[256];
    ssize_t recv_ret = fut_fipc_recv(posixd_channel, resp_buffer, sizeof(resp_buffer));
    if (recv_ret < (ssize_t)(sizeof(struct fut_fipc_msg) + sizeof(struct posixd_write_resp))) {
        return posix_transport_fail();
    }

    struct fut_fipc_msg *resp_msg = (struct fut_fipc_msg *)resp_buffer;
    struct posixd_write_resp *resp = (struct posixd_write_resp *)resp_msg->payload;

    /* bytes_written, or a negative -errno on failure. */
    return (ssize_t)posix_result(resp->bytes_written);
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

/* mmap64 wrapper - aliases not supported on some toolchains */
void *mmap64(void *addr, size_t length, int prot, int flags, int fd, off_t offset) {
    return mmap(addr, length, prot, flags, fd, offset);
}

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
    return (int)posix_result(sys_call2(SYS_flock, fd, operation));
}

int unlink(const char *path) {
    if (!path) {
        errno = EFAULT;
        return -1;
    }
    if (!posixd_channel && posix_init() < 0) {
        return posix_transport_fail();
    }

    struct posixd_unlink_req req;
    size_t i;
    for (i = 0; i < POSIX_PATH_MAX - 1 && path[i]; i++) {
        req.path[i] = path[i];
    }
    req.path[i] = '\0';

    int ret = fut_fipc_send(posixd_channel, POSIXD_MSG_UNLINK, &req, sizeof(req));
    if (ret < 0) {
        return posix_transport_fail();
    }

    uint8_t resp_buffer[256];
    ssize_t recv_ret = fut_fipc_recv(posixd_channel, resp_buffer, sizeof(resp_buffer));
    if (recv_ret < (ssize_t)(sizeof(struct fut_fipc_msg) + sizeof(struct posixd_unlink_resp))) {
        return posix_transport_fail();
    }

    struct fut_fipc_msg *resp_msg = (struct fut_fipc_msg *)resp_buffer;
    struct posixd_unlink_resp *resp = (struct posixd_unlink_resp *)resp_msg->payload;
    return (int)posix_result(resp->result);
}

int mkdir(const char *path, mode_t mode) {
    if (!path) {
        errno = EFAULT;
        return -1;
    }
    if (!posixd_channel && posix_init() < 0) {
        return posix_transport_fail();
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
        return posix_transport_fail();
    }

    uint8_t resp_buffer[256];
    ssize_t recv_ret = fut_fipc_recv(posixd_channel, resp_buffer, sizeof(resp_buffer));
    if (recv_ret < (ssize_t)(sizeof(struct fut_fipc_msg) + sizeof(struct posixd_mkdir_resp))) {
        return posix_transport_fail();
    }

    struct fut_fipc_msg *resp_msg = (struct fut_fipc_msg *)resp_buffer;
    struct posixd_mkdir_resp *resp = (struct posixd_mkdir_resp *)resp_msg->payload;
    return (int)posix_result(resp->result);
}

int rmdir(const char *path) {
    if (!path) {
        errno = EFAULT;
        return -1;
    }
    if (!posixd_channel && posix_init() < 0) {
        return posix_transport_fail();
    }

    struct posixd_unlink_req req;
    size_t i;
    for (i = 0; i < POSIX_PATH_MAX - 1 && path[i]; i++) {
        req.path[i] = path[i];
    }
    req.path[i] = '\0';

    int ret = fut_fipc_send(posixd_channel, POSIXD_MSG_RMDIR, &req, sizeof(req));
    if (ret < 0) {
        return posix_transport_fail();
    }

    uint8_t resp_buffer[256];
    ssize_t recv_ret = fut_fipc_recv(posixd_channel, resp_buffer, sizeof(resp_buffer));
    if (recv_ret < (ssize_t)(sizeof(struct fut_fipc_msg) + sizeof(struct posixd_unlink_resp))) {
        return posix_transport_fail();
    }

    struct fut_fipc_msg *resp_msg = (struct fut_fipc_msg *)resp_buffer;
    struct posixd_unlink_resp *resp = (struct posixd_unlink_resp *)resp_msg->payload;
    return (int)posix_result(resp->result);
}

fut_dir_t *opendir(const char *path) {
    if (!path) {
        errno = EFAULT;
        return NULL;
    }
    if (!posixd_channel && posix_init() < 0) {
        errno = EIO;
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
        errno = EIO;
        return NULL;
    }

    uint8_t resp_buffer[256];
    ssize_t recv_ret = fut_fipc_recv(posixd_channel, resp_buffer, sizeof(resp_buffer));
    if (recv_ret < (ssize_t)(sizeof(struct fut_fipc_msg) + sizeof(struct posixd_opendir_resp))) {
        errno = EIO;
        return NULL;
    }

    struct fut_fipc_msg *resp_msg = (struct fut_fipc_msg *)resp_buffer;
    struct posixd_opendir_resp *resp = (struct posixd_opendir_resp *)resp_msg->payload;
    if (resp->result < 0) {
        errno = -resp->result;
        return NULL;
    }
    if (resp->dir_handle < 0) {
        errno = EBADF;
        return NULL;
    }

    fut_dir_t *dir = malloc(sizeof(*dir));
    if (!dir) {
        struct posixd_closedir_req creq = { .dir_handle = resp->dir_handle };
        fut_fipc_send(posixd_channel, POSIXD_MSG_CLOSEDIR, &creq, sizeof(creq));
        errno = ENOMEM;
        return NULL;
    }
    dir->handle = resp->dir_handle;
    return dir;
}

int closedir(fut_dir_t *dir) {
    if (!dir) {
        errno = EBADF;
        return -1;
    }
    if (!posixd_channel && posix_init() < 0) {
        return posix_transport_fail();
    }

    struct posixd_closedir_req req = { .dir_handle = dir->handle };
    int ret = fut_fipc_send(posixd_channel, POSIXD_MSG_CLOSEDIR, &req, sizeof(req));
    if (ret < 0) {
        free(dir);
        return posix_transport_fail();
    }

    uint8_t resp_buffer[256];
    ssize_t recv_ret = fut_fipc_recv(posixd_channel, resp_buffer, sizeof(resp_buffer));
    if (recv_ret < (ssize_t)(sizeof(struct fut_fipc_msg) + sizeof(struct posixd_closedir_resp))) {
        free(dir);
        return posix_transport_fail();
    }

    struct fut_fipc_msg *resp_msg = (struct fut_fipc_msg *)resp_buffer;
    struct posixd_closedir_resp *resp = (struct posixd_closedir_resp *)resp_msg->payload;
    int result = (int)posix_result(resp->result);
    free(dir);
    return result;
}

int readdir(fut_dir_t *dir, struct fut_dirent *entry) {
    if (!dir) {
        errno = EBADF;
        return -1;
    }
    if (!entry) {
        errno = EFAULT;
        return -1;
    }
    if (!posixd_channel && posix_init() < 0) {
        return posix_transport_fail();
    }

    struct posixd_readdir_req req = { .dir_handle = dir->handle };
    entry->d_name[0] = '\0';
    int ret = fut_fipc_send(posixd_channel, POSIXD_MSG_READDIR, &req, sizeof(req));
    if (ret < 0) {
        return posix_transport_fail();
    }

    uint8_t resp_buffer[sizeof(struct fut_fipc_msg) + sizeof(struct posixd_readdir_resp)] = {0};
    ssize_t recv_ret = fut_fipc_recv(posixd_channel, resp_buffer, sizeof(resp_buffer));
    if (recv_ret < (ssize_t)(sizeof(struct fut_fipc_msg) + sizeof(struct posixd_readdir_resp))) {
        return posix_transport_fail();
    }

    struct fut_fipc_msg *resp_msg = (struct fut_fipc_msg *)resp_buffer;
    struct posixd_readdir_resp *resp = (struct posixd_readdir_resp *)resp_msg->payload;
    if (resp->result < 0) {
        return (int)posix_result(resp->result);
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
    if (!posixd_channel && posix_init() < 0) {
        return posix_transport_fail();
    }

    /* Send fork request */
    struct posixd_fork_req req;
    int ret = fut_fipc_send(posixd_channel, POSIXD_MSG_FORK,
                            &req, sizeof(req));
    if (ret < 0) {
        return posix_transport_fail();
    }

    /* Receive response */
    uint8_t resp_buffer[256];
    ssize_t recv_ret = fut_fipc_recv(posixd_channel, resp_buffer, sizeof(resp_buffer));
    if (recv_ret < (ssize_t)(sizeof(struct fut_fipc_msg) + sizeof(struct posixd_fork_resp))) {
        return posix_transport_fail();
    }

    struct fut_fipc_msg *resp_msg = (struct fut_fipc_msg *)resp_buffer;
    struct posixd_fork_resp *resp = (struct posixd_fork_resp *)resp_msg->payload;

    /* pid in the parent, 0 in the child, or a negative -errno on failure. */
    return (int)posix_result(resp->pid);
}

/**
 * Execute program.
 */
int execve(const char *path, char *const argv[], char *const envp[]) {
    if (!path) {
        errno = EFAULT;
        return -1;
    }
    if (!posixd_channel && posix_init() < 0) {
        return posix_transport_fail();
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
    int ret = fut_fipc_send(posixd_channel, POSIXD_MSG_EXEC,
                            &msg.req, sizeof(msg.req));
    if (ret < 0) {
        return posix_transport_fail();
    }

    /* exec doesn't return on success, so reaching here means the image
     * was not replaced. */
    errno = ENOEXEC;
    return -1;
}

/**
 * Wait for child process.
 */
int waitpid(int pid, int *status, int options) {
    if (!posixd_channel && posix_init() < 0) {
        return posix_transport_fail();
    }

    struct posixd_wait_req req = {
        .pid = pid,
        .options = options,
    };

    /* Send request */
    int ret = fut_fipc_send(posixd_channel, POSIXD_MSG_WAIT,
                            &req, sizeof(req));
    if (ret < 0) {
        return posix_transport_fail();
    }

    /* Receive response */
    uint8_t resp_buffer[256];
    ssize_t recv_ret = fut_fipc_recv(posixd_channel, resp_buffer, sizeof(resp_buffer));
    if (recv_ret < (ssize_t)(sizeof(struct fut_fipc_msg) + sizeof(struct posixd_wait_resp))) {
        return posix_transport_fail();
    }

    struct fut_fipc_msg *resp_msg = (struct fut_fipc_msg *)resp_buffer;
    struct posixd_wait_resp *resp = (struct posixd_wait_resp *)resp_msg->payload;

    /* On failure pid carries -errno; don't touch *status in that case. */
    if (resp->pid < 0) {
        errno = -resp->pid;
        return -1;
    }

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
