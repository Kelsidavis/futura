// SPDX-License-Identifier: MPL-2.0

#include "socket_unix.h"

#include <shared/fut_timespec.h>
#include <user/libfutura.h>
#include <user/sys.h>
#include <user/futura_posix.h>

#include "fd.h"
#include <user/stdio.h>

#ifndef EPOLLIN
#define EPOLLIN 0x001u
#endif
#ifndef EPOLLOUT
#define EPOLLOUT 0x004u
#endif

/* Kernel syscall wrappers for socket operations */
#define __NR_socket 41
#define __NR_sendmsg 46
#define __NR_recvmsg 47
#define __NR_bind   49
#define __NR_listen 50
#define __NR_accept 43
#define __NR_connect 53

static inline long sys_socket(int domain, int type, int protocol) {
    long ret;
    __asm__ volatile("syscall"
                     : "=a"(ret)
                     : "0"(__NR_socket), "D"((long)domain), "S"((long)type), "d"((long)protocol)
                     : "rcx", "r11", "memory");
    return ret;
}

static inline long sys_bind(int sockfd, const void *addr, uint32_t addrlen) {
    long ret;
    __asm__ volatile("syscall"
                     : "=a"(ret)
                     : "0"(__NR_bind), "D"((long)sockfd), "S"((long)addr), "d"((long)addrlen)
                     : "rcx", "r11", "memory");
    return ret;
}

static inline long sys_listen(int sockfd, int backlog) {
    long ret;
    __asm__ volatile("syscall"
                     : "=a"(ret)
                     : "0"(__NR_listen), "D"((long)sockfd), "S"((long)backlog)
                     : "rcx", "r11", "memory");
    return ret;
}

static inline long sys_accept(int sockfd, void *addr, uint32_t *addrlen) {
    long ret;
    __asm__ volatile("syscall"
                     : "=a"(ret)
                     : "0"(__NR_accept), "D"((long)sockfd), "S"((long)addr), "d"((long)addrlen)
                     : "rcx", "r11", "memory");
    return ret;
}

static inline long sys_sendmsg(int sockfd, const void *msg, int flags) {
    long ret;
    __asm__ volatile("syscall"
                     : "=a"(ret)
                     : "0"(__NR_sendmsg), "D"((long)sockfd), "S"((long)msg), "d"((long)flags)
                     : "rcx", "r11", "memory");
    return ret;
}

static inline long sys_recvmsg(int sockfd, void *msg, int flags) {
    long ret;
    __asm__ volatile("syscall"
                     : "=a"(ret)
                     : "0"(__NR_recvmsg), "D"((long)sockfd), "S"((long)msg), "d"((long)flags)
                     : "rcx", "r11", "memory");
    return ret;
}

static inline long sys_connect(int sockfd, const void *addr, uint32_t addrlen) {
    long ret;
    __asm__ volatile("syscall"
                     : "=a"(ret)
                     : "0"(__NR_connect), "D"((long)sockfd), "S"((long)addr), "d"((long)addrlen)
                     : "rcx", "r11", "memory");
    return ret;
}

#define UNIX_MAX_STREAMS       64
#define UNIX_MAX_LISTENERS     16
#define UNIX_MAX_CONNECTIONS   32
#define UNIX_MAX_PENDING_CONN  16

struct unix_packet_fd {
    char path[128];
};

struct unix_packet {
    uint8_t *data;
    size_t data_len;
    size_t offset;
    struct unix_packet_fd *fds;
    size_t fd_count;
    bool control_sent;
    struct unix_packet *next;
};

struct unix_queue {
    struct unix_packet *head;
    struct unix_packet *tail;
};

static void queue_push(struct unix_queue *q, struct unix_packet *pkt) {
    pkt->next = NULL;
    if (!q->head) {
        q->head = q->tail = pkt;
    } else {
        q->tail->next = pkt;
        q->tail = pkt;
    }
}

static struct unix_packet *queue_front(struct unix_queue *q) {
    return q->head;
}

static void queue_pop_front(struct unix_queue *q) {
    if (!q->head) {
        return;
    }
    struct unix_packet *next = q->head->next;
    q->head = next;
    if (!q->head) {
        q->tail = NULL;
    }
}

static void queue_dispose(struct unix_queue *q) {
    while (q->head) {
        struct unix_packet *pkt = q->head;
        q->head = pkt->next;
        if (pkt->data) {
            free(pkt->data);
        }
        if (pkt->fds) {
            free(pkt->fds);
        }
        free(pkt);
    }
    q->tail = NULL;
}

enum stream_state {
    STREAM_UNUSED = 0,
    STREAM_INIT,
    STREAM_BOUND,
    STREAM_LISTENER,
    STREAM_CONNECTED,
    STREAM_CLOSED,
};

struct unix_listener;
struct unix_connection;

struct unix_stream {
    bool in_use;
    enum stream_state state;
    int fd;
    struct unix_listener *listener;
    struct unix_connection *connection;
    int endpoint_index;
    bool nonblocking;
    int refcount;
};

struct unix_listener {
    bool in_use;
    char path[108];
    int backlog;
    int pending[UNIX_MAX_PENDING_CONN];
    int pending_head;
    int pending_tail;
    int pending_count;
};

struct unix_connection {
    bool in_use;
    struct unix_queue inbox[2];
    bool closed[2];
};

static struct unix_stream streams[UNIX_MAX_STREAMS];
static struct unix_listener listeners[UNIX_MAX_LISTENERS];
static struct unix_connection connections[UNIX_MAX_CONNECTIONS];

static void sleep_brief(void) {
    fut_timespec_t ts = {
        .tv_sec = 0,
        .tv_nsec = 1000000L
    };
    sys_nanosleep_call(&ts, NULL);
}

static struct unix_stream *alloc_stream(void) {
    for (int i = 0; i < UNIX_MAX_STREAMS; ++i) {
        if (!streams[i].in_use) {
            streams[i].in_use = true;
            streams[i].state = STREAM_INIT;
            streams[i].fd = -1;
            streams[i].listener = NULL;
            streams[i].connection = NULL;
            streams[i].endpoint_index = 0;
            streams[i].nonblocking = false;
            streams[i].refcount = 1;
            return &streams[i];
        }
    }
    return NULL;
}

static void destroy_stream(struct unix_stream *stream) {
    if (!stream) {
        return;
    }
    stream->in_use = false;
    stream->state = STREAM_UNUSED;
    stream->fd = -1;
    stream->listener = NULL;
    stream->connection = NULL;
    stream->endpoint_index = 0;
    stream->nonblocking = false;
    stream->refcount = 0;
}

static struct unix_listener *alloc_listener(void) {
    for (int i = 0; i < UNIX_MAX_LISTENERS; ++i) {
        if (!listeners[i].in_use) {
            listeners[i].in_use = true;
            listeners[i].path[0] = '\0';
            listeners[i].backlog = 0;
            listeners[i].pending_head = 0;
            listeners[i].pending_tail = 0;
            listeners[i].pending_count = 0;
            return &listeners[i];
        }
    }
    return NULL;
}

static void destroy_listener(struct unix_listener *listener) {
    if (!listener) {
        return;
    }
    listener->in_use = false;
    listener->path[0] = '\0';
    listener->backlog = 0;
    listener->pending_head = listener->pending_tail = listener->pending_count = 0;
}

static struct unix_listener *find_listener(const char *path) {
    if (!path) {
        return NULL;
    }
    for (int i = 0; i < UNIX_MAX_LISTENERS; ++i) {
        if (listeners[i].in_use && strcmp(listeners[i].path, path) == 0) {
            return &listeners[i];
        }
    }
    return NULL;
}

static struct unix_connection *alloc_connection(void) {
    for (int i = 0; i < UNIX_MAX_CONNECTIONS; ++i) {
        if (!connections[i].in_use) {
            connections[i].in_use = true;
            connections[i].inbox[0].head = connections[i].inbox[0].tail = NULL;
            connections[i].inbox[1].head = connections[i].inbox[1].tail = NULL;
            connections[i].closed[0] = false;
            connections[i].closed[1] = false;
            return &connections[i];
        }
    }
    return NULL;
}

static void destroy_connection(struct unix_connection *conn) {
    if (!conn) {
        return;
    }
    queue_dispose(&conn->inbox[0]);
    queue_dispose(&conn->inbox[1]);
    conn->closed[0] = false;
    conn->closed[1] = false;
    conn->in_use = false;
}

static void pending_push(struct unix_listener *listener, int fd) {
    if (!listener || listener->pending_count >= UNIX_MAX_PENDING_CONN) {
        return;
    }
    listener->pending[listener->pending_tail] = fd;
    listener->pending_tail = (listener->pending_tail + 1) % UNIX_MAX_PENDING_CONN;
    listener->pending_count++;
}

static int pending_pop(struct unix_listener *listener) {
    if (!listener || listener->pending_count == 0) {
        return -1;
    }
    int fd = listener->pending[listener->pending_head];
    listener->pending_head = (listener->pending_head + 1) % UNIX_MAX_PENDING_CONN;
    listener->pending_count--;
    return fd;
}

static void free_packet(struct unix_packet *pkt) {
    if (!pkt) {
        return;
    }
    if (pkt->data) {
        free(pkt->data);
    }
    if (pkt->fds) {
        free(pkt->fds);
    }
    free(pkt);
}

static int copy_iov_data(uint8_t *dst, const struct iovec *iov, size_t iovlen) {
    size_t offset = 0;
    for (size_t i = 0; i < iovlen; ++i) {
        if (!iov[i].iov_base || iov[i].iov_len == 0) {
            continue;
        }
        memcpy(dst + offset, iov[i].iov_base, iov[i].iov_len);
        offset += iov[i].iov_len;
    }
    return (int)offset;
}

static size_t iov_total_length(const struct iovec *iov, size_t iovlen) {
    size_t total = 0;
    if (!iov) {
        return 0;
    }
    for (size_t i = 0; i < iovlen; ++i) {
        total += iov[i].iov_len;
    }
    return total;
}

static bool string_has_prefix(const char *str, const char *prefix) {
    if (!str || !prefix) {
        return false;
    }
    while (*prefix) {
        if (*str++ != *prefix++) {
            return false;
        }
    }
    return true;
}

static int extract_fds_from_control(const struct msghdr *msg,
                                    struct unix_packet_fd **out_fds,
                                    size_t *out_count) {
    *out_fds = NULL;
    *out_count = 0;
    if (!msg || !msg->msg_control || msg->msg_controllen == 0) {
        return 0;
    }

    size_t ctrl_len = msg->msg_controllen;
    size_t offset = 0;
    size_t total_fds = 0;

    while (offset + sizeof(struct cmsghdr) <= ctrl_len) {
        /* Use char* for byte arithmetic (allowed to alias per C standard) */
        struct cmsghdr *cmsg = (struct cmsghdr *)((char *)msg->msg_control + offset);
        if (cmsg->cmsg_len < sizeof(struct cmsghdr) ||
            offset + cmsg->cmsg_len > ctrl_len) {
            break;
        }
        if (cmsg->cmsg_level == SOL_SOCKET && cmsg->cmsg_type == SCM_RIGHTS) {
            size_t fd_bytes = cmsg->cmsg_len - sizeof(struct cmsghdr);
            total_fds += fd_bytes / sizeof(int);
        }
        offset += cmsg->cmsg_len;
    }

    if (total_fds == 0) {
        return 0;
    }

    struct unix_packet_fd *fds = malloc(total_fds * sizeof(struct unix_packet_fd));
    if (!fds) {
        return -1;
    }

    offset = 0;
    size_t idx = 0;
    while (offset + sizeof(struct cmsghdr) <= ctrl_len && idx < total_fds) {
        /* Use char* for byte arithmetic (allowed to alias per C standard) */
        struct cmsghdr *cmsg = (struct cmsghdr *)((char *)msg->msg_control + offset);
        if (cmsg->cmsg_len < sizeof(struct cmsghdr) ||
            offset + cmsg->cmsg_len > ctrl_len) {
            break;
        }
        if (cmsg->cmsg_level == SOL_SOCKET && cmsg->cmsg_type == SCM_RIGHTS) {
            size_t fd_bytes = cmsg->cmsg_len - sizeof(struct cmsghdr);
            size_t fd_count = fd_bytes / sizeof(int);
            int *fd_list = (int *)((char *)cmsg + sizeof(struct cmsghdr));
            for (size_t i = 0; i < fd_count && idx < total_fds; ++i, ++idx) {
                char path_buf[128];
                if (fut_fd_path_lookup(fd_list[i], path_buf, sizeof(path_buf)) != 0 ||
                    !string_has_prefix(path_buf, "/tmp/fut-shm-")) {
                    free(fds);
                    return -1;
                }
                size_t len = strlen(path_buf);
                if (len >= sizeof(fds[idx].path)) {
                    len = sizeof(fds[idx].path) - 1;
                }
                memcpy(fds[idx].path, path_buf, len);
                fds[idx].path[len] = '\0';
            }
        }
        offset += cmsg->cmsg_len;
    }

    *out_fds = fds;
    *out_count = total_fds;
    return 0;
}

static int reopen_fd_for_path(const char *path) {
    if (!path || path[0] == '\0') {
        return -1;
    }
    int fd = (int)sys_open(path, O_RDWR, 0);
    if (fd >= 0) {
        fut_fd_path_register(fd, path);
    }
    return fd;
}

static void handle_connection_close(struct unix_connection *conn, int endpoint) {
    if (!conn) {
        return;
    }
    conn->closed[endpoint] = true;
    if (conn->closed[0] && conn->closed[1]) {
        destroy_connection(conn);
    }
}

static struct unix_packet *ensure_front_packet(struct unix_queue *queue) {
    struct unix_packet *pkt = queue_front(queue);
    while (pkt &&
           pkt->offset >= pkt->data_len &&
           (pkt->control_sent || pkt->fd_count == 0)) {
        struct unix_packet *to_free = pkt;
        queue_pop_front(queue);
        free_packet(to_free);
        pkt = queue_front(queue);
    }
    return pkt;
}

static struct unix_stream *socket_from_fd(int fd) {
    struct fut_fd_entry *entry = fut_fd_lookup(fd);
    if (!entry) {
        return NULL;
    }
    if (entry->kind != FUT_FD_UNIX_STREAM && entry->kind != FUT_FD_UNIX_LISTENER) {
        return NULL;
    }
    return (struct unix_stream *)entry->payload;
}

int socket(int domain, int type, int protocol) {
    /* Use kernel syscall for all AF_UNIX sockets
     * This ensures the kernel socket FD table has the entry, which is
     * required for inter-process connections via the VFS socket layer.
     *
     * We don't register these with the userspace FD table because:
     * 1. Client sockets only need kernel-side handling for connect()
     * 2. Server sockets that bind/listen will be handled by the kernel
     * 3. Avoiding FD number mismatch between kernel and userspace tables
     */
    if (domain == AF_UNIX) {
        printf("[SOCKET-LIB] socket(AF_UNIX, type=%d) -> kernel syscall\n", type);
        long fd = sys_socket(domain, type, protocol);
        printf("[SOCKET-LIB] kernel socket returned fd=%ld\n", fd);
        return (int)fd;
    }

    /* For non-AF_UNIX, use userspace-only implementation (backwards compat) */
    if (type != SOCK_STREAM || protocol != 0) {
        return -1;
    }
    struct unix_stream *stream = alloc_stream();
    if (!stream) {
        return -1;
    }
    int fd = fut_fd_alloc(FUT_FD_UNIX_STREAM, stream);
    if (fd < 0) {
        destroy_stream(stream);
        return -1;
    }
    stream->fd = fd;
    return fd;
}

int bind(int fd, const struct sockaddr *addr, socklen_t len) {
    /* First check if this is a userspace-tracked socket */
    struct unix_stream *stream = socket_from_fd(fd);

    /* If not in userspace table, use kernel syscall directly */
    if (!stream) {
        return (int)sys_bind(fd, addr, len);
    }

    if (stream->state != STREAM_INIT) {
        return -1;
    }
    if (!addr || len < sizeof(struct sockaddr_un)) {
        return -1;
    }
    const struct sockaddr_un *sun = (const struct sockaddr_un *)addr;
    if (sun->sun_family != AF_UNIX) {
        return -1;
    }
    if (find_listener(sun->sun_path)) {
        return -1;
    }
    struct unix_listener *listener = alloc_listener();
    if (!listener) {
        return -1;
    }
    size_t path_len = strlen(sun->sun_path);
    if (path_len >= sizeof(listener->path)) {
        destroy_listener(listener);
        return -1;
    }
    memcpy(listener->path, sun->sun_path, path_len);
    listener->path[path_len] = '\0';
    listener->backlog = 0;
    stream->listener = listener;
    stream->state = STREAM_BOUND;
    fut_fd_update_payload(fd, stream);
    return 0;
}

int listen(int fd, int backlog) {
    struct unix_stream *stream = socket_from_fd(fd);

    /* If not in userspace table, use kernel syscall directly */
    if (!stream) {
        return (int)sys_listen(fd, backlog);
    }

    if (stream->state != STREAM_BOUND || !stream->listener) {
        return -1;
    }
    if (backlog <= 0) {
        backlog = 1;
    }
    stream->listener->backlog = backlog;
    stream->state = STREAM_LISTENER;
    fut_fd_update_payload(fd, stream);
    return 0;
}


int connect(int fd, const struct sockaddr *addr, socklen_t len) {
    struct unix_stream *stream = socket_from_fd(fd);
    if (!stream || stream->state != STREAM_INIT) {
        /* Not a userspace socket - fall back to kernel */
        printf("[SOCKET-LIB] connect(fd=%d) -> kernel syscall\n", fd);
        long ret = sys_connect(fd, addr, len);
        printf("[SOCKET-LIB] kernel connect returned %ld\n", ret);
        return (int)ret;
    }
    if (!addr || len < sizeof(struct sockaddr_un)) {
        return -1;
    }
    const struct sockaddr_un *sun = (const struct sockaddr_un *)addr;
    if (sun->sun_family != AF_UNIX) {
        return -1;
    }
    struct unix_listener *listener = find_listener(sun->sun_path);
    if (!listener || listener->pending_count >= listener->backlog) {
        /* No local listener found - try kernel */
        return (int)sys_connect(fd, addr, len);
    }
    struct unix_connection *conn = alloc_connection();
    if (!conn) {
        return -1;
    }

    struct unix_stream *server_stream = alloc_stream();
    if (!server_stream) {
        destroy_connection(conn);
        return -1;
    }

    int server_fd = fut_fd_alloc(FUT_FD_UNIX_STREAM, server_stream);
    if (server_fd < 0) {
        destroy_stream(server_stream);
        destroy_connection(conn);
        return -1;
    }

    stream->connection = conn;
    stream->endpoint_index = 0;
    stream->state = STREAM_CONNECTED;

    server_stream->connection = conn;
    server_stream->endpoint_index = 1;
    server_stream->state = STREAM_CONNECTED;
    server_stream->fd = server_fd;

    conn->closed[0] = false;
    conn->closed[1] = false;

    fut_fd_update_payload(fd, stream);
    fut_fd_update_payload(server_fd, server_stream);

    pending_push(listener, server_fd);
    return 0;
}

static int accept_internal(int fd, struct sockaddr *addr, socklen_t *len, bool block) {
    (void)addr;
    (void)len;

    struct unix_stream *stream = socket_from_fd(fd);
    if (!stream || stream->state != STREAM_LISTENER || !stream->listener) {
        return -1;
    }
    struct unix_listener *listener = stream->listener;

    while (listener->pending_count == 0) {
        if (!block) {
            return -1;
        }
        sleep_brief();
    }
    int new_fd = pending_pop(listener);
    return new_fd;
}

int accept(int fd, struct sockaddr *addr, socklen_t *len) {
    /* First check if this is a userspace-tracked socket */
    struct unix_stream *stream = socket_from_fd(fd);

    /* If not in userspace table, use kernel syscall directly */
    if (!stream) {
        printf("[SOCKET-LIB] accept(fd=%d) -> kernel syscall\n", fd);
        uint32_t addrlen = len ? *len : 0;
        long ret = sys_accept(fd, addr, len ? &addrlen : NULL);
        if (len) *len = addrlen;
        printf("[SOCKET-LIB] kernel accept returned %ld\n", ret);
        if (ret < 0) {
            extern int *__errno_location(void);
            *__errno_location() = (int)(-ret);
            return -1;
        }
        return (int)ret;
    }

    return accept_internal(fd, addr, len, true);
}

static ssize_t socket_stream_send(struct unix_stream *stream,
                                  const struct msghdr *msg) {
    if (!stream || stream->state != STREAM_CONNECTED || !stream->connection) {
        return -1;
    }
    struct unix_connection *conn = stream->connection;
    int local_index = stream->endpoint_index;
    int remote_index = 1 - local_index;

    if (conn->closed[remote_index]) {
        return -1;
    }

    size_t total_len = iov_total_length(msg->msg_iov, msg->msg_iovlen);
    struct unix_packet *pkt = malloc(sizeof(struct unix_packet));
    if (!pkt) {
        return -1;
    }
    pkt->data = NULL;
    pkt->fds = NULL;
    pkt->next = NULL;
    pkt->data_len = total_len;
    pkt->offset = 0;
    pkt->control_sent = false;
    pkt->fd_count = 0;

    if (total_len > 0) {
        pkt->data = malloc(total_len);
        if (!pkt->data) {
            free(pkt);
            return -1;
        }
        copy_iov_data(pkt->data, msg->msg_iov, msg->msg_iovlen);
    }

    if (extract_fds_from_control(msg, &pkt->fds, &pkt->fd_count) != 0) {
        free_packet(pkt);
        return -1;
    }

    queue_push(&conn->inbox[remote_index], pkt);
    return (ssize_t)total_len;
}

static ssize_t socket_stream_recv(struct unix_stream *stream,
                                  struct msghdr *msg) {
    if (!stream || stream->state != STREAM_CONNECTED || !stream->connection) {
        return -1;
    }
    struct unix_connection *conn = stream->connection;
    int index = stream->endpoint_index;

    if (msg && !msg->msg_control) {
        msg->msg_controllen = 0;
    }

    struct unix_queue *queue = &conn->inbox[index];
    struct unix_packet *pkt = ensure_front_packet(queue);

    while (!pkt) {
        if (conn->closed[1 - index]) {
            return 0;
        }
        sleep_brief();
        pkt = ensure_front_packet(queue);
    }

    size_t capacity = iov_total_length(msg->msg_iov, msg->msg_iovlen);
    size_t remaining = pkt->data_len - pkt->offset;
    size_t to_copy = (remaining < capacity) ? remaining : capacity;

    size_t copied = 0;
    for (size_t i = 0; i < msg->msg_iovlen && copied < to_copy; ++i) {
        size_t chunk = msg->msg_iov[i].iov_len;
        if (chunk == 0) {
            continue;
        }
        size_t take = chunk;
        if (take > to_copy - copied) {
            take = to_copy - copied;
        }
        memcpy(msg->msg_iov[i].iov_base,
               pkt->data + pkt->offset + copied,
               take);
        copied += take;
    }
    pkt->offset += copied;

    if (!pkt->control_sent && pkt->fd_count > 0 &&
        msg->msg_control && msg->msg_controllen >= sizeof(struct cmsghdr) + pkt->fd_count * sizeof(int)) {
        struct cmsghdr *cmsg = (struct cmsghdr *)msg->msg_control;
        cmsg->cmsg_level = SOL_SOCKET;
        cmsg->cmsg_type = SCM_RIGHTS;
        cmsg->cmsg_len = sizeof(struct cmsghdr) + pkt->fd_count * sizeof(int);
        int *fd_data = (int *)((char *)cmsg + sizeof(struct cmsghdr));
        for (size_t i = 0; i < pkt->fd_count; ++i) {
            fd_data[i] = reopen_fd_for_path(pkt->fds[i].path);
        }
        msg->msg_flags = 0;
        msg->msg_controllen = cmsg->cmsg_len;
        pkt->control_sent = true;
    } else if (msg->msg_control && msg->msg_controllen > 0) {
        struct cmsghdr *cmsg = (struct cmsghdr *)msg->msg_control;
        cmsg->cmsg_len = 0;
        msg->msg_flags = 0;
        msg->msg_controllen = 0;
    }

    if (pkt->offset >= pkt->data_len &&
        (pkt->control_sent || pkt->fd_count == 0)) {
        queue_pop_front(queue);
        free_packet(pkt);
    }

    return (ssize_t)copied;
}

ssize_t sendmsg(int fd, const struct msghdr *msg, int flags) {
    struct unix_stream *stream = socket_from_fd(fd);
    if (!stream) {
        /* Not in userspace table - use kernel syscall */
        long ret = sys_sendmsg(fd, msg, flags);
        if (ret < 0) {
            extern int *__errno_location(void);
            *__errno_location() = (int)(-ret);
            return -1;
        }
        return (ssize_t)ret;
    }
    (void)flags;
    return socket_stream_send(stream, msg);
}

ssize_t recvmsg(int fd, struct msghdr *msg, int flags) {
    struct unix_stream *stream = socket_from_fd(fd);
    if (!stream) {
        /* Not in userspace table - use kernel syscall */
        long ret = sys_recvmsg(fd, msg, flags);
        if (ret < 0) {
            extern int *__errno_location(void);
            *__errno_location() = (int)(-ret);
            return -1;
        }
        return (ssize_t)ret;
    }
    (void)flags;
    return socket_stream_recv(stream, msg);
}

ssize_t __fut_unix_socket_write(int fd, const void *buf, size_t count) {
    struct unix_stream *stream = socket_from_fd(fd);
    if (!stream) {
        return -1;
    }
    struct iovec iov = {
        .iov_base = (void *)buf,
        .iov_len = count,
    };
    struct msghdr msg = {
        .msg_iov = &iov,
        .msg_iovlen = 1,
        .msg_control = NULL,
        .msg_controllen = 0,
        .msg_flags = 0,
    };
    return socket_stream_send(stream, &msg);
}

ssize_t __fut_unix_socket_read(int fd, void *buf, size_t count) {
    struct unix_stream *stream = socket_from_fd(fd);
    if (!stream) {
        return -1;
    }
    struct iovec iov = {
        .iov_base = buf,
        .iov_len = count,
    };
    struct msghdr msg = {
        .msg_iov = &iov,
        .msg_iovlen = 1,
        .msg_control = NULL,
        .msg_controllen = 0,
        .msg_flags = 0,
    };
    return socket_stream_recv(stream, &msg);
}

int __fut_unix_socket_is(int fd) {
    return socket_from_fd(fd) ? 1 : 0;
}

int __fut_unix_socket_poll(int fd, uint32_t requested, uint32_t *ready_out) {
    struct unix_stream *stream = socket_from_fd(fd);
    if (!stream) {
        return 0;
    }

    uint32_t ready = 0;

    if (stream->state == STREAM_LISTENER && stream->listener) {
        if (stream->listener->pending_count > 0) {
            ready |= EPOLLIN;
        }
        ready |= EPOLLOUT;
    } else if (stream->state == STREAM_CONNECTED && stream->connection) {
        struct unix_queue *queue = &stream->connection->inbox[stream->endpoint_index];
        struct unix_packet *pkt = ensure_front_packet(queue);
        if (pkt) {
            ready |= EPOLLIN;
        }
        if (!stream->connection->closed[1 - stream->endpoint_index]) {
            ready |= EPOLLOUT;
        }
    }

    ready &= requested ? requested : (EPOLLIN | EPOLLOUT);
    if (ready_out) {
        *ready_out = ready;
    }
    return 1;
}

static void close_listener_pending(struct unix_listener *listener) {
    if (!listener) {
        return;
    }
    while (listener->pending_count > 0) {
        int fd = pending_pop(listener);
        if (fd >= 0) {
            struct unix_stream *pending_stream = socket_from_fd(fd);
            if (pending_stream) {
                handle_connection_close(pending_stream->connection, pending_stream->endpoint_index);
                destroy_stream(pending_stream);
            }
            fut_fd_release(fd);
        }
    }
}

int __fut_unix_socket_close(int fd) {
    struct unix_stream *stream = socket_from_fd(fd);
    if (!stream) {
        return -1;
    }

    if (stream->refcount > 1) {
        stream->refcount -= 1;
        return 0;
    }

    if (stream->state == STREAM_LISTENER || stream->state == STREAM_BOUND) {
        if (stream->listener) {
            close_listener_pending(stream->listener);
            destroy_listener(stream->listener);
            stream->listener = NULL;
        }
        destroy_stream(stream);
        return 0;
    }

    if (stream->state == STREAM_CONNECTED && stream->connection) {
        handle_connection_close(stream->connection, stream->endpoint_index);
        stream->connection = NULL;
    }

    destroy_stream(stream);
    return 0;
}

void __fut_unix_socket_forget(int fd) {
    (void)fd;
}

int __fut_unix_socket_retain(int fd) {
    struct unix_stream *stream = socket_from_fd(fd);
    if (!stream) {
        return -1;
    }
    stream->refcount += 1;
    return 0;
}

int __fut_unix_socket_set_flags(int fd, int flags) {
    struct unix_stream *stream = socket_from_fd(fd);
    if (!stream) {
        return -1;
    }
    stream->nonblocking = (flags & O_NONBLOCK) != 0;
    return 0;
}

int getsockopt(int fd, int level, int optname, void *optval, socklen_t *optlen) {
    (void)fd;
    (void)level;
    (void)optname;
    (void)optval;
    (void)optlen;
    return 0;
}

int setsockopt(int fd, int level, int optname, const void *optval, socklen_t optlen) {
    (void)fd;
    (void)level;
    (void)optname;
    (void)optval;
    (void)optlen;
    return 0;
}

int shutdown(int fd, int how) {
    (void)fd;
    (void)how;
    return 0;
}
