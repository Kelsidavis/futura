/* fut_socket.c - Futura OS Kernel Socket Object System
 *
 * Copyright (c) 2025 Kelsi Davis
 * Licensed under the MPL v2.0 — see LICENSE for details.
 *
 * Phase 3 Implementation: Kernel-level AF_UNIX SOCK_STREAM socket support.
 * Manages socket state machines, connection queueing, and bidirectional I/O.
 */

#include "../../include/kernel/fut_socket.h"
#include "../../include/kernel/fut_memory.h"
#include "../../include/kernel/fut_vfs.h"
#include "../../include/kernel/fut_waitq.h"
#include "../../include/kernel/fut_sched.h"
#include "../../include/kernel/fut_timer.h"

extern void fut_printf(const char *fmt, ...);

/* Inline string functions for freestanding kernel environment */
static inline size_t socket_strlen(const char *s) {
    size_t len = 0;
    while (s[len]) len++;
    return len;
}

static inline int socket_strcmp(const char *s1, const char *s2) {
    while (*s1 && *s1 == *s2) {
        s1++;
        s2++;
    }
    return (unsigned char)*s1 - (unsigned char)*s2;
}

static inline char *socket_strcpy(char *s1, const char *s2) {
    char *p = s1;
    while ((*s1++ = *s2++));
    return p;
}

static inline void *socket_memset(void *s, int c, size_t n) {
    unsigned char *p = (unsigned char *)s;
    while (n--) *p++ = (unsigned char)c;
    return s;
}

static inline void *socket_memcpy(void *s1, const void *s2, size_t n) {
    unsigned char *d = (unsigned char *)s1;
    const unsigned char *src = (const unsigned char *)s2;
    while (n--) *d++ = *src++;
    return s1;
}

/* Use our implementations */
#define strlen(s)       socket_strlen(s)
#define strcmp(s1,s2)   socket_strcmp(s1, s2)
#define strcpy(s1,s2)   socket_strcpy(s1, s2)
#define memset(s,c,n)   socket_memset(s, c, n)
#define memcpy(s1,s2,n) socket_memcpy(s1, s2, n)

/* ============================================================
 *   Socket Registry (global)
 * ============================================================ */

#define FUT_SOCKET_MAX 256
static fut_socket_t *socket_registry[FUT_SOCKET_MAX];
static uint32_t socket_next_id = 1;
static fut_spinlock_t socket_lock;

/* ============================================================
 *   VFS Helper Functions
 * ============================================================ */

/**
 * Helper: Parse path into parent directory and filename.
 * Returns allocated component array on success, NULL on failure.
 * Caller must free the returned pointer.
 */
static char *parse_socket_path(const char *path, const char **out_filename) {
    if (!path || !out_filename) {
        return NULL;
    }

    size_t path_len = strlen(path);
    if (path_len == 0 || path_len > 108) {
        return NULL;
    }

    /* Find last slash to split path */
    const char *last_slash = NULL;
    for (size_t i = path_len; i > 0; i--) {
        if (path[i - 1] == '/') {
            last_slash = &path[i - 1];
            break;
        }
    }

    if (!last_slash) {
        /* No parent directory, use current directory (not supported) */
        return NULL;
    }

    size_t parent_len = last_slash - path;
    if (parent_len == 0) {
        parent_len = 1;  /* Root directory "/" */
    }

    char *parent_path = fut_malloc(parent_len + 1);
    if (!parent_path) {
        return NULL;
    }

    if (parent_len == 1) {
        parent_path[0] = '/';
    } else {
        memcpy(parent_path, path, parent_len);
    }
    parent_path[parent_len] = '\0';

    *out_filename = last_slash + 1;
    return parent_path;
}

/**
 * Create a socket inode in the VFS at the given path.
 * Returns the created vnode on success, NULL on failure.
 */
static struct fut_vnode *fut_vfs_create_socket(const char *path) {
    if (!path) {
        return NULL;
    }

    const char *filename = NULL;
    char *parent_path = parse_socket_path(path, &filename);
    if (!parent_path || !filename || filename[0] == '\0') {
        if (parent_path) {
            fut_free(parent_path);
        }
        return NULL;
    }

    /* Lookup parent directory */
    struct fut_vnode *parent = NULL;
    int lookup_ret = fut_vfs_lookup(parent_path, &parent);
    fut_free(parent_path);

    if (lookup_ret != 0 || !parent) {
        return NULL;
    }

    /* Check if parent is a directory */
    if (parent->type != VN_DIR) {
        fut_vnode_unref(parent);
        return NULL;
    }

    /* Call filesystem's create operation with socket inode type mode */
    struct fut_vnode *socket_inode = NULL;
    if (!parent->ops || !parent->ops->create) {
        fut_vnode_unref(parent);
        return NULL;
    }

    /* Mode: S_IFSOCK (0140000) | 0666 permissions = 0140666 */
    uint32_t socket_mode = 0140666;
    int create_ret = parent->ops->create(parent, filename, socket_mode, &socket_inode);
    fut_vnode_unref(parent);

    if (create_ret != 0 || !socket_inode) {
        return NULL;
    }

    return socket_inode;
}

/* ============================================================
 *   Initialization
 * ============================================================ */

void fut_socket_system_init(void) {
    memset(socket_registry, 0, sizeof(socket_registry));
    fut_spinlock_init(&socket_lock);
    fut_printf("[SOCKET] Socket subsystem initialized (max %d sockets)\n", FUT_SOCKET_MAX);
}

/* ============================================================
 *   Socket Creation and Lifecycle
 * ============================================================ */

/**
 * Create a new socket object in CREATED state.
 */
fut_socket_t *fut_socket_create(int family, int type) {
    if (family != 1) {  /* AF_UNIX */
        return NULL;
    }
    if (type != 1) {  /* SOCK_STREAM */
        return NULL;
    }

    fut_socket_t *socket = fut_malloc(sizeof(fut_socket_t));
    if (!socket) {
        return NULL;
    }

    memset(socket, 0, sizeof(*socket));
    socket->state = FUT_SOCK_CREATED;
    socket->address_family = family;
    socket->socket_type = type;
    socket->refcount = 1;
    socket->socket_id = socket_next_id++;

    /* Allocate wait queue for close operations */
    socket->close_waitq = fut_malloc(sizeof(fut_waitq_t));
    if (!socket->close_waitq) {
        fut_free(socket);
        return NULL;
    }
    fut_waitq_init(socket->close_waitq);

    /* Register in global socket table */
    fut_spinlock_acquire(&socket_lock);
    bool registered = false;
    for (int i = 0; i < FUT_SOCKET_MAX; i++) {
        if (!socket_registry[i]) {
            socket_registry[i] = socket;
            registered = true;
            break;
        }
    }
    fut_spinlock_release(&socket_lock);

    if (!registered) {
        fut_free(socket->close_waitq);
        fut_free(socket);
        return NULL;
    }

    fut_printf("[SOCKET] Created socket id=%u family=%d type=%d\n",
               socket->socket_id, family, type);
    return socket;
}

/**
 * Reference a socket (increment refcount).
 */
void fut_socket_ref(fut_socket_t *socket) {
    if (!socket) {
        return;
    }
    if (socket->refcount >= 1000) {
        fut_printf("[SOCKET-ERROR] Socket %u refcount overflow: %lu\n",
                   socket->socket_id, socket->refcount);
        return;
    }
    socket->refcount++;
}

/**
 * Unreference a socket (decrement refcount, may free).
 */
void fut_socket_unref(fut_socket_t *socket) {
    if (!socket) {
        return;
    }
    if (socket->refcount == 0) {
        fut_printf("[SOCKET-ERROR] Socket %u refcount underflow\n", socket->socket_id);
        return;
    }

    socket->refcount--;
    if (socket->refcount == 0) {
        /* Free socket resources */
        fut_printf("[SOCKET] Freeing socket id=%u\n", socket->socket_id);

        if (socket->bound_path) {
            fut_free(socket->bound_path);
        }

        /* Release VFS inode reference if bound */
        if (socket->path_vnode) {
            fut_vnode_unref(socket->path_vnode);
            socket->path_vnode = NULL;
        }

        if (socket->listener) {
            if (socket->listener->accept_waitq) {
                fut_free(socket->listener->accept_waitq);
            }
            fut_free(socket->listener);
        }
        if (socket->pair) {
            if (socket->pair->send_buf) {
                fut_free(socket->pair->send_buf);
            }
            if (socket->pair->recv_buf) {
                fut_free(socket->pair->recv_buf);
            }
            if (socket->pair->send_waitq) {
                fut_free(socket->pair->send_waitq);
            }
            if (socket->pair->recv_waitq) {
                fut_free(socket->pair->recv_waitq);
            }
            fut_free(socket->pair);
        }
        if (socket->close_waitq) {
            fut_free(socket->close_waitq);
        }

        /* Unregister from socket table */
        fut_spinlock_acquire(&socket_lock);
        for (int i = 0; i < FUT_SOCKET_MAX; i++) {
            if (socket_registry[i] == socket) {
                socket_registry[i] = NULL;
                break;
            }
        }
        fut_spinlock_release(&socket_lock);

        fut_free(socket);
    }
}

/* ============================================================
 *   Socket Binding
 * ============================================================ */

/**
 * Bind socket to a path.
 * Creates VFS inode for socket if needed.
 */
int fut_socket_bind(fut_socket_t *socket, const char *path) {
    if (!socket || !path || socket->state != FUT_SOCK_CREATED) {
        return -1;  /* EINVAL */
    }

    size_t path_len = strlen(path);
    if (path_len == 0 || path_len > 108) {
        return -1;  /* EINVAL */
    }

    /* Check if path already bound */
    fut_spinlock_acquire(&socket_lock);
    for (int i = 0; i < FUT_SOCKET_MAX; i++) {
        if (socket_registry[i] && socket_registry[i]->bound_path &&
            strcmp(socket_registry[i]->bound_path, path) == 0) {
            fut_spinlock_release(&socket_lock);
            return -48;  /* EADDRINUSE */
        }
    }
    fut_spinlock_release(&socket_lock);

    /* Allocate and store bound path */
    socket->bound_path = fut_malloc(path_len + 1);
    if (!socket->bound_path) {
        return -12;  /* ENOMEM */
    }
    strcpy(socket->bound_path, path);

    /* Create VFS inode for socket binding location */
    struct fut_vnode *inode = fut_vfs_create_socket(path);
    if (!inode) {
        /* Binding path creation failed, but socket is still bound for lookup */
        fut_printf("[SOCKET] Socket %u VFS inode creation failed (non-fatal), path: %s\n",
                   socket->socket_id, path);
    } else {
        socket->path_vnode = inode;
        fut_printf("[SOCKET] Socket %u created VFS inode, path: %s\n",
                   socket->socket_id, path);
    }

    socket->state = FUT_SOCK_BOUND;
    fut_printf("[SOCKET] Socket %u bound to path: %s\n", socket->socket_id, path);
    return 0;
}

/* ============================================================
 *   Socket Listening
 * ============================================================ */

/**
 * Mark socket as listening and allocate accept queue.
 */
int fut_socket_listen(fut_socket_t *socket, int backlog) {
    if (!socket || socket->state != FUT_SOCK_BOUND || socket->listener) {
        return -1;  /* EINVAL */
    }

    fut_socket_listener_t *listener = fut_malloc(sizeof(fut_socket_listener_t));
    if (!listener) {
        return -12;  /* ENOMEM */
    }

    memset(listener, 0, sizeof(*listener));
    listener->backlog = (backlog > 0) ? backlog : 1;
    if (listener->backlog > FUT_SOCKET_QUEUE_MAX) {
        listener->backlog = FUT_SOCKET_QUEUE_MAX;
    }

    listener->accept_waitq = fut_malloc(sizeof(fut_waitq_t));
    if (!listener->accept_waitq) {
        fut_free(listener);
        return -12;  /* ENOMEM */
    }
    fut_waitq_init(listener->accept_waitq);

    socket->listener = listener;
    socket->state = FUT_SOCK_LISTENING;
    fut_printf("[SOCKET] Socket %u now listening (backlog=%d)\n",
               socket->socket_id, listener->backlog);
    return 0;
}

/**
 * Accept pending connection from listen queue.
 */
int fut_socket_accept(fut_socket_t *listener, fut_socket_t **out_socket) {
    if (!listener || !out_socket || !listener->listener) {
        return -1;  /* EINVAL */
    }

    fut_socket_listener_t *queue = listener->listener;

    /* Try to get pending connection */
    if (queue->queue_count == 0) {
        /* No pending connections */
        return -11;  /* EAGAIN - caller must retry or use blocking I/O */
    }

    /* Dequeue pending connection */
    fut_socket_connection_entry_t *entry =
        &queue->queue[queue->queue_head];
    fut_socket_t *peer = entry->peer_socket;

    queue->queue_head = (queue->queue_head + 1) % FUT_SOCKET_QUEUE_MAX;
    queue->queue_count--;

    /* Peer becomes connected, create bidirectional pair */
    if (!peer->pair) {
        fut_socket_pair_t *pair = fut_malloc(sizeof(fut_socket_pair_t));
        if (!pair) {
            /* Cleanup and return error */
            fut_socket_unref(peer);
            return -12;  /* ENOMEM */
        }

        memset(pair, 0, sizeof(*pair));
        pair->send_buf = fut_malloc(FUT_SOCKET_BUFSIZE);
        pair->recv_buf = fut_malloc(FUT_SOCKET_BUFSIZE);
        if (!pair->send_buf || !pair->recv_buf) {
            if (pair->send_buf) fut_free(pair->send_buf);
            if (pair->recv_buf) fut_free(pair->recv_buf);
            fut_free(pair);
            fut_socket_unref(peer);
            return -12;  /* ENOMEM */
        }

        pair->send_size = FUT_SOCKET_BUFSIZE;
        pair->recv_size = FUT_SOCKET_BUFSIZE;
        pair->send_waitq = fut_malloc(sizeof(fut_waitq_t));
        pair->recv_waitq = fut_malloc(sizeof(fut_waitq_t));
        if (!pair->send_waitq || !pair->recv_waitq) {
            if (pair->send_waitq) fut_free(pair->send_waitq);
            if (pair->recv_waitq) fut_free(pair->recv_waitq);
            if (pair->send_buf) fut_free(pair->send_buf);
            if (pair->recv_buf) fut_free(pair->recv_buf);
            fut_free(pair);
            fut_socket_unref(peer);
            return -12;  /* ENOMEM */
        }
        fut_waitq_init(pair->send_waitq);
        fut_waitq_init(pair->recv_waitq);
        /* pair->lock is already zeroed by memset */
        pair->peer = NULL;  /* Will be set when accepted socket is used */
        pair->refcount = 2;  /* Shared between listener and peer */

        peer->pair = pair;
        peer->state = FUT_SOCK_CONNECTED;
    }

    *out_socket = peer;
    fut_printf("[SOCKET] Socket %u accepted connection from %u\n",
               listener->socket_id, peer->socket_id);
    return 0;
}

/* ============================================================
 *   Socket Connection
 * ============================================================ */

/**
 * Find listening socket by bound path.
 */
fut_socket_t *fut_socket_find_listener(const char *path) {
    if (!path) {
        return NULL;
    }

    fut_spinlock_acquire(&socket_lock);
    for (int i = 0; i < FUT_SOCKET_MAX; i++) {
        fut_socket_t *socket = socket_registry[i];
        if (socket && socket->bound_path &&
            strcmp(socket->bound_path, path) == 0 &&
            socket->state == FUT_SOCK_LISTENING) {
            fut_socket_ref(socket);
            fut_spinlock_release(&socket_lock);
            return socket;
        }
    }
    fut_spinlock_release(&socket_lock);
    return NULL;
}

/**
 * Connect to listening socket.
 */
int fut_socket_connect(fut_socket_t *socket, const char *target_path) {
    if (!socket || !target_path) {
        return -1;  /* EINVAL */
    }

    /* Find listening socket */
    fut_socket_t *listener = fut_socket_find_listener(target_path);
    if (!listener) {
        return -111;  /* ECONNREFUSED */
    }

    /* Check if listener has space in backlog */
    fut_socket_listener_t *queue = listener->listener;
    if ((int)queue->queue_count >= queue->backlog) {
        fut_socket_unref(listener);
        return -111;  /* ECONNREFUSED */
    }

    /* Queue pending connection */
    uint32_t tail = (queue->queue_head + queue->queue_count) % FUT_SOCKET_QUEUE_MAX;
    queue->queue[tail].peer_socket = socket;
    queue->queue[tail].flags = 0;
    queue->queue[tail].timestamp_ns = fut_get_time_ns();
    queue->queue_count++;

    socket->state = FUT_SOCK_CONNECTING;

    /* Wake up listener's accept queue */
    fut_waitq_wake_one(queue->accept_waitq);

    fut_socket_unref(listener);
    fut_printf("[SOCKET] Socket %u connecting to %s\n", socket->socket_id, target_path);
    return 0;
}

/* ============================================================
 *   Socket I/O
 * ============================================================ */

/**
 * Send data on connected socket.
 */
ssize_t fut_socket_send(fut_socket_t *socket, const void *buf, size_t len) {
    if (!socket || !buf || socket->state != FUT_SOCK_CONNECTED || !socket->pair) {
        return -1;  /* EINVAL */
    }

    fut_socket_pair_t *pair = socket->pair;
    if (!pair->peer) {
        return 0;  /* Peer closed */
    }

    fut_spinlock_acquire(&pair->lock);

    /* Block until send buffer has space (or socket is non-blocking) */
    uint32_t available = pair->recv_size -
        ((pair->recv_head + pair->recv_size - pair->recv_tail) % pair->recv_size);

    while (available == 0) {
        if (socket->flags & 0x800) {  /* O_NONBLOCK */
            fut_spinlock_release(&pair->lock);
            return -11;  /* EAGAIN */
        }
        /* Blocking socket: wait for receiver to read data */
        fut_waitq_sleep_locked(pair->send_waitq, &pair->lock, FUT_THREAD_BLOCKED);
        /* When we wake up, reacquire the lock */
        fut_spinlock_acquire(&pair->lock);

        /* Check again - peer might have closed while we were sleeping */
        if (!pair->peer) {
            fut_spinlock_release(&pair->lock);
            return 0;  /* Peer closed */
        }

        available = pair->recv_size -
            ((pair->recv_head + pair->recv_size - pair->recv_tail) % pair->recv_size);
    }

    size_t to_write = (len > available) ? available : len;
    if (to_write > (pair->recv_size - pair->recv_head)) {
        to_write = pair->recv_size - pair->recv_head;
    }

    memcpy(&pair->recv_buf[pair->recv_head], buf, to_write);
    pair->recv_head = (pair->recv_head + to_write) % pair->recv_size;

    /* Wake receiver */
    fut_waitq_wake_one(pair->recv_waitq);

    fut_spinlock_release(&pair->lock);

    fut_printf("[SOCKET] Socket %u sent %zu bytes\n", socket->socket_id, to_write);
    return (ssize_t)to_write;
}

/**
 * Receive data from connected socket.
 */
ssize_t fut_socket_recv(fut_socket_t *socket, void *buf, size_t len) {
    if (!socket || !buf || socket->state != FUT_SOCK_CONNECTED || !socket->pair) {
        return -1;  /* EINVAL */
    }

    fut_socket_pair_t *pair = socket->pair;

    fut_spinlock_acquire(&pair->lock);

    /* Block until data is available (or socket is non-blocking) */
    uint32_t available = (pair->recv_head + pair->recv_size - pair->recv_tail) %
                         pair->recv_size;

    while (available == 0) {
        if (socket->flags & 0x800) {  /* O_NONBLOCK */
            fut_spinlock_release(&pair->lock);
            return -11;  /* EAGAIN */
        }
        /* Blocking socket: wait for sender to write data */
        fut_waitq_sleep_locked(pair->recv_waitq, &pair->lock, FUT_THREAD_BLOCKED);
        /* When we wake up, reacquire the lock */
        fut_spinlock_acquire(&pair->lock);

        /* Check again - peer might have closed while we were sleeping */
        if (!pair->peer) {
            fut_spinlock_release(&pair->lock);
            return 0;  /* EOF - peer closed */
        }

        available = (pair->recv_head + pair->recv_size - pair->recv_tail) %
                    pair->recv_size;
    }

    size_t to_read = (len > available) ? available : len;
    if (to_read > (pair->recv_size - pair->recv_tail)) {
        to_read = pair->recv_size - pair->recv_tail;
    }

    memcpy(buf, &pair->recv_buf[pair->recv_tail], to_read);
    pair->recv_tail = (pair->recv_tail + to_read) % pair->recv_size;

    /* Wake sender */
    fut_waitq_wake_one(pair->send_waitq);

    fut_spinlock_release(&pair->lock);

    fut_printf("[SOCKET] Socket %u received %zu bytes\n", socket->socket_id, to_read);
    return (ssize_t)to_read;
}

/* ============================================================
 *   Socket Closing
 * ============================================================ */

/**
 * Close socket and clean up resources.
 */
int fut_socket_close(fut_socket_t *socket) {
    if (!socket) {
        return -1;  /* EINVAL */
    }

    socket->state = FUT_SOCK_CLOSED;

    /* Wake any waiters */
    if (socket->listener && socket->listener->accept_waitq) {
        fut_waitq_wake_all(socket->listener->accept_waitq);
    }
    if (socket->pair) {
        if (socket->pair->send_waitq) {
            fut_waitq_wake_all(socket->pair->send_waitq);
        }
        if (socket->pair->recv_waitq) {
            fut_waitq_wake_all(socket->pair->recv_waitq);
        }
    }

    fut_printf("[SOCKET] Socket %u closed\n", socket->socket_id);
    fut_socket_unref(socket);
    return 0;
}

/* ============================================================
 *   Socket Polling (for poll/select)
 * ============================================================ */

/**
 * Check if socket is ready for I/O operations.
 */
int fut_socket_poll(fut_socket_t *socket, int events) {
    if (!socket) {
        return 0;
    }

    int ready = 0;

    if (socket->state == FUT_SOCK_LISTENING && socket->listener) {
        if ((events & 0x1) && socket->listener->queue_count > 0) {  /* POLLIN */
            ready |= 0x1;
        }
    } else if (socket->state == FUT_SOCK_CONNECTED && socket->pair) {
        if ((events & 0x1)) {  /* POLLIN - readable if data available */
            uint32_t available = (socket->pair->recv_head + socket->pair->recv_size -
                                 socket->pair->recv_tail) % socket->pair->recv_size;
            if (available > 0) {
                ready |= 0x1;
            }
        }
        if ((events & 0x4)) {  /* POLLOUT - writable if space available */
            uint32_t available = socket->pair->recv_size -
                ((socket->pair->recv_head + socket->pair->recv_size -
                  socket->pair->recv_tail) % socket->pair->recv_size);
            if (available > 0) {
                ready |= 0x4;
            }
        }
    }

    return ready;
}
