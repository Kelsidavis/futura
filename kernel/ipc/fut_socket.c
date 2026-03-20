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
#include "../../include/kernel/fut_task.h"
#include "../../include/kernel/fut_thread.h"
#include "../../include/kernel/fut_waitq.h"
#include "../../include/kernel/fut_sched.h"
#include "../../include/kernel/fut_timer.h"
#include <kernel/errno.h>

#include <kernel/kprintf.h>
#include <kernel/debug_config.h>

/* Socket debugging (controlled via debug_config.h) */
#if SOCKET_DEBUG
#define SOCKET_LOG(...) fut_printf(__VA_ARGS__)
#else
#define SOCKET_LOG(...) ((void)0)
#endif

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

static inline int socket_memcmp(const void *s1, const void *s2, size_t n) {
    const unsigned char *a = (const unsigned char *)s1;
    const unsigned char *b = (const unsigned char *)s2;
    while (n--) {
        if (*a != *b) return (int)*a - (int)*b;
        a++; b++;
    }
    return 0;
}

/* Use our implementations */
#define strlen(s)         socket_strlen(s)
#define strcmp(s1,s2)     socket_strcmp(s1, s2)
#define strcpy(s1,s2)     socket_strcpy(s1, s2)
#define memset(s,c,n)     socket_memset(s, c, n)
#define memcpy(s1,s2,n)   socket_memcpy(s1, s2, n)
#define memcmp(s1,s2,n)   socket_memcmp(s1, s2, n)

/* ============================================================
 *   Socket timeout support (SO_RCVTIMEO / SO_SNDTIMEO)
 * ============================================================ */

typedef struct sock_timeout_ctx {
    fut_thread_t     *thread;
    fut_waitq_t      *waitq;
    fut_spinlock_t   *lock;
    bool              fired;   /* set by callback to indicate timeout */
} sock_timeout_ctx_t;

/* Timer callback: remove thread from waitq and wake it with timeout flag */
static void sock_timeout_callback(void *arg) {
    sock_timeout_ctx_t *ctx = (sock_timeout_ctx_t *)arg;
    fut_thread_t *thread = ctx->thread;
    fut_waitq_t  *wq     = ctx->waitq;

    fut_spinlock_acquire(ctx->lock);

    /* Walk the wait queue and remove our thread if still there */
    fut_thread_t *cur  = wq->head;
    fut_thread_t *prev = NULL;
    bool found = false;

    while (cur) {
        if (cur == thread) {
            if (prev) prev->wait_next = cur->wait_next;
            else      wq->head = cur->wait_next;
            if (wq->tail == cur) wq->tail = prev;
            cur->wait_next = NULL;
            found = true;
            break;
        }
        prev = cur;
        cur  = cur->wait_next;
    }

    if (found) {
        ctx->fired = true;
        thread->state = FUT_THREAD_READY;
        fut_sched_add_thread(thread);
    }

    fut_spinlock_release(ctx->lock);
}

/**
 * socket_pair_cleanup - Free all resources allocated for a socket pair
 *
 * Safely frees all buffers and wait queues associated with a socket pair.
 * Handles partial initialization (NULL-safe for all fields).
 *
 * @param pair Socket pair to clean up (may be NULL)
 */
static inline void socket_pair_cleanup(fut_socket_pair_t *pair) {
    if (!pair) return;
    if (pair->send_waitq) fut_free(pair->send_waitq);
    if (pair->recv_waitq) fut_free(pair->recv_waitq);
    if (pair->send_buf) fut_free(pair->send_buf);
    if (pair->recv_buf) fut_free(pair->recv_buf);
    fut_free(pair);
}

/* ============================================================
 *   Socket Registry (global)
 * ============================================================ */

#define FUT_SOCKET_MAX 256
static fut_socket_t *socket_registry[FUT_SOCKET_MAX];
static volatile uint32_t socket_next_id = 1;
static fut_spinlock_t socket_lock;

/**
 * fut_socket_foreach - Iterate over all live (non-closed) sockets.
 *
 * Calls @cb for each socket in the registry that is not NULL and not
 * in FUT_SOCK_CLOSED state.  The spinlock is held for the minimum time
 * needed to snapshot each pointer; the callback runs unlocked so it
 * may safely read (but not modify) socket fields.
 */
void fut_socket_foreach(void (*cb)(const fut_socket_t *, void *), void *arg) {
    for (int i = 0; i < FUT_SOCKET_MAX; i++) {
        fut_spinlock_acquire(&socket_lock);
        fut_socket_t *s = socket_registry[i];
        int ref_ok = 0;
        if (s) {
            /* Validate pointer is in kernel VA range before any dereference.
             * Garbage/user-space pointers would fault in fut_socket_ref when
             * accessing s->magic (e.g. ptr=0x500000000 faults at +320 offset). */
            if ((uintptr_t)(void *)s < 0xFFFF800000000000ULL) {
                fut_printf("[SOCKET] Clearing out-of-range registry slot %d (ptr=%p)\n",
                           i, (void *)s);
                socket_registry[i] = NULL;
            } else {
                ref_ok = fut_socket_ref(s);
                if (!ref_ok) {
                    /* Stale/corrupted registry entry — clear it */
                    fut_printf("[SOCKET] Clearing corrupted registry slot %d (addr=%p)\n",
                               i, (void *)s);
                    socket_registry[i] = NULL;
                }
            }
        }
        fut_spinlock_release(&socket_lock);
        if (!s || !ref_ok) continue;
        if (s->state != FUT_SOCK_CLOSED)
            cb(s, arg);
        fut_socket_unref(s);
    }
}

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
    SOCKET_LOG("[SOCKET] Socket subsystem initialized (max %d sockets)\n", FUT_SOCKET_MAX);
}

/* ============================================================
 *   Socket Creation and Lifecycle
 * ============================================================ */

/**
 * Create a new socket object in CREATED state.
 */
fut_socket_t *fut_socket_create(int family, int type) {
    /* Supported families: AF_UNIX (full), AF_INET/AF_INET6 (stub — no TCP/IP stack) */
    if (family != AF_UNIX && family != AF_INET && family != AF_INET6) {
        return NULL;
    }
    /* Support SOCK_STREAM, SOCK_DGRAM, and SOCK_SEQPACKET for AF_UNIX.
     * AF_INET/AF_INET6 support SOCK_STREAM and SOCK_DGRAM only. */
    if (type != SOCK_STREAM && type != SOCK_DGRAM && type != SOCK_SEQPACKET) {
        return NULL;
    }

    fut_socket_t *socket = fut_malloc(sizeof(fut_socket_t));
    if (!socket) {
        return NULL;
    }

    memset(socket, 0, sizeof(*socket));
    socket->magic = FUT_SOCKET_MAGIC;
    socket->state = FUT_SOCK_CREATED;
    socket->address_family = family;
    socket->socket_type = type;
    socket->refcount = 1;
    socket->socket_id = __atomic_fetch_add(&socket_next_id, 1, __ATOMIC_RELAXED);
    socket->shutdown_rd = false;
    socket->shutdown_wr = false;
    /* SO_SNDBUF / SO_RCVBUF: Linux doubles the requested value; default = 2×BUFSIZE */
    socket->sndbuf = 2 * FUT_SOCKET_BUFSIZE;
    socket->rcvbuf = 2 * FUT_SOCKET_BUFSIZE;

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

    SOCKET_LOG("[SOCKET] Created socket id=%u family=%d type=%d\n",
               socket->socket_id, family, type);
    return socket;
}

/**
 * Reference a socket (increment refcount).
 * Returns 1 on success, 0 if the socket is invalid or corrupted.
 */
int fut_socket_ref(fut_socket_t *socket) {
    if (!socket) {
        return 0;
    }
    /* Guard against garbage pointers before any dereference. */
    if ((uintptr_t)(void *)socket < 0xFFFF800000000000ULL) {
        fut_printf("[SOCKET-ERROR] Socket ref on non-kernel ptr (addr=%p)\n",
                   (void *)socket);
        return 0;
    }
    if (socket->magic != FUT_SOCKET_MAGIC) {
        fut_printf("[SOCKET-ERROR] Socket ref on invalid/freed struct (magic=0x%08x addr=%p)\n",
                   socket->magic, (void *)socket);
        return 0;
    }
    if (socket->refcount >= 1000) {
        fut_printf("[SOCKET-ERROR] Socket %u refcount overflow: %lu\n",
                   socket->socket_id, socket->refcount);
        return 0;
    }
    __atomic_add_fetch(&socket->refcount, 1, __ATOMIC_ACQ_REL);
    return 1;
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

    uint64_t remaining = __atomic_sub_fetch(&socket->refcount, 1, __ATOMIC_ACQ_REL);
    if (remaining == 0) {
        /* Free socket resources */
        SOCKET_LOG("[SOCKET] Freeing socket id=%u\n", socket->socket_id);

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
        /* Release pair buffer with refcounting.
         * Both socket->pair and socket->pair_reverse reference pair buffers
         * that are shared with the peer socket (pair_fwd->refcount starts at 2).
         * Only free when refcount reaches 0 to prevent use-after-free when the
         * peer socket closes concurrently or sequentially. */
        if (socket->pair) {
            uint32_t pair_remaining = __atomic_sub_fetch(&socket->pair->refcount, 1,
                                                         __ATOMIC_ACQ_REL);
            if (pair_remaining == 0) {
                /* Drop references on any in-flight FDs in the FD queue */
                while (socket->pair->fd_queue_count > 0) {
                    uint32_t head = socket->pair->fd_queue_head;
                    struct fut_file *f = socket->pair->fd_queue[head];
                    socket->pair->fd_queue[head] = NULL;
                    socket->pair->fd_queue_head = (head + 1) % FUT_SOCKET_FD_QUEUE_MAX;
                    socket->pair->fd_queue_count--;
                    if (f && f->refcount > 0) __atomic_sub_fetch(&f->refcount, 1, __ATOMIC_ACQ_REL);
                }
                if (socket->pair->send_buf)  fut_free(socket->pair->send_buf);
                if (socket->pair->recv_buf)  fut_free(socket->pair->recv_buf);
                if (socket->pair->send_waitq) fut_free(socket->pair->send_waitq);
                if (socket->pair->recv_waitq) fut_free(socket->pair->recv_waitq);
                fut_free(socket->pair);
            }
        }
        /* Release the reverse-pair reference too (the buffer that the peer sends into) */
        if (socket->pair_reverse) {
            uint32_t rev_remaining = __atomic_sub_fetch(&socket->pair_reverse->refcount, 1,
                                                        __ATOMIC_ACQ_REL);
            if (rev_remaining == 0) {
                while (socket->pair_reverse->fd_queue_count > 0) {
                    uint32_t head = socket->pair_reverse->fd_queue_head;
                    struct fut_file *f = socket->pair_reverse->fd_queue[head];
                    socket->pair_reverse->fd_queue[head] = NULL;
                    socket->pair_reverse->fd_queue_head = (head + 1) % FUT_SOCKET_FD_QUEUE_MAX;
                    socket->pair_reverse->fd_queue_count--;
                    if (f && f->refcount > 0) __atomic_sub_fetch(&f->refcount, 1, __ATOMIC_ACQ_REL);
                }
                if (socket->pair_reverse->send_buf)  fut_free(socket->pair_reverse->send_buf);
                if (socket->pair_reverse->recv_buf)  fut_free(socket->pair_reverse->recv_buf);
                if (socket->pair_reverse->send_waitq) fut_free(socket->pair_reverse->send_waitq);
                if (socket->pair_reverse->recv_waitq) fut_free(socket->pair_reverse->recv_waitq);
                fut_free(socket->pair_reverse);
            }
        }
        if (socket->close_waitq) {
            fut_free(socket->close_waitq);
        }

        if (socket->dgram_queue) {
            if (socket->dgram_queue->recv_waitq)
                fut_free(socket->dgram_queue->recv_waitq);
            fut_free(socket->dgram_queue);
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

        /* Poison magic before free to catch use-after-free */
        socket->magic = 0;
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
int fut_socket_bind(fut_socket_t *socket, const char *path, size_t path_len) {
    if (!socket || !path || socket->state != FUT_SOCK_CREATED) {
        return -EINVAL;
    }

    /* For filesystem paths use strlen; path_len passed from caller for abstract sockets */
    if (path_len == 0 || path_len > 108) {
        return -EINVAL;
    }

    bool is_abstract = (path[0] == '\0' && path_len > 1);

    /* Check if path already bound (allow SO_REUSEADDR-like behavior for unix sockets)
     * Use memcmp to correctly handle abstract paths that contain embedded NUL bytes. */
    fut_socket_t *old_socket = NULL;
    fut_spinlock_acquire(&socket_lock);
    for (int i = 0; i < FUT_SOCKET_MAX; i++) {
        fut_socket_t *s = socket_registry[i];
        if (s && s->bound_path && s->bound_path_len == path_len &&
            memcmp(s->bound_path, path, path_len) == 0) {
            SOCKET_LOG("[SOCKET-BIND-CHECK] Found socket %u with same path: state=%d refcount=%d\n",
                       s->socket_id, s->state, s->refcount);
            if (s->refcount > 1) {
                fut_spinlock_release(&socket_lock);
                return -EADDRINUSE;
            }
            old_socket = s;
        }
    }
    fut_spinlock_release(&socket_lock);

    /* Allocate and store bound path (include full path_len bytes, NUL-terminate after) */
    socket->bound_path = fut_malloc(path_len + 1);
    if (!socket->bound_path) {
        return -ENOMEM;
    }
    memcpy(socket->bound_path, path, path_len);
    socket->bound_path[path_len] = '\0';
    socket->bound_path_len = (uint16_t)path_len;

    /* Create VFS inode for filesystem paths only (not abstract sockets) */
    if (!is_abstract && !old_socket) {
        struct fut_vnode *inode = fut_vfs_create_socket(path);
        if (!inode) {
            SOCKET_LOG("[SOCKET] Socket %u VFS inode creation failed (non-fatal), path: %s\n",
                       socket->socket_id, path);
        } else {
            fut_vnode_ref(inode);  /* socket holds its own reference; VFS tree has refcount=1 */
            socket->path_vnode = inode;
            SOCKET_LOG("[SOCKET] Socket %u created VFS inode, path: %s\n",
                       socket->socket_id, path);
        }
    }

    /* Allocate datagram receive queue for SOCK_DGRAM sockets */
    if (socket->socket_type == SOCK_DGRAM && !socket->dgram_queue) {
        fut_dgram_queue_t *dq = fut_malloc(sizeof(fut_dgram_queue_t));
        if (!dq) {
            fut_free(socket->bound_path);
            socket->bound_path = NULL;
            socket->bound_path_len = 0;
            return -ENOMEM;
        }
        memset(dq, 0, sizeof(*dq));
        fut_spinlock_init(&dq->lock);
        dq->recv_waitq = fut_malloc(sizeof(fut_waitq_t));
        if (!dq->recv_waitq) {
            fut_free(dq);
            fut_free(socket->bound_path);
            socket->bound_path = NULL;
            socket->bound_path_len = 0;
            return -ENOMEM;
        }
        fut_waitq_init(dq->recv_waitq);
        socket->dgram_queue = dq;
    }

    socket->state = FUT_SOCK_BOUND;
    SOCKET_LOG("[SOCKET] Socket %u bound (abstract=%d, len=%zu)\n",
               socket->socket_id, (int)is_abstract, path_len);
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
        return -EINVAL;
    }

    fut_socket_listener_t *listener = fut_malloc(sizeof(fut_socket_listener_t));
    if (!listener) {
        return -ENOMEM;
    }

    memset(listener, 0, sizeof(*listener));
    listener->backlog = (backlog > 0) ? backlog : 1;
    if (listener->backlog > FUT_SOCKET_QUEUE_MAX) {
        listener->backlog = FUT_SOCKET_QUEUE_MAX;
    }

    listener->accept_waitq = fut_malloc(sizeof(fut_waitq_t));
    if (!listener->accept_waitq) {
        fut_free(listener);
        return -ENOMEM;
    }
    fut_waitq_init(listener->accept_waitq);

    socket->listener = listener;
    socket->state = FUT_SOCK_LISTENING;
    SOCKET_LOG("[SOCKET] Socket %u now listening (backlog=%d)\n",
               socket->socket_id, listener->backlog);
    return 0;
}

/**
 * Accept pending connection from listen queue.
 */
int fut_socket_accept(fut_socket_t *listener, fut_socket_t **out_socket) {
    if (!listener || !out_socket || !listener->listener) {
        return -EINVAL;
    }

    fut_socket_listener_t *queue = listener->listener;

    /* Try to get pending connection */
    if (queue->queue_count == 0) {
        /* No pending connections */
        return -EAGAIN;  /* Caller must retry or use blocking I/O */
    }

    /* Dequeue pending connection */
    fut_socket_connection_entry_t *entry =
        &queue->queue[queue->queue_head];
    fut_socket_t *peer = entry->peer_socket;  /* The connecting (client) socket */

    queue->queue_head = (queue->queue_head + 1) % FUT_SOCKET_QUEUE_MAX;
    queue->queue_count--;

    /* Peer becomes connected, create TWO bidirectional pairs for proper communication */
    if (!peer->pair) {
        /* PAIR 1: peer → listener (peer sends, listener receives) */
        fut_socket_pair_t *pair_forward = fut_malloc(sizeof(fut_socket_pair_t));
        if (!pair_forward) {
            fut_socket_unref(peer);
            return -ENOMEM;
        }

        memset(pair_forward, 0, sizeof(*pair_forward));
        pair_forward->send_buf = fut_malloc(FUT_SOCKET_BUFSIZE);
        pair_forward->recv_buf = fut_malloc(FUT_SOCKET_BUFSIZE);
        if (!pair_forward->send_buf || !pair_forward->recv_buf) {
            socket_pair_cleanup(pair_forward);
            fut_socket_unref(peer);
            return -ENOMEM;
        }

        pair_forward->send_size = FUT_SOCKET_BUFSIZE;
        pair_forward->recv_size = FUT_SOCKET_BUFSIZE;
        pair_forward->send_waitq = fut_malloc(sizeof(fut_waitq_t));
        pair_forward->recv_waitq = fut_malloc(sizeof(fut_waitq_t));
        if (!pair_forward->send_waitq || !pair_forward->recv_waitq) {
            socket_pair_cleanup(pair_forward);
            fut_socket_unref(peer);
            return -ENOMEM;
        }
        fut_waitq_init(pair_forward->send_waitq);
        fut_waitq_init(pair_forward->recv_waitq);
        pair_forward->refcount = 2;

        /* PAIR 2: listener → peer (listener sends, peer receives) */
        fut_socket_pair_t *pair_reverse = fut_malloc(sizeof(fut_socket_pair_t));
        if (!pair_reverse) {
            socket_pair_cleanup(pair_forward);
            fut_socket_unref(peer);
            return -ENOMEM;
        }

        memset(pair_reverse, 0, sizeof(*pair_reverse));
        pair_reverse->send_buf = fut_malloc(FUT_SOCKET_BUFSIZE);
        pair_reverse->recv_buf = fut_malloc(FUT_SOCKET_BUFSIZE);
        if (!pair_reverse->send_buf || !pair_reverse->recv_buf) {
            socket_pair_cleanup(pair_reverse);
            socket_pair_cleanup(pair_forward);
            fut_socket_unref(peer);
            return -ENOMEM;
        }

        pair_reverse->send_size = FUT_SOCKET_BUFSIZE;
        pair_reverse->recv_size = FUT_SOCKET_BUFSIZE;
        pair_reverse->send_waitq = fut_malloc(sizeof(fut_waitq_t));
        pair_reverse->recv_waitq = fut_malloc(sizeof(fut_waitq_t));
        if (!pair_reverse->send_waitq || !pair_reverse->recv_waitq) {
            socket_pair_cleanup(pair_reverse);
            socket_pair_cleanup(pair_forward);
            fut_socket_unref(peer);
            return -ENOMEM;
        }
        fut_waitq_init(pair_reverse->send_waitq);
        fut_waitq_init(pair_reverse->recv_waitq);
        pair_reverse->refcount = 2;

        /* Set up peer (client) socket for proper bidirectional communication */
        /* peer->pair = pair_forward means: peer SENDS via pair_forward
         * peer->pair_reverse = pair_reverse means: peer RECEIVES from pair_reverse */
        peer->pair = pair_forward;    /* client sends here */
        peer->pair_reverse = pair_reverse;  /* client receives from here */
        peer->is_accepted = false;  /* Client side */
        peer->state = FUT_SOCK_CONNECTED;
    }

    /* Create a NEW server-side socket for the accepted connection
     * This is critical: each side needs its own socket object with
     * pair/pair_reverse configured in opposite directions */
    fut_socket_t *accepted = fut_malloc(sizeof(fut_socket_t));
    if (!accepted) {
        fut_socket_unref(peer);
        return -ENOMEM;
    }

    memset(accepted, 0, sizeof(*accepted));
    accepted->magic = FUT_SOCKET_MAGIC;
    accepted->state = FUT_SOCK_CONNECTED;
    accepted->address_family = listener->address_family;
    accepted->socket_type = listener->socket_type;
    accepted->refcount = 1;
    accepted->socket_id = __atomic_fetch_add(&socket_next_id, 1, __ATOMIC_RELAXED);
    accepted->is_accepted = true;  /* Server side */
    accepted->shutdown_rd = false;
    accepted->shutdown_wr = false;

    /* Allocate wait queue for close operations */
    accepted->close_waitq = fut_malloc(sizeof(fut_waitq_t));
    if (!accepted->close_waitq) {
        fut_free(accepted);
        fut_socket_unref(peer);
        return -ENOMEM;
    }
    fut_waitq_init(accepted->close_waitq);

    /* Register in global socket table */
    fut_spinlock_acquire(&socket_lock);
    bool registered = false;
    for (int i = 0; i < FUT_SOCKET_MAX; i++) {
        if (!socket_registry[i]) {
            socket_registry[i] = accepted;
            registered = true;
            break;
        }
    }
    fut_spinlock_release(&socket_lock);

    if (!registered) {
        fut_free(accepted->close_waitq);
        fut_free(accepted);
        fut_socket_unref(peer);
        return -ENOMEM;  /* Socket table full */
    }

    /* Set up server (accepted) socket with OPPOSITE pair directions:
     * accepted->pair = pair_reverse means: server SENDS via pair_reverse (client receives)
     * accepted->pair_reverse = pair_forward means: server RECEIVES from pair_forward (client sends) */
    accepted->pair = peer->pair_reverse;  /* server sends here, client receives */
    accepted->pair_reverse = peer->pair;  /* server receives from here, client sends */

    /* SO_PEERCRED: server side gets the client's credentials (captured at connect() time) */
    accepted->peer_pid = entry->peer_pid;
    accepted->peer_uid = entry->peer_uid;
    accepted->peer_gid = entry->peer_gid;

    /* SO_PEERCRED: client side gets the server's credentials (current accepting task) */
    {
        fut_task_t *at = fut_task_current();
        peer->peer_pid = at ? at->pid : 0;
        peer->peer_uid = at ? at->uid : 0;
        peer->peer_gid = at ? at->gid : 0;
    }

    /* IMPORTANT: Listener socket REMAINS in LISTENING state!
     * Only the accepted peer becomes CONNECTED.
     * The listener must stay in LISTENING to accept more connections.
     * Do NOT set listener->pair or listener->state here.
     * The listener continues listening for new connections.
     */

    /* Set peer pointers so both sockets know about each other */
    peer->pair->peer = accepted;        /* client's send buffer points to server socket */
    peer->pair_reverse->peer = peer;    /* client's recv buffer points to client socket */

    SOCKET_LOG("[SOCKET] Socket %u accepted connection from %u, created server socket %u\n",
               listener->socket_id, peer->socket_id, accepted->socket_id);

    /* Wake up the connecting socket that's waiting in fut_socket_connect() */
    if (peer->connect_waitq) {
        SOCKET_LOG("[SOCKET] Waking up connecting socket %u\n", peer->socket_id);
        fut_waitq_wake_all(peer->connect_waitq);
    }

    /* Notify poll/epoll instances that were waiting for CONNECTING→CONNECTED */
    if (peer->connect_notify) {
        /* Propagate to the newly created pair so future I/O events also wake the watcher */
        peer->pair_reverse->epoll_notify = peer->connect_notify;
        fut_waitq_wake_one(peer->connect_notify);
        peer->connect_notify = NULL;
    }

    *out_socket = accepted;
    SOCKET_LOG("[SOCKET] Socket %u accepted connection from %u\n",
               listener->socket_id, peer->socket_id);
    return 0;
}

/* ============================================================
 *   Socket Connection
 * ============================================================ */

/**
 * Find listening socket by bound path.
 */
fut_socket_t *fut_socket_find_listener(const char *path, size_t path_len) {
    if (!path || path_len == 0) {
        return NULL;
    }

    fut_spinlock_acquire(&socket_lock);
    for (int i = 0; i < FUT_SOCKET_MAX; i++) {
        fut_socket_t *socket = socket_registry[i];
        if (!socket || (uintptr_t)(void *)socket < 0xFFFF800000000000ULL) {
            if (socket) socket_registry[i] = NULL;
            continue;
        }
        if (socket->magic == FUT_SOCKET_MAGIC &&
            socket->bound_path &&
            socket->bound_path_len == path_len &&
            memcmp(socket->bound_path, path, path_len) == 0 &&
            socket->state == FUT_SOCK_LISTENING) {
            if (!fut_socket_ref(socket)) {
                socket_registry[i] = NULL;
                continue;
            }
            fut_spinlock_release(&socket_lock);
            return socket;
        }
    }
    fut_spinlock_release(&socket_lock);
    return NULL;
}

/**
 * Connect to listening socket.
 * For blocking sockets, waits until accept() completes the connection.
 */
int fut_socket_connect(fut_socket_t *socket, const char *target_path, size_t path_len) {
    if (!socket || !target_path || path_len == 0) {
        return -EINVAL;
    }

    /* SOCK_DGRAM: connect() just stores the default peer address; no listener required */
    if (socket->socket_type == SOCK_DGRAM) {
        if (path_len > 108) return -EINVAL;
        __builtin_memcpy(socket->dgram_peer_path, target_path, path_len);
        socket->dgram_peer_path_len = (uint16_t)path_len;
        socket->state = FUT_SOCK_CONNECTED;
        SOCKET_LOG("[SOCKET] DGRAM socket %u connected to peer (path_len=%zu)\n",
                   socket->socket_id, path_len);
        return 0;
    }

    /* Find listening socket */
    fut_socket_t *listener = fut_socket_find_listener(target_path, path_len);
    if (!listener) {
        return -ECONNREFUSED;
    }

    /* Check if listener has space in backlog */
    fut_socket_listener_t *queue = listener->listener;
    if ((int)queue->queue_count >= queue->backlog) {
        fut_socket_unref(listener);
        return -ECONNREFUSED;
    }

    /* Allocate connect wait queue if needed (for blocking connect) */
    if (!socket->connect_waitq) {
        socket->connect_waitq = fut_malloc(sizeof(fut_waitq_t));
        if (!socket->connect_waitq) {
            fut_socket_unref(listener);
            return -ENOMEM;
        }
        fut_waitq_init(socket->connect_waitq);
    }

    /* Queue pending connection */
    uint32_t tail = (queue->queue_head + queue->queue_count) % FUT_SOCKET_QUEUE_MAX;
    queue->queue[tail].peer_socket = socket;
    queue->queue[tail].flags = 0;
    /* Skip high-resolution timestamp - it blocks during calibration on first use */
    queue->queue[tail].timestamp_ns = fut_get_ticks() * 10000000ULL;  /* ticks (10ms) -> ns */

    /* Capture connecting task credentials for SO_PEERCRED on the server side */
    {
        fut_task_t *ct = fut_task_current();
        queue->queue[tail].peer_pid = ct ? ct->pid : 0;
        queue->queue[tail].peer_uid = ct ? ct->uid : 0;
        queue->queue[tail].peer_gid = ct ? ct->gid : 0;
    }

    queue->queue_count++;

    socket->state = FUT_SOCK_CONNECTING;

    /* Wake up listener's accept queue so it can call accept() */
    fut_waitq_wake_one(queue->accept_waitq);

    /* Wake any epoll instance monitoring the listening socket */
    if (queue->epoll_notify) {
        fut_waitq_wake_one(queue->epoll_notify);
    }

    fut_socket_unref(listener);

    /* For Unix domain sockets, connect returns immediately after queueing.
     * The connection will be completed when the server calls accept().
     * I/O operations will wait for the socket to become connected.
     * This avoids deadlock when client and server are in the same address space. */
    SOCKET_LOG("[SOCKET] Socket %u connecting to %s (queued, returning immediately)\n", socket->socket_id, target_path);
    return 0;
}

/* ============================================================
 *   Socket I/O
 * ============================================================ */

/* Circular buffer helpers for SEQPACKET framing — lock must be held by caller */
static void circ_buf_write(fut_socket_pair_t *pair, const void *src, uint32_t len) {
    const uint8_t *s = (const uint8_t *)src;
    uint32_t sz = pair->recv_size, h = pair->recv_head;
    uint32_t fc = sz - h;
    if (len <= fc) {
        __builtin_memcpy(&pair->recv_buf[h], s, len);
    } else {
        __builtin_memcpy(&pair->recv_buf[h], s, fc);
        __builtin_memcpy(&pair->recv_buf[0], s + fc, len - fc);
    }
    pair->recv_head = (h + len) % sz;
}

static void circ_buf_read(fut_socket_pair_t *pair, void *dst, uint32_t len) {
    uint8_t *d = (uint8_t *)dst;
    uint32_t sz = pair->recv_size, t = pair->recv_tail;
    uint32_t fc = sz - t;
    if (len <= fc) {
        __builtin_memcpy(d, &pair->recv_buf[t], len);
    } else {
        __builtin_memcpy(d, &pair->recv_buf[t], fc);
        __builtin_memcpy(d + fc, &pair->recv_buf[0], len - fc);
    }
    pair->recv_tail = (t + len) % sz;
}

static void circ_buf_skip(fut_socket_pair_t *pair, uint32_t len) {
    pair->recv_tail = (pair->recv_tail + len) % pair->recv_size;
}

/**
 * Send data on connected socket.
 */
ssize_t fut_socket_send(fut_socket_t *socket, const void *buf, size_t len) {
    if (!socket || !buf) {
        return -EINVAL;
    }

    /* Wait for connection to complete if socket is still connecting */
    if (socket->state == FUT_SOCK_CONNECTING) {
        if (socket->flags & 0x800) {  /* O_NONBLOCK */
            return -EAGAIN;
        }
        /* Block until connection completes */
        if (socket->connect_waitq) {
            fut_waitq_sleep_locked(socket->connect_waitq, NULL, FUT_THREAD_BLOCKED);
        }
    }

    if (socket->state != FUT_SOCK_CONNECTED || !socket->pair) {
        return -ENOTCONN;
    }

    /* Phase 4: Enforce shutdown_wr flag */
    if (socket->shutdown_wr) {
        SOCKET_LOG("[SOCKET] Socket %u send blocked: write channel shutdown (SHUT_WR)\n",
                   socket->socket_id);
        return -EPIPE;  /* Broken pipe */
    }

    /* With separate socket objects for client and server, each socket's
     * pair is configured for the correct send direction:
     * - Client socket: pair = forward buffer (client→server)
     * - Server socket: pair = reverse buffer (server→client)
     * No heuristics needed - just use socket->pair directly */
    fut_socket_pair_t *pair = socket->pair;

    fut_spinlock_acquire(&pair->lock);

    if (!pair->peer) {
        fut_spinlock_release(&pair->lock);
        return -EPIPE;  /* Peer closed — broken pipe */
    }

    /* Block until send buffer has space (or socket is non-blocking) */
    uint32_t available = pair->recv_size -
        ((pair->recv_head + pair->recv_size - pair->recv_tail) % pair->recv_size);

    /* SEQPACKET: must write entire frame atomically — need space for 4-byte header + body */
    bool seqp = (socket->socket_type == SOCK_SEQPACKET);
    uint32_t seqp_needed = seqp ? (uint32_t)(4 + len) : 1u;
    if (seqp && seqp_needed > pair->recv_size - 1u) {
        fut_spinlock_release(&pair->lock);
        return -EMSGSIZE;
    }

    /* SO_SNDTIMEO: set up timer if a send timeout is configured */
    sock_timeout_ctx_t snd_tmo_ctx = {0};
    bool snd_has_timeout = (socket->sndtimeo_ms > 0);
    if (snd_has_timeout) {
        uint64_t ticks = socket->sndtimeo_ms / 10;
        if (socket->sndtimeo_ms % 10 != 0) ticks++;
        if (ticks == 0) ticks = 1;
        snd_tmo_ctx.thread = fut_thread_current();
        snd_tmo_ctx.waitq  = pair->send_waitq;
        snd_tmo_ctx.lock   = &pair->lock;
        snd_tmo_ctx.fired  = false;
        if (available < seqp_needed)
            fut_timer_start(ticks, sock_timeout_callback, &snd_tmo_ctx);
    }

    while (available < seqp_needed) {
        if (socket->flags & 0x800) {  /* O_NONBLOCK */
            if (snd_has_timeout) fut_timer_cancel(sock_timeout_callback, &snd_tmo_ctx);
            fut_spinlock_release(&pair->lock);
            return -EAGAIN;
        }
        /* Check for pending signals → EINTR */
        {
            fut_task_t *stask = fut_task_current();
            if (stask) {
                uint64_t pending = __atomic_load_n(&stask->pending_signals, __ATOMIC_ACQUIRE);
                fut_thread_t *scur_thr = fut_thread_current();
                uint64_t blocked = scur_thr ?
                    __atomic_load_n(&scur_thr->signal_mask, __ATOMIC_ACQUIRE) :
                    __atomic_load_n(&stask->signal_mask, __ATOMIC_ACQUIRE);
                if (pending & ~blocked) {
                    if (snd_has_timeout) fut_timer_cancel(sock_timeout_callback, &snd_tmo_ctx);
                    fut_spinlock_release(&pair->lock);
                    return -EINTR;
                }
            }
        }
        /* Blocking socket: wait for receiver to read data */
        fut_waitq_sleep_locked(pair->send_waitq, &pair->lock, FUT_THREAD_BLOCKED);
        /* When we wake up, reacquire the lock */
        fut_spinlock_acquire(&pair->lock);

        /* Timed out? */
        if (snd_has_timeout && snd_tmo_ctx.fired) {
            fut_spinlock_release(&pair->lock);
            return -EAGAIN;
        }

        /* Check again - peer might have closed while we were sleeping */
        if (!pair->peer) {
            if (snd_has_timeout) fut_timer_cancel(sock_timeout_callback, &snd_tmo_ctx);
            fut_spinlock_release(&pair->lock);
            return -EPIPE;  /* Peer closed — broken pipe */
        }

        available = pair->recv_size -
            ((pair->recv_head + pair->recv_size - pair->recv_tail) % pair->recv_size);
    }

    if (snd_has_timeout) fut_timer_cancel(sock_timeout_callback, &snd_tmo_ctx);

    if (seqp) {
        /* SEQPACKET: write 4-byte little-endian length header then message body */
        uint32_t ml = (uint32_t)len;
        uint8_t hdr[4] = { (uint8_t)ml, (uint8_t)(ml >> 8),
                           (uint8_t)(ml >> 16), (uint8_t)(ml >> 24) };
        circ_buf_write(pair, hdr, 4);
        circ_buf_write(pair, buf, (uint32_t)len);
    } else {
        size_t to_write = (len > available) ? available : len;

        /* Handle circular buffer wrap-around with two-chunk copy */
        size_t first_chunk = pair->recv_size - pair->recv_head;
        if (to_write <= first_chunk) {
            memcpy(&pair->recv_buf[pair->recv_head], buf, to_write);
        } else {
            memcpy(&pair->recv_buf[pair->recv_head], buf, first_chunk);
            memcpy(&pair->recv_buf[0], (const char *)buf + first_chunk, to_write - first_chunk);
        }
        pair->recv_head = (pair->recv_head + to_write) % pair->recv_size;
        len = to_write;  /* report actual bytes written for stream */
    }

    /* Wake receiver */
    fut_waitq_wake_one(pair->recv_waitq);

    /* Wake any epoll instance monitoring the receiving socket */
    if (pair->epoll_notify) {
        fut_waitq_wake_one(pair->epoll_notify);
    }

    fut_spinlock_release(&pair->lock);

    SOCKET_LOG("[SOCKET] Socket %u sent %zu bytes\n", socket->socket_id, len);
    return (ssize_t)len;
}

/**
 * Receive data from connected socket.
 */
ssize_t fut_socket_recv(fut_socket_t *socket, void *buf, size_t len) {
    if (!socket || !buf) {
        return -EINVAL;
    }

    /* Wait for connection to complete if socket is still connecting */
    if (socket->state == FUT_SOCK_CONNECTING) {
        if (socket->flags & 0x800) {  /* O_NONBLOCK */
            return -EAGAIN;
        }
        /* Block until connection completes */
        if (socket->connect_waitq) {
            fut_waitq_sleep_locked(socket->connect_waitq, NULL, FUT_THREAD_BLOCKED);
        }
    }

    if (socket->state != FUT_SOCK_CONNECTED || !socket->pair) {
        return -ENOTCONN;
    }

    /* Phase 4: Enforce shutdown_rd flag */
    if (socket->shutdown_rd) {
        SOCKET_LOG("[SOCKET] Socket %u recv blocked: read channel shutdown (SHUT_RD)\n",
                   socket->socket_id);
        return 0;  /* EOF - no more data */
    }

    /* With separate socket objects for client and server, each socket's
     * pair_reverse is configured for the correct receive direction:
     * - Client socket: pair_reverse = reverse buffer (receives server→client)
     * - Server socket: pair_reverse = forward buffer (receives client→server)
     * No heuristics needed - just use socket->pair_reverse directly */
    if (!socket->pair_reverse) {
        return -EINVAL;  /* Socket not properly connected */
    }
    fut_socket_pair_t *pair = socket->pair_reverse;

    fut_spinlock_acquire(&pair->lock);

    /* Check for data first, then peer status.
     * Must return buffered data even after peer close. */
    uint32_t available = (pair->recv_head + pair->recv_size - pair->recv_tail) %
                         pair->recv_size;

    /* EOF: peer closed AND no buffered data */
    if (!pair->peer && available == 0) {
        fut_spinlock_release(&pair->lock);
        return 0;  /* EOF */
    }

    /* SO_RCVTIMEO: set up timer if a receive timeout is configured */
    sock_timeout_ctx_t rcv_tmo_ctx = {0};
    bool rcv_has_timeout = (socket->rcvtimeo_ms > 0);
    if (rcv_has_timeout) {
        uint64_t ticks = socket->rcvtimeo_ms / 10;
        if (socket->rcvtimeo_ms % 10 != 0) ticks++;
        if (ticks == 0) ticks = 1;
        rcv_tmo_ctx.thread = fut_thread_current();
        rcv_tmo_ctx.waitq  = pair->recv_waitq;
        rcv_tmo_ctx.lock   = &pair->lock;
        rcv_tmo_ctx.fired  = false;
        if (available == 0)
            fut_timer_start(ticks, sock_timeout_callback, &rcv_tmo_ctx);
    }

    while (available == 0) {
        if (socket->flags & 0x800) {  /* O_NONBLOCK */
            if (rcv_has_timeout) fut_timer_cancel(sock_timeout_callback, &rcv_tmo_ctx);
            fut_spinlock_release(&pair->lock);
            return -EAGAIN;
        }
        /* Check for pending signals → EINTR */
        {
            fut_task_t *stask = fut_task_current();
            if (stask) {
                uint64_t pending = __atomic_load_n(&stask->pending_signals, __ATOMIC_ACQUIRE);
                fut_thread_t *scur_thr = fut_thread_current();
                uint64_t blocked = scur_thr ?
                    __atomic_load_n(&scur_thr->signal_mask, __ATOMIC_ACQUIRE) :
                    __atomic_load_n(&stask->signal_mask, __ATOMIC_ACQUIRE);
                if (pending & ~blocked) {
                    if (rcv_has_timeout) fut_timer_cancel(sock_timeout_callback, &rcv_tmo_ctx);
                    fut_spinlock_release(&pair->lock);
                    return -EINTR;
                }
            }
        }
        /* Blocking socket: wait for sender to write data */
        fut_waitq_sleep_locked(pair->recv_waitq, &pair->lock, FUT_THREAD_BLOCKED);
        /* When we wake up, reacquire the lock */
        fut_spinlock_acquire(&pair->lock);

        /* Timed out? */
        if (rcv_has_timeout && rcv_tmo_ctx.fired) {
            fut_spinlock_release(&pair->lock);
            return -EAGAIN;
        }

        /* Recompute available data, then check peer status */
        available = (pair->recv_head + pair->recv_size - pair->recv_tail) %
                    pair->recv_size;

        /* EOF: peer closed AND no buffered data */
        if (!pair->peer && available == 0) {
            if (rcv_has_timeout) fut_timer_cancel(sock_timeout_callback, &rcv_tmo_ctx);
            fut_spinlock_release(&pair->lock);
            return 0;
        }
    }

    if (rcv_has_timeout) fut_timer_cancel(sock_timeout_callback, &rcv_tmo_ctx);

    size_t to_read;
    if (socket->socket_type == SOCK_SEQPACKET) {
        /* SEQPACKET: read 4-byte frame header, then exactly one message */
        uint8_t hdr[4];
        circ_buf_read(pair, hdr, 4);
        uint32_t msglen = (uint32_t)hdr[0] | ((uint32_t)hdr[1] << 8)
                        | ((uint32_t)hdr[2] << 16) | ((uint32_t)hdr[3] << 24);
        to_read = (len < (size_t)msglen) ? len : (size_t)msglen;
        circ_buf_read(pair, buf, (uint32_t)to_read);
        if (to_read < (size_t)msglen)
            circ_buf_skip(pair, msglen - (uint32_t)to_read);
    } else {
        to_read = (len > available) ? available : len;
        /* Handle circular buffer wrap-around with two-chunk copy */
        size_t first_chunk = pair->recv_size - pair->recv_tail;
        if (to_read <= first_chunk) {
            memcpy(buf, &pair->recv_buf[pair->recv_tail], to_read);
        } else {
            memcpy(buf, &pair->recv_buf[pair->recv_tail], first_chunk);
            memcpy((char *)buf + first_chunk, &pair->recv_buf[0], to_read - first_chunk);
        }
        pair->recv_tail = (pair->recv_tail + to_read) % pair->recv_size;
    }

    /* Wake sender */
    fut_waitq_wake_one(pair->send_waitq);
    /* Wake epoll on the sending socket (EPOLLOUT — space available) */
    if (pair->epoll_notify)
        fut_waitq_wake_one(pair->epoll_notify);

    fut_spinlock_release(&pair->lock);

    SOCKET_LOG("[SOCKET] Socket %u received %zu bytes\n", socket->socket_id, to_read);
    return (ssize_t)to_read;
}

/**
 * Peek at data on connected socket (MSG_PEEK: read without consuming).
 */
ssize_t fut_socket_recv_peek(fut_socket_t *socket, void *buf, size_t len) {
    if (!socket || !buf) return -EINVAL;
    if (socket->state != FUT_SOCK_CONNECTED || !socket->pair_reverse)
        return -ENOTCONN;
    if (socket->shutdown_rd) return 0;

    fut_socket_pair_t *pair = socket->pair_reverse;
    fut_spinlock_acquire(&pair->lock);

    uint32_t available = (pair->recv_head + pair->recv_size - pair->recv_tail) %
                         pair->recv_size;

    if (!pair->peer && available == 0) {
        fut_spinlock_release(&pair->lock);
        return 0;  /* EOF */
    }

    if (available == 0) {
        if (socket->flags & 0x800) {  /* O_NONBLOCK */
            fut_spinlock_release(&pair->lock);
            return -EAGAIN;
        }
        /* Block until data arrives */
        fut_waitq_sleep_locked(pair->recv_waitq, &pair->lock, FUT_THREAD_BLOCKED);
        fut_spinlock_acquire(&pair->lock);
        available = (pair->recv_head + pair->recv_size - pair->recv_tail) %
                    pair->recv_size;
        if (!pair->peer && available == 0) {
            fut_spinlock_release(&pair->lock);
            return 0;
        }
        if (available == 0) {
            fut_spinlock_release(&pair->lock);
            return -EAGAIN;
        }
    }

    size_t to_read;
    if (socket->socket_type == SOCK_SEQPACKET) {
        /* SEQPACKET peek: read 4-byte header from temp position, then peek data */
        uint32_t t = pair->recv_tail, sz = pair->recv_size;
        uint8_t hdr[4];
        for (int i = 0; i < 4; i++) { hdr[i] = pair->recv_buf[t]; t = (t + 1) % sz; }
        uint32_t msglen = (uint32_t)hdr[0] | ((uint32_t)hdr[1] << 8)
                        | ((uint32_t)hdr[2] << 16) | ((uint32_t)hdr[3] << 24);
        to_read = (len < (size_t)msglen) ? len : (size_t)msglen;
        /* Copy data from t without advancing recv_tail */
        uint32_t fc = sz - t;
        if (to_read <= fc) {
            memcpy(buf, &pair->recv_buf[t], to_read);
        } else {
            memcpy(buf, &pair->recv_buf[t], fc);
            memcpy((char *)buf + fc, &pair->recv_buf[0], to_read - fc);
        }
    } else {
        to_read = (len > available) ? available : len;
        /* Handle circular buffer wrap-around with two-chunk copy */
        size_t first_chunk = pair->recv_size - pair->recv_tail;

        /* Copy data but do NOT advance recv_tail — data stays in buffer */
        if (to_read <= first_chunk) {
            memcpy(buf, &pair->recv_buf[pair->recv_tail], to_read);
        } else {
            memcpy(buf, &pair->recv_buf[pair->recv_tail], first_chunk);
            memcpy((char *)buf + first_chunk, &pair->recv_buf[0], to_read - first_chunk);
        }
    }

    fut_spinlock_release(&pair->lock);
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
        return -EINVAL;
    }

    socket->state = FUT_SOCK_CLOSED;

    /* Nullify peer pointers under lock so send/recv see the close atomically */
    if (socket->pair) {
        fut_spinlock_acquire(&socket->pair->lock);
        socket->pair->peer = NULL;
        fut_spinlock_release(&socket->pair->lock);
    }
    if (socket->pair_reverse) {
        fut_spinlock_acquire(&socket->pair_reverse->lock);
        socket->pair_reverse->peer = NULL;
        fut_spinlock_release(&socket->pair_reverse->lock);
    }

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
    if (socket->pair_reverse) {
        if (socket->pair_reverse->send_waitq) {
            fut_waitq_wake_all(socket->pair_reverse->send_waitq);
        }
        if (socket->pair_reverse->recv_waitq) {
            fut_waitq_wake_all(socket->pair_reverse->recv_waitq);
        }
    }

    /* Wake epoll instances monitoring this socket or its peer (EPOLLHUP) */
    if (socket->pair && socket->pair->epoll_notify)
        fut_waitq_wake_one(socket->pair->epoll_notify);
    if (socket->pair_reverse && socket->pair_reverse->epoll_notify)
        fut_waitq_wake_one(socket->pair_reverse->epoll_notify);

    SOCKET_LOG("[SOCKET] Socket %u closed\n", socket->socket_id);
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
    } else if (socket->state == FUT_SOCK_CONNECTED && socket->pair && socket->pair_reverse) {
        /* Check for peer closure → POLLHUP (always reported) */
        if (!socket->pair_reverse->peer) {
            ready |= 0x10;  /* POLLHUP */
            ready |= 0x1;   /* POLLIN (EOF is readable) */
        }
        if ((events & 0x1)) {  /* POLLIN - readable if data available in pair_reverse */
            if (socket->shutdown_rd) {
                ready |= 0x1;
            } else {
                uint32_t recv_available = (socket->pair_reverse->recv_head + socket->pair_reverse->recv_size -
                                           socket->pair_reverse->recv_tail) % socket->pair_reverse->recv_size;
                if (recv_available > 0) {
                    ready |= 0x1;
                }
            }
        }
        if ((events & 0x4)) {  /* POLLOUT - writable if space available in pair (send buffer) */
            /* If shutdown_wr is set, socket is never writable (send returns EPIPE) */
            if (!socket->shutdown_wr) {
                /* With separate sockets, we only check pair (our send direction) */
                uint32_t send_space = socket->pair->recv_size -
                    ((socket->pair->recv_head + socket->pair->recv_size -
                      socket->pair->recv_tail) % socket->pair->recv_size);
                if (send_space > 0) {
                    ready |= 0x4;
                }
            }
        }
    }

    return ready;
}

/**
 * Get number of bytes available for reading from socket (for FIONREAD ioctl).
 *
 * @param sockfd Socket file descriptor
 * @return Number of bytes available, or -1 on error
 */
int fut_socket_bytes_available(int sockfd) {
    /* Get socket from file descriptor */
    extern fut_socket_t *get_socket_from_fd(int fd);
    fut_socket_t *socket = get_socket_from_fd(sockfd);

    if (!socket) {
        return -1;
    }

    /* Only connected sockets have data to read */
    if (socket->state != FUT_SOCK_CONNECTED || !socket->pair_reverse) {
        return 0;
    }

    /* Calculate bytes available in receive buffer
     * pair_reverse points to the socket pair that represents our receive direction */
    fut_socket_pair_t *recv_pair = socket->pair_reverse;
    uint32_t bytes_available = (recv_pair->recv_head + recv_pair->recv_size -
                                recv_pair->recv_tail) % recv_pair->recv_size;

    return (int)bytes_available;
}

/* ============================================================
 *   SOCK_DGRAM Support
 * ============================================================ */

/**
 * Find a socket bound to the given path regardless of state.
 * Used for SOCK_DGRAM delivery.
 */
fut_socket_t *fut_socket_find_bound(const char *path, size_t path_len) {
    if (!path || path_len == 0)
        return NULL;

    fut_spinlock_acquire(&socket_lock);
    for (int i = 0; i < FUT_SOCKET_MAX; i++) {
        fut_socket_t *s = socket_registry[i];
        if (!s || (uintptr_t)(void *)s < 0xFFFF800000000000ULL) {
            if (s) socket_registry[i] = NULL;
            continue;
        }
        if (s->magic == FUT_SOCKET_MAGIC &&
            s->bound_path &&
            s->bound_path_len == path_len &&
            memcmp(s->bound_path, path, path_len) == 0 &&
            (s->state == FUT_SOCK_BOUND || s->state == FUT_SOCK_CONNECTED)) {
            if (!fut_socket_ref(s)) {
                socket_registry[i] = NULL;
                continue;
            }
            fut_spinlock_release(&socket_lock);
            return s;
        }
    }
    fut_spinlock_release(&socket_lock);
    return NULL;
}

/**
 * Send datagram to socket bound at dest_path.
 */
ssize_t fut_socket_sendto_dgram(const char *dest_path, size_t dest_path_len,
                                const char *sender_path, size_t sender_path_len,
                                const void *data, size_t data_len) {
    if (!dest_path || dest_path_len == 0 || !data)
        return -EINVAL;
    if (data_len > FUT_DGRAM_DATA_MAX)
        return -EMSGSIZE;

    /* Find destination socket */
    fut_socket_t *dest = fut_socket_find_bound(dest_path, dest_path_len);
    if (!dest)
        return -ECONNREFUSED;

    if (!dest->dgram_queue) {
        fut_socket_unref(dest);
        return -ECONNREFUSED;
    }

    fut_dgram_queue_t *dq = dest->dgram_queue;
    fut_spinlock_acquire(&dq->lock);

    if (dq->count >= FUT_DGRAM_QUEUE_MAX) {
        fut_spinlock_release(&dq->lock);
        fut_socket_unref(dest);
        return -EAGAIN;  /* Receiver's queue full */
    }

    /* Enqueue message */
    uint32_t tail = (dq->head + dq->count) % FUT_DGRAM_QUEUE_MAX;
    fut_dgram_entry_t *entry = &dq->msgs[tail];

    /* Copy sender path */
    if (sender_path && sender_path_len > 0 && sender_path_len <= 108) {
        memcpy(entry->sender_path, sender_path, sender_path_len);
        entry->sender_path_len = (uint16_t)sender_path_len;
    } else {
        entry->sender_path[0] = '\0';
        entry->sender_path_len = 0;
    }

    memcpy(entry->data, data, data_len);
    entry->data_len = (uint16_t)data_len;
    dq->count++;

    /* Wake any blocked recvfrom */
    fut_waitq_wake_one(dq->recv_waitq);
    fut_spinlock_release(&dq->lock);

    fut_socket_unref(dest);
    return (ssize_t)data_len;
}

/**
 * Receive datagram from this socket's dgram_queue.
 */
ssize_t fut_socket_recvfrom_dgram(fut_socket_t *socket, void *buf, size_t len,
                                  char *sender_path_out, uint16_t *sender_path_len_out,
                                  size_t *actual_datagram_len_out) {
    if (!socket || !buf)
        return -EINVAL;
    if (!socket->dgram_queue)
        return -ENOTCONN;

    fut_dgram_queue_t *dq = socket->dgram_queue;
    fut_spinlock_acquire(&dq->lock);

    /* SO_RCVTIMEO: set up a one-shot timer if a receive timeout is configured */
    sock_timeout_ctx_t dg_tmo_ctx = {0};
    bool dg_has_timeout = (socket->rcvtimeo_ms > 0);
    if (dg_has_timeout && dq->count == 0) {
        uint64_t ticks = socket->rcvtimeo_ms / 10;
        if (socket->rcvtimeo_ms % 10 != 0) ticks++;
        if (ticks == 0) ticks = 1;
        dg_tmo_ctx.thread = fut_thread_current();
        dg_tmo_ctx.waitq  = dq->recv_waitq;
        dg_tmo_ctx.lock   = &dq->lock;
        dg_tmo_ctx.fired  = false;
        fut_timer_start(ticks, sock_timeout_callback, &dg_tmo_ctx);
    }

    while (dq->count == 0) {
        if (socket->flags & 0x800) {  /* O_NONBLOCK */
            if (dg_has_timeout) fut_timer_cancel(sock_timeout_callback, &dg_tmo_ctx);
            fut_spinlock_release(&dq->lock);
            return -EAGAIN;
        }
        /* Check for pending signals */
        {
            fut_task_t *t = fut_task_current();
            if (t) {
                uint64_t pending = __atomic_load_n(&t->pending_signals, __ATOMIC_ACQUIRE);
                fut_thread_t *thr = fut_thread_current();
                uint64_t blocked = thr ?
                    __atomic_load_n(&thr->signal_mask, __ATOMIC_ACQUIRE) :
                    __atomic_load_n(&t->signal_mask, __ATOMIC_ACQUIRE);
                if (pending & ~blocked) {
                    if (dg_has_timeout) fut_timer_cancel(sock_timeout_callback, &dg_tmo_ctx);
                    fut_spinlock_release(&dq->lock);
                    return -EINTR;
                }
            }
        }
        fut_waitq_sleep_locked(dq->recv_waitq, &dq->lock, FUT_THREAD_BLOCKED);
        fut_spinlock_acquire(&dq->lock);
        if (dg_has_timeout && dg_tmo_ctx.fired) {
            fut_spinlock_release(&dq->lock);
            return -EAGAIN;
        }
    }

    if (dg_has_timeout) fut_timer_cancel(sock_timeout_callback, &dg_tmo_ctx);

    fut_dgram_entry_t *entry = &dq->msgs[dq->head];
    size_t dgram_len = entry->data_len;
    size_t copy_len = (len < dgram_len) ? len : dgram_len;
    memcpy(buf, entry->data, copy_len);

    if (sender_path_out && sender_path_len_out) {
        if (entry->sender_path_len > 0)
            memcpy(sender_path_out, entry->sender_path, entry->sender_path_len);
        *sender_path_len_out = entry->sender_path_len;
    }

    if (actual_datagram_len_out)
        *actual_datagram_len_out = dgram_len;

    dq->head = (dq->head + 1) % FUT_DGRAM_QUEUE_MAX;
    dq->count--;
    fut_spinlock_release(&dq->lock);

    return (ssize_t)copy_len;
}

/**
 * Peek at the next datagram without consuming it (MSG_PEEK).
 * Same as fut_socket_recvfrom_dgram but leaves the datagram in the queue.
 */
ssize_t fut_socket_peek_dgram(fut_socket_t *socket, void *buf, size_t len,
                               char *sender_path_out, uint16_t *sender_path_len_out,
                               size_t *actual_datagram_len_out) {
    if (!socket || !buf)
        return -EINVAL;
    if (!socket->dgram_queue)
        return -ENOTCONN;

    fut_dgram_queue_t *dq = socket->dgram_queue;
    fut_spinlock_acquire(&dq->lock);

    if (dq->count == 0) {
        if (socket->flags & 0x800) { /* O_NONBLOCK */
            fut_spinlock_release(&dq->lock);
            return -EAGAIN;
        }
        /* Block until a datagram arrives */
        while (dq->count == 0) {
            fut_waitq_sleep_locked(dq->recv_waitq, &dq->lock, FUT_THREAD_BLOCKED);
            fut_spinlock_acquire(&dq->lock);
        }
    }

    fut_dgram_entry_t *entry = &dq->msgs[dq->head];
    size_t dgram_len = entry->data_len;
    size_t copy_len = (len < dgram_len) ? len : dgram_len;
    memcpy(buf, entry->data, copy_len);

    if (sender_path_out && sender_path_len_out) {
        if (entry->sender_path_len > 0)
            memcpy(sender_path_out, entry->sender_path, entry->sender_path_len);
        *sender_path_len_out = entry->sender_path_len;
    }
    if (actual_datagram_len_out)
        *actual_datagram_len_out = dgram_len;

    /* Do NOT advance head — MSG_PEEK leaves datagram in queue */
    fut_spinlock_release(&dq->lock);

    return (ssize_t)copy_len;
}
