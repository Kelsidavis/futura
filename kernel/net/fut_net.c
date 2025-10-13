// SPDX-License-Identifier: MPL-2.0
/*
 * fut_net.c - FuturaNet core socket layer
 *
 * Provides a minimal asynchronous frame socket with loopback delivery.
 * NIC drivers enqueue RX frames via fut_net_rx(), and sockets consume
 * frames through fut_net_recv() with simple wait queue semantics.
 */

#include <futura/net.h>

#include <kernel/errno.h>
#include <kernel/fut_memory.h>
#include <kernel/fut_sched.h>
#include <kernel/fut_waitq.h>

#include <stdbool.h>
#include <string.h>

extern void fut_printf(const char *fmt, ...);

/* Uncomment to force verbose tracing. */
/* #define DEBUG_NET 1 */

#ifdef DEBUG_NET
#define NETDBG(...) fut_printf(__VA_ARGS__)
#else
#define NETDBG(...) do { } while (0)
#endif

#define FUT_NET_QUEUE_DEPTH 8u
#define FUT_NET_MAX_FRAME   2048u

typedef struct fut_net_packet {
    size_t len;
    uint8_t *data;
} fut_net_packet_t;

struct fut_socket {
    uint16_t port;
    bool is_listener;
    bool closed;
    fut_handle_t handle;
    fut_spinlock_t lock;
    fut_waitq_t rx_wait;
    fut_net_packet_t queue[FUT_NET_QUEUE_DEPTH];
    size_t head;
    size_t tail;
    size_t count;
    struct fut_socket *next;
};

static bool net_initialized = false;
static fut_spinlock_t net_lock;
static struct fut_socket *socket_list = NULL;

/* Forward declarations provided by fut_net_dev.c */
void fut_net_dev_system_init(void);
fut_status_t fut_net_dev_tx_all(const void *frame, size_t len);

/* Forward declaration for loopback init */
void fut_net_loopback_init(void);

/* -------------------------------------------------------------------------- */
/* Helpers                                                                    */
/* -------------------------------------------------------------------------- */

static fut_status_t fut_net_enqueue_locked(struct fut_socket *sock,
                                           const void *buf,
                                           size_t len) {
    if (sock->count == FUT_NET_QUEUE_DEPTH) {
        return -ENOSPC;
    }

    uint8_t *copy = (uint8_t *)fut_malloc(len);
    if (!copy) {
        return -ENOMEM;
    }
    memcpy(copy, buf, len);

    sock->queue[sock->tail].data = copy;
    sock->queue[sock->tail].len = len;
    sock->tail = (sock->tail + 1u) % FUT_NET_QUEUE_DEPTH;
    sock->count++;
    return 0;
}

static void fut_net_wake(struct fut_socket *sock) {
    fut_waitq_wake_one(&sock->rx_wait);
}

static void fut_net_free_packets(struct fut_socket *sock) {
    for (size_t i = 0; i < FUT_NET_QUEUE_DEPTH; ++i) {
        if (sock->queue[i].data) {
            fut_free(sock->queue[i].data);
            sock->queue[i].data = NULL;
            sock->queue[i].len = 0;
        }
    }
    sock->head = 0;
    sock->tail = 0;
    sock->count = 0;
}

/* -------------------------------------------------------------------------- */
/* Public API                                                                 */
/* -------------------------------------------------------------------------- */

void fut_net_init(void) {
    if (net_initialized) {
        return;
    }

    fut_spinlock_init(&net_lock);
    fut_net_dev_system_init();
    fut_net_loopback_init();
    net_initialized = true;
    NETDBG("[net] subsystem initialized\n");
}

fut_status_t fut_net_listen(uint16_t port, fut_socket_t **out) {
    if (!out) {
        return -EINVAL;
    }
    fut_net_init();

    struct fut_socket *sock = (struct fut_socket *)fut_malloc(sizeof(*sock));
    if (!sock) {
        return -ENOMEM;
    }
    memset(sock, 0, sizeof(*sock));

    sock->port = port;
    sock->is_listener = true;
    sock->closed = false;
    fut_spinlock_init(&sock->lock);
    fut_waitq_init(&sock->rx_wait);

    fut_handle_t handle =
        fut_object_create(FUT_OBJ_SOCKET,
                          FUT_NET_BIND | FUT_NET_SEND | FUT_NET_RECV | FUT_NET_ADMIN,
                          sock);
    if (handle == FUT_INVALID_HANDLE) {
        fut_free(sock);
        return -ENOMEM;
    }
    sock->handle = handle;

    fut_spinlock_acquire(&net_lock);
    sock->next = socket_list;
    socket_list = sock;
    fut_spinlock_release(&net_lock);

    *out = sock;
    NETDBG("[net] listen port=%u socket=%p\n", port, (void *)sock);
    return 0;
}

fut_status_t fut_net_accept(fut_socket_t *listener, fut_socket_t **out) {
    if (!listener || !out) {
        return -EINVAL;
    }

    fut_spinlock_acquire(&listener->lock);
    if (!listener->is_listener || listener->closed) {
        fut_spinlock_release(&listener->lock);
        return -EINVAL;
    }
    listener->is_listener = false;
    fut_spinlock_release(&listener->lock);

    *out = listener;
    NETDBG("[net] accept socket=%p\n", (void *)listener);
    return 0;
}

fut_status_t fut_net_send(fut_socket_t *socket, const void *buf, size_t len) {
    if (!socket || !buf || len == 0) {
        return -EINVAL;
    }
    if (len > FUT_NET_MAX_FRAME) {
        return -EMSGSIZE;
    }

    fut_spinlock_acquire(&socket->lock);
    bool closed = socket->closed;
    fut_spinlock_release(&socket->lock);
    if (closed) {
        return -ENOTCONN;
    }

    NETDBG("[net] send socket=%p len=%zu\n", (void *)socket, len);
    fut_status_t rc = fut_net_dev_tx_all(buf, len);
    if (rc < 0) {
        return rc;
    }
    return 0;
}

fut_status_t fut_net_recv(fut_socket_t *socket,
                          void *buf,
                          size_t len,
                          size_t *out) {
    if (!socket || !buf || !out) {
        return -EINVAL;
    }

    fut_spinlock_acquire(&socket->lock);
    while (!socket->closed && socket->count == 0) {
        fut_waitq_sleep_locked(&socket->rx_wait, &socket->lock, FUT_THREAD_BLOCKED);
        fut_spinlock_acquire(&socket->lock);
    }

    if (socket->closed && socket->count == 0) {
        fut_spinlock_release(&socket->lock);
        return -ENOTCONN;
    }

    fut_net_packet_t pkt = socket->queue[socket->head];
    socket->queue[socket->head].data = NULL;
    socket->queue[socket->head].len = 0;
    socket->head = (socket->head + 1u) % FUT_NET_QUEUE_DEPTH;
    socket->count--;
    fut_spinlock_release(&socket->lock);

    size_t copy_len = (pkt.len < len) ? pkt.len : len;
    memcpy(buf, pkt.data, copy_len);
    *out = copy_len;
    fut_free(pkt.data);

    NETDBG("[net] recv socket=%p len=%zu\n", (void *)socket, copy_len);
    return 0;
}

void fut_net_close(fut_socket_t *socket) {
    if (!socket) {
        return;
    }

    fut_spinlock_acquire(&socket->lock);
    if (socket->closed) {
        fut_spinlock_release(&socket->lock);
        return;
    }
    socket->closed = true;
    fut_net_free_packets(socket);
    fut_spinlock_release(&socket->lock);

    fut_spinlock_acquire(&net_lock);
    struct fut_socket **prev = &socket_list;
    struct fut_socket *cur = socket_list;
    while (cur) {
        if (cur == socket) {
            *prev = cur->next;
            break;
        }
        prev = &cur->next;
        cur = cur->next;
    }
    fut_spinlock_release(&net_lock);

    if (socket->handle != FUT_INVALID_HANDLE) {
        fut_object_destroy(socket->handle);
        socket->handle = FUT_INVALID_HANDLE;
    }

    fut_net_wake(socket);
    fut_free(socket);
}

/* -------------------------------------------------------------------------- */
/* Frame dispatch                                                             */
/* -------------------------------------------------------------------------- */

void fut_net_dispatch_frame(const void *frame, size_t len) {
    if (!frame || len == 0) {
        return;
    }

    fut_spinlock_acquire(&net_lock);
    struct fut_socket *sock = socket_list;
    while (sock) {
        if (!sock->is_listener && !sock->closed) {
            fut_spinlock_acquire(&sock->lock);
            fut_status_t rc = fut_net_enqueue_locked(sock, frame, len);
            fut_spinlock_release(&sock->lock);
            if (rc == 0) {
                fut_net_wake(sock);
            } else {
                NETDBG("[net] drop frame len=%zu rc=%d\n", len, rc);
            }
        }
        sock = sock->next;
    }
    fut_spinlock_release(&net_lock);
}
