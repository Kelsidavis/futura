// SPDX-License-Identifier: MPL-2.0
/*
 * fut_net.c - FuturaNet core socket layer
 *
 * Provides capability-gated raw frame sockets backed by loopback and
 * virtio-net providers. Frames delivered by providers fan out to all active
 * sockets, which expose a simple FIFO receive queue with timed waits.
 */

#include <futura/net.h>

#include <kernel/errno.h>
#include <kernel/fut_memory.h>
#include <kernel/fut_object.h>
#include <kernel/fut_sched.h>
#include <kernel/fut_thread.h>
#include <kernel/fut_timer.h>
#include <kernel/fut_waitq.h>

#include <stdatomic.h>
#include <stdbool.h>
#include <string.h>

extern void fut_printf(const char *fmt, ...);

/* Uncomment for verbose tracing */
/* #define DEBUG_NET 1 */

#ifdef DEBUG_NET
#define NETDBG(...) fut_printf(__VA_ARGS__)
#else
#define NETDBG(...) do { } while (0)
#endif

#define FUT_NET_QUEUE_DEPTH 128u

typedef struct fut_net_packet {
    size_t len;
    uint8_t *data;
} fut_net_packet_t;

typedef struct fut_net_waiter {
    fut_waitq_t *queue;
    fut_thread_t *thread;
    _Atomic bool timed_out;
} fut_net_waiter_t;

struct fut_socket {
    uint16_t port;
    uint32_t mtu;
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
static fut_netdev_t *primary_dev = NULL;

/* Forward declarations provided by fut_net_dev.c */
void fut_net_dev_system_init(void);
fut_status_t fut_net_dev_tx_all(const void *frame, size_t len);
void fut_net_dev_record_rx(fut_netdev_t *dev, bool success);
void fut_net_dev_record_tx(fut_netdev_t *dev, bool success);

/* Forward declaration for loopback init */
void fut_net_loopback_init(void);

/* -------------------------------------------------------------------------- */
/* Helpers                                                                    */
/* -------------------------------------------------------------------------- */

static bool fut_socket_has_rights(const struct fut_socket *sock,
                                  fut_rights_t rights) {
    if (!sock) {
        return false;
    }
    return fut_object_has_rights(sock->handle, rights);
}

static bool fut_net_is_loopback_name(const char *name) {
    if (!name) {
        return false;
    }
    const char loop_name[] = "loopback0";
    for (size_t i = 0; loop_name[i] != '\0'; ++i) {
        if (name[i] != loop_name[i]) {
            return false;
        }
    }
    return name[8] == '0' && name[9] == '\0';
}

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

static void fut_net_wake(struct fut_socket *sock) {
    fut_waitq_wake_one(&sock->rx_wait);
}

static void fut_net_wait_timeout_cb(void *arg) {
    fut_net_waiter_t *waiter = (fut_net_waiter_t *)arg;
    if (!waiter || !waiter->queue) {
        return;
    }

    fut_thread_t *thread = waiter->thread;
    if (!thread) {
        return;
    }

    if (fut_waitq_remove_thread(waiter->queue, thread)) {
        atomic_store_explicit(&waiter->timed_out, true, memory_order_release);
        thread->state = FUT_THREAD_READY;
        fut_sched_add_thread(thread);
    }
}

static fut_net_waiter_t *fut_net_waiter_create(fut_waitq_t *queue) {
    fut_net_waiter_t *waiter =
        (fut_net_waiter_t *)fut_malloc(sizeof(fut_net_waiter_t));
    if (!waiter) {
        return NULL;
    }
    waiter->queue = queue;
    waiter->thread = fut_thread_current();
    atomic_store_explicit(&waiter->timed_out, false, memory_order_relaxed);
    return waiter;
}

/* -------------------------------------------------------------------------- */
/* Public API                                                                 */
/* -------------------------------------------------------------------------- */

void fut_net_init(void) {
    fut_printf("[NET-INIT] Entry\n");
    if (net_initialized) {
        fut_printf("[NET-INIT] Already initialized, returning\n");
        return;
    }

    fut_printf("[NET-INIT] Initializing spinlock\n");
    fut_spinlock_init(&net_lock);
    fut_printf("[NET-INIT] Calling fut_net_dev_system_init\n");
    fut_net_dev_system_init();
    fut_printf("[NET-INIT] Calling fut_net_loopback_init\n");
    fut_net_loopback_init();
    fut_printf("[NET-INIT] Setting initialized flag\n");
    net_initialized = true;
    NETDBG("[net] subsystem initialized\n");
    fut_printf("[NET-INIT] Complete\n");
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
    sock->mtu = FUT_NET_DEFAULT_MTU;
    sock->is_listener = true;
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
    if (!fut_socket_has_rights(listener, FUT_NET_BIND)) {
        return -EACCES;
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
    if (!fut_socket_has_rights(socket, FUT_NET_SEND)) {
        return -EACCES;
    }

    fut_spinlock_acquire(&socket->lock);
    bool closed = socket->closed;
    uint32_t mtu = socket->mtu ? socket->mtu : FUT_NET_DEFAULT_MTU;
    fut_spinlock_release(&socket->lock);

    if (closed) {
        return -ENOTCONN;
    }
    if (len > mtu || len > FUT_NET_MAX_FRAME) {
        return -EMSGSIZE;
    }

    NETDBG("[net] send socket=%p len=%u\n", (void *)socket, len);
    fut_status_t rc = fut_net_dev_tx_all(buf, len);
    if (rc < 0) {
        return rc;
    }
    return 0;
}

fut_status_t fut_net_recv_timed(fut_socket_t *socket,
                                void *buf,
                                size_t len,
                                size_t *out,
                                uint32_t timeout_ms) {
    if (!socket || !buf || !out || len == 0) {
        return -EINVAL;
    }
    if (!fut_socket_has_rights(socket, FUT_NET_RECV)) {
        return -EACCES;
    }

    fut_spinlock_acquire(&socket->lock);
    while (!socket->closed && socket->count == 0) {
        fut_net_waiter_t *waiter = fut_net_waiter_create(&socket->rx_wait);
        if (!waiter) {
            fut_spinlock_release(&socket->lock);
            return -ENOMEM;
        }

        fut_status_t timer_rc = fut_timer_start(timeout_ms ? timeout_ms : FUT_NET_RECV_TIMEOUT_MS,
                                                fut_net_wait_timeout_cb,
                                                waiter);
        if (timer_rc != 0) {
            fut_free(waiter);
            fut_spinlock_release(&socket->lock);
            return timer_rc;
        }

        fut_waitq_sleep_locked(&socket->rx_wait, &socket->lock, FUT_THREAD_BLOCKED);
        fut_spinlock_acquire(&socket->lock);

        bool timed_out = atomic_load_explicit(&waiter->timed_out, memory_order_acquire);
        if (!timed_out) {
            (void)fut_timer_cancel(fut_net_wait_timeout_cb, waiter);
        }
        fut_free(waiter);

        if (timed_out && socket->count == 0) {
            fut_spinlock_release(&socket->lock);
            return -EAGAIN;
        }
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

    NETDBG("[net] recv socket=%p len=%u\n", (void *)socket, copy_len);
    return 0;
}

void fut_net_close(fut_socket_t *socket) {
    if (!socket) {
        return;
    }
    if (!fut_socket_has_rights(socket, FUT_NET_ADMIN)) {
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

    bool dump_stats = false;
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
    if (!socket_list) {
        dump_stats = true;
    }
    fut_spinlock_release(&net_lock);

    if (socket->handle != FUT_INVALID_HANDLE) {
        fut_object_destroy(socket->handle);
        socket->handle = FUT_INVALID_HANDLE;
    }

    fut_net_wake(socket);
    fut_free(socket);

#ifdef DEBUG_NET
    if (dump_stats) {
        fut_net_debug_dump_stats();
    }
#else
    (void)dump_stats;
#endif
}

const char *fut_net_primary_provider(void) {
    fut_spinlock_acquire(&net_lock);
    fut_netdev_t *dev = primary_dev;
    const char *name = dev ? dev->name : "loopback0";
    fut_spinlock_release(&net_lock);
    return name;
}

void fut_net_get_stats(const fut_netdev_t *dev, fut_net_stats_t *out) {
    if (!dev || !out) {
        return;
    }
    out->rx_ok = atomic_load_explicit(&dev->stats_rx_ok, memory_order_relaxed);
    out->rx_drop = atomic_load_explicit(&dev->stats_rx_drop, memory_order_relaxed);
    out->tx_ok = atomic_load_explicit(&dev->stats_tx_ok, memory_order_relaxed);
    out->tx_err = atomic_load_explicit(&dev->stats_tx_err, memory_order_relaxed);
}

/* -------------------------------------------------------------------------- */
/* Frame dispatch                                                             */
/* -------------------------------------------------------------------------- */

static void fut_net_dispatch_frame(fut_netdev_t *dev,
                                   const void *frame,
                                   size_t len) {
    if (!frame || len == 0 || len > FUT_NET_MAX_FRAME) {
        fut_net_dev_record_rx(dev, false);
        return;
    }

    bool delivered = false;
    fut_spinlock_acquire(&net_lock);
    struct fut_socket *sock = socket_list;
    while (sock) {
        if (!sock->is_listener && !sock->closed) {
            fut_spinlock_acquire(&sock->lock);
            fut_status_t rc = fut_net_enqueue_locked(sock, frame, len);
            fut_spinlock_release(&sock->lock);
            if (rc == 0) {
                fut_net_wake(sock);
                delivered = true;
            } else {
                NETDBG("[net] drop frame for socket=%p rc=%d\n", (void *)sock, rc);
            }
        }
        sock = sock->next;
    }
    fut_spinlock_release(&net_lock);

    fut_net_dev_record_rx(dev, delivered);
}

/* -------------------------------------------------------------------------- */
/* Provider entry points                                                      */
/* -------------------------------------------------------------------------- */

void fut_net_provider_rx(fut_netdev_t *dev, const void *frame, size_t len) {
    if (!dev) {
        return;
    }
    fut_net_dispatch_frame(dev, frame, len);
}

void fut_net_provider_irq(fut_netdev_t *dev) {
    (void)dev;
    fut_spinlock_acquire(&net_lock);
    struct fut_socket *sock = socket_list;
    while (sock) {
        fut_net_wake(sock);
        sock = sock->next;
    }
    fut_spinlock_release(&net_lock);
}

void fut_net_set_primary_dev(fut_netdev_t *dev) {
    fut_spinlock_acquire(&net_lock);
    if (!primary_dev && dev && dev->name && !fut_net_is_loopback_name(dev->name)) {
        primary_dev = dev;
    }
    fut_spinlock_release(&net_lock);
}

/* -------------------------------------------------------------------------- */
/* Device registration helpers                                               */
/* -------------------------------------------------------------------------- */
