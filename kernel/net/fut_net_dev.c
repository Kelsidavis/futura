// SPDX-License-Identifier: MPL-2.0
/*
 * fut_net_dev.c - FuturaNet device registry
 *
 * Bridges NIC drivers (virtio-net, loopback) with the socket layer and
 * maintains per-device statistics.
 */

#include <futura/net.h>

#include <kernel/devfs.h>
#include <kernel/errno.h>
#include <kernel/fut_memory.h>
#include <kernel/fut_object.h>
#include <kernel/fut_sched.h>

#include <stdatomic.h>
#include <stdbool.h>

extern void fut_printf(const char *fmt, ...);

/* Uncomment for verbose tracing. */
/* #define DEBUG_NET 1 */

#ifdef DEBUG_NET
#define NETDBG(...) fut_printf(__VA_ARGS__)
#else
#define NETDBG(...) do { } while (0)
#endif

static fut_spinlock_t dev_lock;
static bool dev_lock_ready = false;
static fut_netdev_t *dev_list = NULL;
static unsigned net_minor_alloc = 0;

void fut_net_dev_system_init(void) {
    if (dev_lock_ready) {
        return;
    }
    fut_spinlock_init(&dev_lock);
    dev_lock_ready = true;
}

static void fut_net_stats_reset(fut_netdev_t *dev) {
    if (!dev) {
        return;
    }
    atomic_store_explicit(&dev->stats_rx_ok, 0, memory_order_relaxed);
    atomic_store_explicit(&dev->stats_rx_drop, 0, memory_order_relaxed);
    atomic_store_explicit(&dev->stats_tx_ok, 0, memory_order_relaxed);
    atomic_store_explicit(&dev->stats_tx_err, 0, memory_order_relaxed);
}

fut_status_t fut_net_register(fut_netdev_t *dev) {
    if (!dev || !dev->name || !dev->ops || !dev->ops->tx) {
        return -EINVAL;
    }
    fut_net_dev_system_init();

    if (dev->mtu == 0) {
        dev->mtu = FUT_NET_DEFAULT_MTU;
    }

    if (dev->handle == FUT_INVALID_HANDLE) {
        fut_handle_t handle =
            fut_object_create(FUT_OBJ_NETDEV,
                              FUT_NET_ADMIN | FUT_NET_SEND | FUT_NET_RECV,
                              dev);
        if (handle == FUT_INVALID_HANDLE) {
            return -ENOMEM;
        }
        dev->handle = handle;
    }

    fut_net_stats_reset(dev);

    fut_spinlock_acquire(&dev_lock);
    dev->next = dev_list;
    dev_list = dev;
    unsigned minor = net_minor_alloc++;
    fut_spinlock_release(&dev_lock);

    fut_net_set_primary_dev(dev);

    if (dev->name) {
        char path[64];
        const char prefix[] = "/dev/";
        size_t idx = 0;
        for (size_t i = 0; i < (sizeof(prefix) - 1u); ++i) {
            path[idx++] = prefix[i];
        }
        const char *name = dev->name;
        while (*name && idx < (sizeof(path) - 1u)) {
            char c = *name++;
            if (c == ':') {
                c = '_';
            }
            path[idx++] = c;
        }
        path[idx] = '\0';
        devfs_create_chr(path, FUT_NET_MAJOR, minor);
    }

    NETDBG("[net] registered device %s mtu=%u\n", dev->name, dev->mtu);
    return 0;
}

void fut_net_unregister(fut_netdev_t *dev) {
    if (!dev) {
        return;
    }

    fut_spinlock_acquire(&dev_lock);
    fut_netdev_t **prev = &dev_list;
    fut_netdev_t *cursor = dev_list;
    while (cursor) {
        if (cursor == dev) {
            *prev = cursor->next;
            break;
        }
        prev = &cursor->next;
        cursor = cursor->next;
    }
    fut_spinlock_release(&dev_lock);

    if (dev->handle != FUT_INVALID_HANDLE) {
        fut_object_destroy(dev->handle);
        dev->handle = FUT_INVALID_HANDLE;
    }
}

static void fut_net_dev_record_tx_locked(fut_netdev_t *dev, bool success) {
    if (!dev) {
        return;
    }
    if (success) {
        atomic_fetch_add_explicit(&dev->stats_tx_ok, 1, memory_order_relaxed);
    } else {
        atomic_fetch_add_explicit(&dev->stats_tx_err, 1, memory_order_relaxed);
    }
}

void fut_net_dev_record_tx(fut_netdev_t *dev, bool success) {
    fut_net_dev_record_tx_locked(dev, success);
}

void fut_net_dev_record_rx(fut_netdev_t *dev, bool success) {
    if (!dev) {
        return;
    }
    if (success) {
        atomic_fetch_add_explicit(&dev->stats_rx_ok, 1, memory_order_relaxed);
    } else {
        atomic_fetch_add_explicit(&dev->stats_rx_drop, 1, memory_order_relaxed);
    }
}

fut_status_t fut_net_dev_tx_all(const void *frame, size_t len) {
    if (!frame || len == 0) {
        return -EINVAL;
    }

    fut_status_t last_err = 0;
    bool success = false;

    fut_spinlock_acquire(&dev_lock);
    fut_netdev_t *cursor = dev_list;
    while (cursor) {
        fut_status_t drv_rc = -ENODEV;
        if (cursor->ops && cursor->ops->tx) {
            if (cursor->mtu && len > cursor->mtu) {
                drv_rc = -EMSGSIZE;
            } else {
                drv_rc = cursor->ops->tx(cursor, frame, len);
            }
            fut_net_dev_record_tx_locked(cursor, drv_rc == 0);
        }

        if (drv_rc == 0) {
            success = true;
        } else if (!success) {
            last_err = drv_rc;
        }

        cursor = cursor->next;
    }
    fut_spinlock_release(&dev_lock);

    if (success) {
        return 0;
    }
    return (last_err != 0) ? last_err : -ENODEV;
}

void fut_net_debug_dump_stats(void) {
#ifdef DEBUG_NET
    fut_spinlock_acquire(&dev_lock);
    fut_netdev_t *cursor = dev_list;
    while (cursor) {
        uint64_t rx_ok = atomic_load_explicit(&cursor->stats_rx_ok, memory_order_relaxed);
        uint64_t rx_drop = atomic_load_explicit(&cursor->stats_rx_drop, memory_order_relaxed);
        uint64_t tx_ok = atomic_load_explicit(&cursor->stats_tx_ok, memory_order_relaxed);
        uint64_t tx_err = atomic_load_explicit(&cursor->stats_tx_err, memory_order_relaxed);
        NETDBG("[net] stats %s rx_ok=%llu rx_drop=%llu tx_ok=%llu tx_err=%llu\n",
               cursor->name ? cursor->name : "(anon)",
               (unsigned long long)rx_ok,
               (unsigned long long)rx_drop,
               (unsigned long long)tx_ok,
               (unsigned long long)tx_err);
        cursor = cursor->next;
    }
    fut_spinlock_release(&dev_lock);
#else
    (void)dev_list;
#endif
}
