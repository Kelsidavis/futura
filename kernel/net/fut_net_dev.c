// SPDX-License-Identifier: MPL-2.0
/*
 * fut_net_dev.c - FuturaNet device registry
 *
 * Bridges NIC drivers (virtio-net, loopback) with the socket layer.
 */

#include <futura/net.h>

#include <kernel/devfs.h>
#include <kernel/errno.h>
#include <kernel/fut_memory.h>
#include <kernel/fut_sched.h>

#include <stdbool.h>

extern void fut_printf(const char *fmt, ...);
void fut_net_dispatch_frame(const void *frame, size_t len);

/* Uncomment to force verbose tracing. */
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

fut_status_t fut_net_register(fut_netdev_t *dev) {
    if (!dev || !dev->name || !dev->ops || !dev->ops->tx) {
        return -EINVAL;
    }
    fut_net_dev_system_init();

    if (dev->mtu == 0) {
        dev->mtu = 1500;
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

    fut_spinlock_acquire(&dev_lock);
    dev->next = dev_list;
    dev_list = dev;
    unsigned minor = net_minor_alloc++;
    fut_spinlock_release(&dev_lock);

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

fut_status_t fut_net_dev_tx_all(const void *frame, size_t len) {
    if (!frame || len == 0) {
        return -EINVAL;
    }

    fut_status_t rc = 0;
    fut_spinlock_acquire(&dev_lock);
    fut_netdev_t *cursor = dev_list;
    while (cursor) {
        if (cursor->ops && cursor->ops->tx) {
            fut_status_t drv_rc = cursor->ops->tx(cursor, frame, len);
            if (drv_rc < 0 && rc == 0) {
                rc = drv_rc;
            }
        }
        cursor = cursor->next;
    }
    fut_spinlock_release(&dev_lock);
    return rc;
}

void fut_net_rx(fut_netdev_t *dev, const void *frame, size_t len) {
    (void)dev;
    fut_net_dispatch_frame(frame, len);
}
