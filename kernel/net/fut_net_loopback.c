// SPDX-License-Identifier: MPL-2.0
/*
 * fut_net_loopback.c - Software loopback provider for FuturaNet
 */

#include <futura/net.h>

#include <kernel/errno.h>

#include <string.h>

static fut_netdev_t loopback_dev;

static fut_status_t loopback_tx(fut_netdev_t *dev, const void *frame, size_t len) {
    if (!frame || len == 0) {
        return -EINVAL;
    }
    fut_net_provider_rx(dev, frame, len);
    return 0;
}

void fut_net_loopback_init(void) {
    memset(&loopback_dev, 0, sizeof(loopback_dev));
    static const fut_netdev_ops_t ops = {
        .tx = loopback_tx,
        .irq_ack = NULL,
    };
    loopback_dev.name = "loopback0";
    loopback_dev.mtu = 1500;
    loopback_dev.features = 0;
    loopback_dev.ops = &ops;
    loopback_dev.handle = FUT_INVALID_HANDLE;

    fut_net_register(&loopback_dev);
}
