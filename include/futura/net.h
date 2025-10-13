// SPDX-License-Identifier: MPL-2.0
/*
 * net.h - FuturaNet kernel networking interface
 *
 * Minimal async socket API backed by loopback and virtio-net providers.
 * Exposed to kernel subsystems and in-kernel tests; userland bindings will
 * layer on top once the capability surface stabilizes.
 */

#pragma once

#include <stddef.h>
#include <stdint.h>

#include <kernel/fut_object.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef int fut_status_t;

enum fut_net_rights {
    FUT_NET_BIND  = 1ULL << 16,
    FUT_NET_SEND  = 1ULL << 17,
    FUT_NET_RECV  = 1ULL << 18,
    FUT_NET_ADMIN = 1ULL << 19,
};

typedef struct fut_netdev fut_netdev_t;
typedef struct fut_socket fut_socket_t;

typedef struct fut_net_frame {
    uint8_t *data;
    size_t len;
} fut_net_frame_t;

#define FUT_NET_MAJOR 240u

typedef struct fut_netdev_ops {
    fut_status_t (*tx)(fut_netdev_t *dev, const void *frame, size_t len);
} fut_netdev_ops_t;

struct fut_netdev {
    const char *name;
    uint32_t mtu;
    uint32_t features;
    void *driver_ctx;
    const fut_netdev_ops_t *ops;
    fut_handle_t handle;
    struct fut_netdev *next;
};

/* --------------------------------------------------------------------- */
/* Socket API                                                            */
/* --------------------------------------------------------------------- */

void fut_net_init(void);

fut_status_t fut_net_listen(uint16_t port, fut_socket_t **out);
fut_status_t fut_net_accept(fut_socket_t *listener, fut_socket_t **out);
fut_status_t fut_net_send(fut_socket_t *socket, const void *buf, size_t len);
fut_status_t fut_net_recv(fut_socket_t *socket, void *buf, size_t len, size_t *out);
void fut_net_close(fut_socket_t *socket);

/* --------------------------------------------------------------------- */
/* Provider registration (loopback + NICs)                               */
/* --------------------------------------------------------------------- */

fut_status_t fut_net_register(fut_netdev_t *dev);
void fut_net_unregister(fut_netdev_t *dev);
void fut_net_rx(fut_netdev_t *dev, const void *frame, size_t len);

#ifdef __cplusplus
}
#endif
