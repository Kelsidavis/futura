/* netd_core.c - Minimal UDP transport glue for host-mode FIPC tests
 *
 * SPDX-License-Identifier: MPL-2.0
 */

#define _POSIX_C_SOURCE 200809L

#include "netd_core.h"

#include <arpa/inet.h>
#include <errno.h>
#include <poll.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>

#include <kernel/fut_fipc.h>
#include "../svc_registryd/registry_client.h"

/* Some builds may not expose a prototype publicly; declare if needed. */
extern int fut_fipc_set_transport_ops(const struct fut_fipc_transport_ops *ops, void *context);

struct netd_binding {
    uint64_t local_id;
    char name[64];
    char host[64];
    uint16_t port;
    uint64_t cached_remote;
};

struct netd_counters {
    uint64_t lookup_attempts;
    uint64_t lookup_hits;
    uint64_t lookup_miss;
    uint64_t send_eagain;
};

struct netd {
    int                sock;
    struct sockaddr_in bind_addr;
    bool               running;
    struct netd_binding bindings[64];
    size_t             nb;
    struct netd_counters ctrs;
};

/* ---------- CRC32 (standard polynomial) ---------- */
static uint32_t crc32_accum(const uint8_t *data, size_t len) {
    uint32_t crc = 0xFFFFFFFFu;
    for (size_t i = 0; i < len; i++) {
        crc ^= data[i];
        for (int k = 0; k < 8; k++) {
            uint32_t mask = (uint32_t)-(int32_t)(crc & 1u);
            crc = (crc >> 1) ^ (0xEDB88320u & mask);
        }
    }
    return ~crc;
}

/* Forward declaration for transport callback */
static int udp_send_cb(const struct fut_fipc_remote_endpoint *remote,
                       const struct fut_fipc_net_hdr *hdr,
                       const uint8_t *payload,
                       size_t payload_len,
                       void *context);

static const struct fut_fipc_transport_ops g_udp_ops = {
    .send = udp_send_cb,
};

static struct netd_binding *find_binding(struct netd *nd, uint64_t local_id) {
    if (!nd) {
        return NULL;
    }
    for (size_t i = 0; i < nd->nb; i++) {
        if (nd->bindings[i].local_id == local_id) {
            return &nd->bindings[i];
        }
    }
    return NULL;
}

struct netd *netd_bootstrap(const char *bind_ip, uint16_t port) {
    struct netd *nd = (struct netd *)calloc(1, sizeof(*nd));
    if (!nd) {
        return NULL;
    }

    nd->sock = socket(AF_INET, SOCK_DGRAM, 0);
    if (nd->sock < 0) {
        free(nd);
        return NULL;
    }

    memset(&nd->bind_addr, 0, sizeof(nd->bind_addr));
    nd->bind_addr.sin_family = AF_INET;
    nd->bind_addr.sin_port = htons(port);
    nd->bind_addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);

    if (bind_ip && bind_ip[0]) {
        struct in_addr addr;
        if (inet_pton(AF_INET, bind_ip, &addr) == 1) {
            nd->bind_addr.sin_addr = addr;
        }
    }

    if (bind(nd->sock, (struct sockaddr *)&nd->bind_addr, sizeof(nd->bind_addr)) < 0) {
        close(nd->sock);
        free(nd);
        return NULL;
    }

    nd->running = true;

    if (fut_fipc_set_transport_ops(&g_udp_ops, nd) != 0) {
        close(nd->sock);
        free(nd);
        return NULL;
    }

    return nd;
}

bool netd_is_running(const struct netd *nd) {
    return nd && nd->running;
}

bool netd_bind_service(struct netd *nd,
                       uint64_t local_channel_id,
                       const char *service_name,
                       const char *registry_host,
                       uint16_t registry_port) {
    if (!nd || !service_name || !registry_host || local_channel_id == 0) {
        return false;
    }

    struct netd_binding *binding = find_binding(nd, local_channel_id);
    if (!binding) {
        if (nd->nb >= (sizeof(nd->bindings) / sizeof(nd->bindings[0]))) {
            return false;
        }
        binding = &nd->bindings[nd->nb++];
        binding->local_id = local_channel_id;
        binding->cached_remote = 0;
    }

    strncpy(binding->name, service_name, sizeof(binding->name) - 1);
    binding->name[sizeof(binding->name) - 1] = '\0';

    strncpy(binding->host, registry_host, sizeof(binding->host) - 1);
    binding->host[sizeof(binding->host) - 1] = '\0';

    binding->port = registry_port;
    return true;
}

void netd_shutdown(struct netd *nd) {
    if (!nd) {
        return;
    }

    nd->running = false;
    (void)fut_fipc_set_transport_ops(NULL, NULL);

    if (nd->sock >= 0) {
        close(nd->sock);
    }

    free(nd);
}

bool netd_poll_once(struct netd *nd, uint32_t timeout_ms) {
    if (!nd || !nd->running) {
        return false;
    }

    struct pollfd pfd = {
        .fd = nd->sock,
        .events = POLLIN,
        .revents = 0
    };

    int rv = poll(&pfd, 1, (int)timeout_ms);
    if (rv < 0) {
        if (errno == EINTR) {
            return true;
        }
        nd->running = false;
        return false;
    }

    if (rv == 0) {
        return true;
    }

    if (pfd.revents & POLLIN) {
        uint8_t buf[65536];
        ssize_t received = recvfrom(nd->sock, buf, sizeof(buf), 0, NULL, NULL);
        if (received <= 0) {
            if (errno == EINTR || errno == EAGAIN) {
                return true;
            }
            nd->running = false;
            return false;
        }

        if ((size_t)received < sizeof(struct fut_fipc_net_hdr) + sizeof(struct fut_fipc_msg)) {
            return true;
        }

        struct fut_fipc_net_hdr net_hdr;
        memcpy(&net_hdr, buf, sizeof(net_hdr));

        size_t payload_len = net_hdr.payload_len;
        if (sizeof(net_hdr) + payload_len != (size_t)received) {
            return true;
        }

        const uint8_t *payload = buf + sizeof(net_hdr);
        if (crc32_accum(payload, payload_len) != net_hdr.crc) {
            return true;
        }

        if (payload_len < sizeof(struct fut_fipc_msg)) {
            return true;
        }

        const struct fut_fipc_msg *msg = (const struct fut_fipc_msg *)payload;
        size_t user_len = msg->length;
        if (sizeof(struct fut_fipc_msg) + user_len != payload_len) {
            return true;
        }

        struct fut_fipc_channel *channel = fut_fipc_channel_lookup(net_hdr.channel_id);
        if (!channel) {
            return true;
        }

        if (channel->capability != 0 && channel->capability != msg->capability) {
            return true;
        }

        (void)fut_fipc_channel_inject(channel,
                                      msg->type,
                                      msg->payload,
                                      user_len,
                                      msg->src_pid,
                                      msg->dst_pid,
                                      msg->capability);
    }

    return true;
}

static int udp_send_cb(const struct fut_fipc_remote_endpoint *remote,
                       const struct fut_fipc_net_hdr *hdr,
                       const uint8_t *payload,
                       size_t payload_len,
                       void *context) {
    struct netd *nd = (struct netd *)context;
    if (!nd || nd->sock < 0 || !remote || !hdr || (!payload && payload_len > 0)) {
        return FIPC_EINVAL;
    }

    struct fut_fipc_remote_endpoint ep = *remote;
    uint64_t effective_channel = hdr->channel_id;

    if (ep.channel_id == 0) {
        struct netd_binding *binding = find_binding(nd, effective_channel);
        if (!binding) {
            nd->ctrs.lookup_miss++;
            nd->ctrs.send_eagain++;
            return FIPC_EAGAIN;
        }

        nd->ctrs.lookup_attempts++;
        uint64_t cached = binding->cached_remote;
        if (cached == 0) {
            uint64_t resolved = 0;
            if (registry_client_lookup(binding->host, binding->port, binding->name, &resolved) == 0 && resolved != 0) {
                binding->cached_remote = resolved;
                ep.channel_id = resolved;
                (void)fut_fipc_register_remote(binding->local_id, &ep);
                nd->ctrs.lookup_hits++;
                effective_channel = resolved;
            } else {
                nd->ctrs.lookup_miss++;
                nd->ctrs.send_eagain++;
                return FIPC_EAGAIN;
            }
        } else {
            ep.channel_id = cached;
            effective_channel = cached;
            (void)fut_fipc_register_remote(binding->local_id, &ep);
        }
    }

    uint16_t port = (uint16_t)(ep.node_id & 0xFFFFu);

    struct sockaddr_in dst;
    memset(&dst, 0, sizeof(dst));
    dst.sin_family = AF_INET;
    dst.sin_port = htons(port);
    dst.sin_addr.s_addr = htonl(INADDR_LOOPBACK);

    struct fut_fipc_net_hdr net_hdr = *hdr;
    net_hdr.channel_id = effective_channel;
    net_hdr.crc = crc32_accum(payload, payload_len);

    size_t frame_len = sizeof(net_hdr) + payload_len;
    uint8_t *frame = (uint8_t *)malloc(frame_len);
    if (!frame) {
        return FIPC_ENOMEM;
    }

    memcpy(frame, &net_hdr, sizeof(net_hdr));
    if (payload_len) {
        memcpy(frame + sizeof(net_hdr), payload, payload_len);
    }

    ssize_t sent = sendto(nd->sock, frame, frame_len, 0,
                          (struct sockaddr *)&dst, sizeof(dst));
    int saved_errno = errno;
    free(frame);

    if (sent != (ssize_t)frame_len) {
        if (saved_errno == EAGAIN || saved_errno == EWOULDBLOCK) {
            return FIPC_EAGAIN;
        }
        return FIPC_EPIPE;
    }

    return 0;
}
