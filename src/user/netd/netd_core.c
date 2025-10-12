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

/* Some builds may not expose a prototype publicly; declare if needed. */
extern int fut_fipc_set_transport_ops(const struct fut_fipc_transport_ops *ops, void *context);

struct netd {
    int                sock;
    struct sockaddr_in bind_addr;
    bool               running;
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

    uint16_t port = (uint16_t)(remote->node_id & 0xFFFFu);

    struct sockaddr_in dst;
    memset(&dst, 0, sizeof(dst));
    dst.sin_family = AF_INET;
    dst.sin_port = htons(port);
    dst.sin_addr.s_addr = htonl(INADDR_LOOPBACK);

    struct fut_fipc_net_hdr net_hdr = *hdr;
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
