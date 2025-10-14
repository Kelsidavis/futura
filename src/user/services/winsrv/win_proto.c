// SPDX-License-Identifier: MPL-2.0
//
// win_proto.c - Minimal FIPC framing helpers for the window protocol

#include "win_proto.h"

#include <kernel/errno.h>
#include <kernel/fut_fipc.h>
#include <user/futura_posix.h>
#include <user/libfutura.h>

int win_proto_send(struct fut_fipc_channel *channel,
                   uint32_t id,
                   const void *payload,
                   size_t payload_size) {
    if (!channel) {
        return -EINVAL;
    }

    if (payload_size > 0 && !payload) {
        return -EINVAL;
    }

    struct {
        struct win_msg_hdr hdr;
        uint8_t data[256];
    } frame = {0};

    if (payload_size > sizeof(frame.data)) {
        return -EMSGSIZE;
    }

    frame.hdr.id = id;
    frame.hdr.size = (uint32_t)payload_size;
    if (payload_size > 0) {
        memcpy(frame.data, payload, payload_size);
    }

    return fut_fipc_send(channel,
                         id,
                         &frame,
                         sizeof(frame.hdr) + payload_size);
}

int win_proto_recv(struct fut_fipc_channel *channel,
                   struct win_proto_message *out) {
    if (!channel || !out) {
        return -EINVAL;
    }

    uint8_t buffer[sizeof(struct fut_fipc_msg) + sizeof(struct win_proto_message)];

    while (true) {
        ssize_t got = fut_fipc_recv(channel, buffer, sizeof(buffer));
        if (got == -EINTR) {
            continue;
        }
        if (got < 0) {
            return (int)got;
        }
        if ((size_t)got < sizeof(struct fut_fipc_msg) + sizeof(struct win_msg_hdr)) {
            return -EMSGSIZE;
        }

        const struct fut_fipc_msg *msg = (const struct fut_fipc_msg *)buffer;
        const size_t payload_size = msg->length;
        if (payload_size < sizeof(struct win_msg_hdr)) {
            return -EMSGSIZE;
        }

        const struct win_msg_hdr *hdr = (const struct win_msg_hdr *)msg->payload;
        const uint8_t *payload = msg->payload + sizeof(struct win_msg_hdr);
        const size_t actual_payload = payload_size - sizeof(struct win_msg_hdr);

        if (actual_payload > sizeof(out->payload)) {
            return -EMSGSIZE;
        }

        out->header = *hdr;
        out->payload_size = actual_payload;
        if (actual_payload > 0) {
            memcpy(out->payload, payload, actual_payload);
        }
        return 0;
    }
}
