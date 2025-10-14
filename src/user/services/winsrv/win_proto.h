// SPDX-License-Identifier: MPL-2.0
//
// win_proto.h - Thin wrappers over FIPC for window IPC

#pragma once

#include <stddef.h>
#include <stdint.h>

#include <futura/ipc_win.h>

struct fut_fipc_channel;
struct win_proto_message {
    struct win_msg_hdr header;
    uint8_t payload[256];
    size_t payload_size;
};

int win_proto_send(struct fut_fipc_channel *channel,
                   uint32_t id,
                   const void *payload,
                   size_t payload_size);

int win_proto_recv(struct fut_fipc_channel *channel,
                   struct win_proto_message *out);

