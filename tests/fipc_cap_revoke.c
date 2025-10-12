// SPDX-License-Identifier: MPL-2.0
#define _POSIX_C_SOURCE 200809L

#include <stdio.h>
#include <string.h>
#include <kernel/fut_fipc.h>

int main(void) {
    fut_fipc_init();

    struct fut_fipc_channel *ch = NULL;
    if (fut_fipc_channel_create(NULL, NULL, 1024, FIPC_CHANNEL_NONBLOCKING, &ch) != 0 || !ch) {
        fprintf(stderr, "[REVOKE] channel create failed\n");
        return 1;
    }

    struct fut_fipc_cap cap = {
        .rights = FIPC_CAP_R_SEND | FIPC_CAP_R_RECV,
        .revoke_flags = 0,
        .max_msgs = 0,
        .max_bytes = 0,
        .expiry_tick = 0,
        .lease_id = 0
    };
    if (fut_fipc_cap_bind(ch, &cap) != 0) {
        fprintf(stderr, "[REVOKE] bind failed\n");
        return 1;
    }

    if (fut_fipc_send(ch, 0xCA01u, "hi", 2) != 0) {
        fprintf(stderr, "[REVOKE] initial send failed\n");
        return 1;
    }
    if (fut_fipc_channel_inject(ch, 0xCA02u, "reply", 5, 0, 0, 0) != 0) {
        fprintf(stderr, "[REVOKE] initial inject failed\n");
        return 1;
    }

    if (fut_fipc_cap_revoke(ch, FIPC_CAP_REVOKE_RECV) != 0) {
        fprintf(stderr, "[REVOKE] revoke recv failed\n");
        return 1;
    }
    if (fut_fipc_channel_inject(ch, 0xCA03u, "drop", 4, 0, 0, 0) != FIPC_EPERM) {
        fprintf(stderr, "[REVOKE] recv not revoked\n");
        return 1;
    }
    if (fut_fipc_send(ch, 0xCA04u, "ok", 2) != 0) {
        fprintf(stderr, "[REVOKE] send should still succeed\n");
        return 1;
    }

    if (fut_fipc_cap_revoke(ch, FIPC_CAP_REVOKE_SEND) != 0) {
        fprintf(stderr, "[REVOKE] revoke send failed\n");
        return 1;
    }
    if (fut_fipc_send(ch, 0xCA05u, "fail", 4) != FIPC_EPERM) {
        fprintf(stderr, "[REVOKE] send not revoked\n");
        return 1;
    }

    if (fut_fipc_cap_unbind(ch) != 0) {
        fprintf(stderr, "[REVOKE] unbind failed\n");
        return 1;
    }
    if (fut_fipc_send(ch, 0xCA06u, "ok", 2) != 0) {
        fprintf(stderr, "[REVOKE] send after unbind failed\n");
        return 1;
    }
    if (fut_fipc_channel_inject(ch, 0xCA07u, "ok", 2, 0, 0, 0) != 0) {
        fprintf(stderr, "[REVOKE] inject after unbind failed\n");
        return 1;
    }

    printf("[REVOKE] capability revoke — PASS\n");
    return 0;
}
