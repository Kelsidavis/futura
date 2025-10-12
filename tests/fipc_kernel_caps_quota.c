// SPDX-License-Identifier: MPL-2.0
// fipc_kernel_caps_quota.c - Capability rights and quota enforcement

#define _POSIX_C_SOURCE 200809L

#include <stdio.h>
#include <kernel/fut_fipc.h>

int main(void) {
    fut_fipc_init();

    struct fut_fipc_channel *ch = NULL;
    if (fut_fipc_channel_create(NULL, NULL, 4096, FIPC_CHANNEL_NONBLOCKING, &ch) != 0 || !ch) {
        fprintf(stderr, "[CAPQ] channel create failed\n");
        return 1;
    }

    struct fut_fipc_cap cap = {
        .rights = FIPC_CAP_R_SEND | FIPC_CAP_R_RECV,
        .max_msgs = 2,
        .max_bytes = 8,
        .expiry_tick = 0
    };
    if (fut_fipc_cap_bind(ch, &cap) != 0) {
        fprintf(stderr, "[CAPQ] cap bind failed\n");
        return 1;
    }

    if (fut_fipc_send(ch, 0xC001u, "OK", 2) != 0) {
        fprintf(stderr, "[CAPQ] send 1 failed\n");
        return 1;
    }
    if (fut_fipc_send(ch, 0xC002u, "OK", 2) != 0) {
        fprintf(stderr, "[CAPQ] send 2 failed\n");
        return 1;
    }
    int rc = fut_fipc_send(ch, 0xC003u, "OK", 2);
    if (rc == 0 || rc != FIPC_ENOSPC) {
        fprintf(stderr, "[CAPQ] quota not enforced\n");
        return 1;
    }

    cap.rights = FIPC_CAP_R_RECV; /* remove send right */
    cap.max_msgs = 0;
    cap.max_bytes = 0;
    if (fut_fipc_cap_bind(ch, &cap) != 0) {
        fprintf(stderr, "[CAPQ] cap rebind failed\n");
        return 1;
    }
    rc = fut_fipc_send(ch, 0xC004u, "NO", 2);
    if (rc == 0 || rc != FIPC_EPERM) {
        fprintf(stderr, "[CAPQ] rights enforcement failed\n");
        return 1;
    }

    cap.rights = FIPC_CAP_R_SEND | FIPC_CAP_R_RECV;
    cap.max_msgs = 0;
    cap.max_bytes = 0;
    if (fut_fipc_cap_bind(ch, &cap) != 0) {
        fprintf(stderr, "[CAPQ] cap restore failed\n");
        return 1;
    }

    if (fut_fipc_channel_inject(ch, 0xD001u, "DATA", 4, 0, 0, 0) != 0) {
        fprintf(stderr, "[CAPQ] inject 1 failed\n");
        return 1;
    }
    if (fut_fipc_channel_inject(ch, 0xD002u, "DATA", 4, 0, 0, 0) != 0) {
        fprintf(stderr, "[CAPQ] inject 2 failed\n");
        return 1;
    }

    if (fut_fipc_cap_unbind(ch) != 0) {
        fprintf(stderr, "[CAPQ] cap unbind failed\n");
        return 1;
    }
    if (fut_fipc_send(ch, 0xC005u, "OK", 2) != 0) {
        fprintf(stderr, "[CAPQ] send after unbind failed\n");
        return 1;
    }

    printf("[CAPQ] capability + quota enforcement — PASS\n");
    return 0;
}
