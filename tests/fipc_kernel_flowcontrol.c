// SPDX-License-Identifier: MPL-2.0
// fipc_kernel_flowcontrol.c - Verify per-channel credit windows

#define _POSIX_C_SOURCE 200809L

#include <stdio.h>
#include <kernel/fut_fipc.h>

int main(void) {
    fut_fipc_init();

    struct fut_fipc_channel *ch = NULL;
    if (fut_fipc_channel_create(NULL, NULL, 4096, FIPC_CHANNEL_NONBLOCKING, &ch) != 0 || !ch) {
        fprintf(stderr, "[FLOW] channel create failed\n");
        return 1;
    }

    struct fut_fipc_cap cap = {
        .rights = FIPC_CAP_R_SEND | FIPC_CAP_R_RECV,
        .max_msgs = 0,
        .max_bytes = 0,
        .expiry_tick = 0
    };
    (void)fut_fipc_cap_bind(ch, &cap);

    if (fut_fipc_set_credits(ch, 2, 0) != 0) {
        fprintf(stderr, "[FLOW] set credits failed\n");
        return 1;
    }

    if (fut_fipc_send(ch, 0xF100u, "A", 1) != 0) {
        fprintf(stderr, "[FLOW] send 1 failed\n");
        return 1;
    }
    if (fut_fipc_send(ch, 0xF101u, "B", 1) != 0) {
        fprintf(stderr, "[FLOW] send 2 failed\n");
        return 1;
    }
    int rc = fut_fipc_send(ch, 0xF102u, "C", 1);
    if (rc == 0 || rc != FIPC_EAGAIN) {
        fprintf(stderr, "[FLOW] expected backpressure (rc=%d)\n", rc);
        return 1;
    }

    if (fut_fipc_refill_credits(ch, 2) != 0) {
        fprintf(stderr, "[FLOW] refill failed\n");
        return 1;
    }
    if (fut_fipc_send(ch, 0xF103u, "D", 1) != 0) {
        fprintf(stderr, "[FLOW] send after refill 1 failed\n");
        return 1;
    }
    if (fut_fipc_send(ch, 0xF104u, "E", 1) != 0) {
        fprintf(stderr, "[FLOW] send after refill 2 failed\n");
        return 1;
    }

    if (ch->drops_backpressure == 0) {
        fprintf(stderr, "[FLOW] drops counter not incremented\n");
        return 1;
    }

    if (fut_fipc_publish_kernel_metrics() != 0) {
        fprintf(stderr, "[FLOW] kernel metrics publish failed\n");
        return 1;
    }

    printf("[FLOW] credit window enforcement — PASS\n");
    return 0;
}
