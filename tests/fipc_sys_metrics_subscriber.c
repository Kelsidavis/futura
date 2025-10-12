/* fipc_sys_metrics_subscriber.c - Validate system metrics IDL decoding
 *
 * Copyright (c) 2025 Kelsi Davis
 * Licensed under the MPL v2.0 — see LICENSE for details.
 */

#define _POSIX_C_SOURCE 200809L

#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <time.h>

#include <kernel/fut_fipc.h>
#include <kernel/fut_fipc_sys.h>

#include "../src/user/netd/netd_core.h"
#include "../src/user/sys/fipc_sys.h"

static int receive_once(struct fut_fipc_channel *channel,
                        uint8_t *buffer,
                        size_t buffer_size) {
    for (int i = 0; i < 256; i++) {
        ssize_t rc = fut_fipc_recv(channel, buffer, buffer_size);
        if (rc > 0) {
            return (int)rc;
        }
        if (rc < 0 && rc != FIPC_EAGAIN) {
            return -1;
        }
        struct timespec ts = { .tv_sec = 0, .tv_nsec = 1 * 1000 * 1000 };
        nanosleep(&ts, NULL);
    }
    return -1;
}

int main(void) {
    fut_fipc_init();

    const char *loop_host = "127.0.0.1";
    const uint16_t udp_port = 29500;

    struct netd *nd = netd_bootstrap(loop_host, udp_port);
    if (!nd) {
        fprintf(stderr, "[SYSMET] failed to bootstrap netd\n");
        return 1;
    }

    if (!fipc_sys_publish_metrics(nd)) {
        fprintf(stderr, "[SYSMET] publish to system channel failed\n");
        return 1;
    }

    struct fut_fipc_channel *sys_channel = fut_fipc_channel_lookup(FIPC_SYS_CHANNEL_ID);
    if (!sys_channel) {
        fprintf(stderr, "[SYSMET] system channel not available\n");
        return 1;
    }

    uint8_t buffer[512];
    int bytes = receive_once(sys_channel, buffer, sizeof(buffer));
    if (bytes <= 0) {
        fprintf(stderr, "[SYSMET] no metrics payload received\n");
        return 1;
    }

    struct fut_fipc_msg *msg = (struct fut_fipc_msg *)buffer;
    if (msg->length > sizeof(buffer) - sizeof(*msg)) {
        fprintf(stderr, "[SYSMET] payload length invalid\n");
        return 1;
    }

    struct netd_metrics expected = {0};
    (void)netd_metrics_snapshot(nd, &expected);

    struct netd_metrics decoded = {0};
    if (!fipc_sys_decode_metrics(msg->payload, msg->length, &decoded)) {
        fprintf(stderr, "[SYSMET] decode failed\n");
        return 1;
    }

    if (decoded.lookup_attempts != expected.lookup_attempts ||
        decoded.lookup_hits != expected.lookup_hits ||
        decoded.lookup_miss != expected.lookup_miss ||
        decoded.send_eagain != expected.send_eagain ||
        decoded.tx_frames != expected.tx_frames ||
        decoded.tx_blocked_credits != expected.tx_blocked_credits ||
        decoded.auth_fail != expected.auth_fail ||
        decoded.replay_drop != expected.replay_drop) {
        fprintf(stderr, "[SYSMET] decoded metrics mismatch snapshot\n");
        return 1;
    }

    printf("[SYSMET] system metrics stream decoded — PASS\n");
    netd_shutdown(nd);
    return 0;
}
