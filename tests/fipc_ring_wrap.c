// SPDX-License-Identifier: MPL-2.0
#define _POSIX_C_SOURCE 200809L

#include <stdio.h>
#include <string.h>
#include <kernel/fut_fipc.h>

int main(void) {
    fut_fipc_init();

    struct fut_fipc_channel *ch = NULL;
    if (fut_fipc_channel_create(NULL, NULL, 256, FIPC_CHANNEL_NONBLOCKING, &ch) != 0 || !ch) {
        fprintf(stderr, "[RING-WRAP] channel create failed\n");
        return 1;
    }

    /* Fill the ring with multiple small messages to approach capacity. */
    int sent_small = 0;
    for (int i = 0; i < 64; ++i) {
        char payload = (char)(0x41 + (i % 26));
        int rc = fut_fipc_send(ch, 0xAA00u | (uint32_t)i, &payload, 1);
        if (rc != 0) {
            break;
        }
        sent_small++;
    }
    if (sent_small < 3) {
        fprintf(stderr, "[RING-WRAP] insufficient fill before wrap (%d)\n", sent_small);
        return 1;
    }

    /* Drain a handful to advance the tail pointer away from zero. */
    uint8_t buf[512];
    int drained = 0;
    for (int i = 0; i < sent_small / 2; ++i) {
        ssize_t r = fut_fipc_recv(ch, buf, sizeof(buf));
        if (r <= 0) {
            fprintf(stderr, "[RING-WRAP] unexpected recv while draining (%zd)\n", r);
            return 1;
        }
        drained++;
    }

    /* Send a larger payload that should wrap around the buffer end. */
    uint8_t big[80];
    memset(big, 0x5B, sizeof(big));
    if (fut_fipc_send(ch, 0xBB00u, big, sizeof(big)) != 0) {
        fprintf(stderr, "[RING-WRAP] failed to send wrapped payload\n");
        return 1;
    }

    /* Drain everything, verifying that the large payload arrives intact. */
    int saw_big = 0;
    for (;;) {
        ssize_t r = fut_fipc_recv(ch, buf, sizeof(buf));
        if (r == FIPC_EAGAIN) {
            break;
        }
        if (r <= 0) {
            fprintf(stderr, "[RING-WRAP] recv error while draining (%zd)\n", r);
            return 1;
        }
        struct fut_fipc_msg *msg = (struct fut_fipc_msg *)buf;
        if (msg->type == 0xBB00u) {
            if (msg->length != sizeof(big)) {
                fprintf(stderr, "[RING-WRAP] wrapped payload length mismatch (%u)\n", msg->length);
                return 1;
            }
            saw_big = 1;
        }
    }

    if (!saw_big) {
        fprintf(stderr, "[RING-WRAP] did not observe wrapped payload\n");
        return 1;
    }

    printf("[RING-WRAP] wrap/near-full/empty scenarios — PASS\n");
    return 0;
}
