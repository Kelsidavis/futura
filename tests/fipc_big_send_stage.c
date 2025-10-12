// SPDX-License-Identifier: MPL-2.0
#define _POSIX_C_SOURCE 200809L

#include <stdio.h>
#include <string.h>
#include <kernel/fut_fipc.h>

static int drain_and_verify(struct fut_fipc_channel *ch,
                            size_t expected_msgs,
                            size_t payload_len) {
    size_t total = 0;
    uint8_t buf[128 * 1024];
    size_t offsets[128];
    size_t lengths[128];

    while (total < expected_msgs) {
        int rc = fut_fipc_recv_batch(ch, buf, sizeof(buf), offsets, lengths, 128);
        if (rc == FIPC_EAGAIN) {
            continue;
        }
        if (rc < 0) {
            fprintf(stderr, "[STAGE] recv_batch failed (%d)\n", rc);
            return -1;
        }
        for (int i = 0; i < rc; ++i) {
            struct fut_fipc_msg *msg = (struct fut_fipc_msg *)(buf + offsets[i]);
            if (msg->type != 0xDADAu) {
                fprintf(stderr, "[STAGE] bad type %08x\n", msg->type);
                return -1;
            }
            if (msg->length != payload_len) {
                fprintf(stderr, "[STAGE] bad length %u\n", msg->length);
                return -1;
            }
            uint8_t expected = (uint8_t)((total + (size_t)i) & 0xFFu);
            for (size_t b = 0; b < payload_len; ++b) {
                if (msg->payload[b] != expected) {
                    fprintf(stderr, "[STAGE] payload mismatch\n");
                    return -1;
                }
            }
        }
        total += (size_t)rc;
    }
    return 0;
}

int main(void) {
    fut_fipc_init();

    struct fut_fipc_channel *ch = NULL;
    if (fut_fipc_channel_create(NULL, NULL, 8 * 1024 * 1024, FIPC_CHANNEL_NONBLOCKING, &ch) != 0 || !ch) {
        fprintf(stderr, "[STAGE] channel create failed\n");
        return 1;
    }

    const size_t payload_len = 4096;
    const size_t message_count = 512;
    size_t staged = 0;
    size_t fallback = 0;

    for (size_t i = 0; i < message_count; ++i) {
        uint8_t *payload_ptr = NULL;
        struct fut_fipc_stage stage = {0};
        int rc = fut_fipc_stage_begin(ch, 0xDADAu, payload_len, &payload_ptr, &stage);
        uint8_t pattern = (uint8_t)(i & 0xFFu);
        if (rc == 0) {
            memset(payload_ptr, pattern, payload_len);
            if (fut_fipc_stage_commit(ch, &stage) != 0) {
                fprintf(stderr, "[STAGE] commit failed\n");
                return 1;
            }
            staged++;
        } else if (rc == FIPC_EAGAIN) {
            uint8_t buf[4096];
            memset(buf, pattern, payload_len);
            if (fut_fipc_send(ch, 0xDADAu, buf, payload_len) != 0) {
                fprintf(stderr, "[STAGE] fallback send failed\n");
                return 1;
            }
            fallback++;
        } else {
            fprintf(stderr, "[STAGE] stage_begin failed (%d)\n", rc);
            return 1;
        }
    }

    if (drain_and_verify(ch, message_count, payload_len) != 0) {
        return 1;
    }

    fut_fipc_channel_destroy(ch);

    printf("[STAGE] staged=%zu fallback=%zu\n", staged, fallback);
    if (staged == 0) {
        fprintf(stderr, "[STAGE] staging path not exercised\n");
        return 1;
    }

    printf("[STAGE] zero-copy staging exercised — PASS\n");
    return 0;
}
