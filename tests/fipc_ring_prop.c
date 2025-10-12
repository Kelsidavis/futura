// SPDX-License-Identifier: MPL-2.0
#define _POSIX_C_SOURCE 200809L

#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <kernel/fut_fipc.h>
#include "ring_model.h"

static uint64_t prng_state = 0xC0FFEE123456789ULL;

static inline uint32_t prng_next(void) {
    prng_state ^= prng_state << 7;
    prng_state ^= prng_state >> 9;
    prng_state ^= prng_state << 8;
    return (uint32_t)prng_state;
}

int main(void) {
    fut_fipc_init();

    struct fut_fipc_channel *ch = NULL;
    const size_t RING_CAP = 1024;
    if (fut_fipc_channel_create(NULL, NULL, RING_CAP, FIPC_CHANNEL_NONBLOCKING, &ch) != 0 || !ch) {
        fprintf(stderr, "[RING-PROP] channel create failed\n");
        return 1;
    }

    uint8_t model_storage[RING_CAP];
    ring_model_t model;
    rm_init(&model, model_storage, RING_CAP);

    uint8_t payload_buf[65];
    uint8_t model_msg[sizeof(struct fut_fipc_msg) + sizeof(payload_buf)];
    uint8_t drain_buf[2048];

    const int OPS = 100000;
    for (int i = 0; i < OPS; ++i) {
        int op = (int)(prng_next() & 1u);

        if (op == 0) {
            size_t payload_len = prng_next() % sizeof(payload_buf);
            for (size_t j = 0; j < payload_len; ++j) {
                payload_buf[j] = (uint8_t)(prng_next() & 0xFFu);
            }
            size_t msg_bytes = sizeof(struct fut_fipc_msg) + payload_len;
            if (msg_bytes >= RING_CAP) {
                continue; /* message can never fit; skip */
            }
            int rc = fut_fipc_send(ch, 0xEF00u, payload_buf, payload_len);
            if (rc == 0) {
                memset(model_msg, 0xCC, msg_bytes);
                if (rm_push(&model, model_msg, msg_bytes) != 0) {
                    fprintf(stderr, "[RING-PROP] model push failed (free=%zu msg=%zu)\n",
                            rm_free(&model), msg_bytes);
                    return 1;
                }
            } else if (rc == FIPC_EAGAIN) {
                if (rm_free(&model) >= msg_bytes) {
                    fprintf(stderr, "[RING-PROP] send EAGAIN but model free=%zu msg=%zu\n",
                            rm_free(&model), msg_bytes);
                    return 1;
                }
            } else {
                fprintf(stderr, "[RING-PROP] unexpected send rc=%d\n", rc);
                return 1;
            }
        } else {
            ssize_t rc = fut_fipc_recv(ch, drain_buf, sizeof(drain_buf));
            if (rc > 0) {
                if (rm_pop(&model, model_msg, (size_t)rc) != 0) {
                    fprintf(stderr, "[RING-PROP] model pop failed (requested=%zd used=%zu)\n",
                            rc, rm_used(&model));
                    return 1;
                }
            } else if (rc == FIPC_EAGAIN) {
                if (rm_used(&model) != 0) {
                    fprintf(stderr, "[RING-PROP] recv EAGAIN but model used=%zu\n",
                            rm_used(&model));
                    return 1;
                }
            } else {
                fprintf(stderr, "[RING-PROP] unexpected recv rc=%zd\n", rc);
                return 1;
            }
        }
    }

    printf("[RING-PROP] 100k randomized operations — PASS\n");
    return 0;
}
