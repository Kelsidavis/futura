// SPDX-License-Identifier: MPL-2.0
#define _POSIX_C_SOURCE 200809L

#include <stdio.h>
#include <time.h>
#include <kernel/fut_fipc.h>

static void spin_sleep_ms(uint64_t ms) {
    struct timespec ts = {
        .tv_sec = (time_t)(ms / 1000ULL),
        .tv_nsec = (long)((ms % 1000ULL) * 1000000ULL)
    };
    nanosleep(&ts, NULL);
}

int main(void) {
    fut_fipc_init();

    struct fut_fipc_channel *ch = NULL;
    if (fut_fipc_channel_create(NULL, NULL, 1024, FIPC_CHANNEL_NONBLOCKING, &ch) != 0 || !ch) {
        fprintf(stderr, "[RL] channel create failed\n");
        return 1;
    }

    if (fut_fipc_set_rate(ch, 1, 3) != 0) {
        fprintf(stderr, "[RL] set rate failed\n");
        return 1;
    }

    for (int i = 0; i < 3; ++i) {
        if (fut_fipc_send(ch, 0xDD00u + (uint32_t)i, "X", 1) != 0) {
            fprintf(stderr, "[RL] expected send success #%d\n", i);
            return 1;
        }
    }

    for (int i = 0; i < 2; ++i) {
        if (fut_fipc_send(ch, 0xDD10u + (uint32_t)i, "Y", 1) != FIPC_EAGAIN) {
            fprintf(stderr, "[RL] rate limit did not trigger #%d\n", i);
            return 1;
        }
    }

    if (ch->drops_ratelimit < 2) {
        fprintf(stderr, "[RL] drops counter too low\n");
        return 1;
    }

    spin_sleep_ms(4);

    for (int i = 0; i < 3; ++i) {
        int rc = fut_fipc_send(ch, 0xDD20u + (uint32_t)i, "Z", 1);
        if (rc != 0) {
            fprintf(stderr, "[RL] send after refill failed rc=%d\n", rc);
            return 1;
        }
    }

    printf("[RL] token bucket rate limiting — PASS\n");
    return 0;
}
