// SPDX-License-Identifier: MPL-2.0
// fipc_timer_deadline.c - Timer firing & deadline enforcement smoke test

#define _POSIX_C_SOURCE 200809L

#include <stdio.h>
#include <time.h>
#include <kernel/fut_fipc.h>
#include <kernel/fut_timer.h>
#include <kernel/fut_thread.h>

static volatile int timer_fired = 0;

static void timer_cb(void *arg) {
    (void)arg;
    timer_fired = 1;
}

static void spin_sleep_ms(uint64_t ms) {
    struct timespec ts = {
        .tv_sec = (time_t)(ms / 1000),
        .tv_nsec = (long)((ms % 1000) * 1000000ULL)
    };
    nanosleep(&ts, NULL);
}

int main(void) {
    fut_fipc_init();

    if (fut_timer_start(10, timer_cb, NULL) != 0) {
        fprintf(stderr, "[TMR] timer start failed\n");
        return 1;
    }

    for (int i = 0; i < 100 && !timer_fired; ++i) {
        spin_sleep_ms(1);
    }
    if (!timer_fired) {
        fprintf(stderr, "[TMR] timer did not fire\n");
        return 1;
    }

    struct fut_fipc_channel *ch = NULL;
    if (fut_fipc_channel_create(NULL, NULL, 1024, FIPC_CHANNEL_NONBLOCKING, &ch) != 0 || !ch) {
        fprintf(stderr, "[TMR] channel create failed\n");
        return 1;
    }

    fut_thread_t deadline_thread = {0};
    deadline_thread.tid = 1;
    deadline_thread.priority = 10;
    deadline_thread.base_priority = 10;
    fut_thread_set_current(&deadline_thread);

    uint64_t now = fut_get_ticks();
    fut_thread_set_deadline(now + 1);
    spin_sleep_ms(5);
    int rc = fut_fipc_send(ch, 0xDC01u, "X", 1);
    if (rc != FIPC_EAGAIN) {
        fprintf(stderr, "[TMR] deadline enforcement failed rc=%d\n", rc);
        return 1;
    }
    if (ch->drops_deadline == 0) {
        fprintf(stderr, "[TMR] deadline metrics not incremented\n");
        return 1;
    }

    printf("[TMR] timers + deadlines — PASS\n");
    return 0;
}
