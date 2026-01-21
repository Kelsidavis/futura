// SPDX-License-Identifier: MPL-2.0
/*
 * input_smoke.c - Minimal smoke test for keyboard/mouse event queues
 */

#include <futura/input_event.h>

#include <kernel/fut_vfs.h>
#include <kernel/fut_thread.h>
#include <kernel/fut_timer.h>
#include <kernel/errno.h>

#include <tests/test_api.h>

#include <kernel/kprintf.h>

#define SAMPLE_MS 500u
#define STEP_MS   25u

void fut_input_smoke(void) {
    static int already_run = 0;
    if (already_run) {
        return;
    }
    already_run = 1;

    int kfd = fut_vfs_open("/dev/input/kbd0", O_RDONLY | O_NONBLOCK, 0);
    int mfd = fut_vfs_open("/dev/input/mouse0", O_RDONLY | O_NONBLOCK, 0);

    if (kfd < 0 && mfd < 0) {
        fut_printf("[INPUT-TEST] devices unavailable, skipping\n");
        return;
    }

    uint32_t elapsed = 0;
    uint32_t kbd_events = 0;
    uint32_t mouse_events = 0;

    struct fut_input_event buf[8];

    while (elapsed < SAMPLE_MS) {
        if (kfd >= 0) {
            ssize_t rd = fut_vfs_read(kfd, buf, sizeof(buf));
            if (rd > 0) {
                kbd_events += (uint32_t)(rd / sizeof(struct fut_input_event));
            }
        }
        if (mfd >= 0) {
            ssize_t rd = fut_vfs_read(mfd, buf, sizeof(buf));
            if (rd > 0) {
                mouse_events += (uint32_t)(rd / sizeof(struct fut_input_event));
            }
        }

        fut_thread_sleep(STEP_MS);
        elapsed += STEP_MS;
    }

    if (kfd >= 0) {
        fut_vfs_close(kfd);
    }
    if (mfd >= 0) {
        fut_vfs_close(mfd);
    }

    fut_printf("[INPUT-TEST] kbd events=%u mouse events=%u OK\n",
               kbd_events, mouse_events);
    fut_test_pass();
}
