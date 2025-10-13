// SPDX-License-Identifier: MPL-2.0

#include <futura/net.h>

#include <kernel/errno.h>
#include <kernel/fut_task.h>
#include <kernel/fut_thread.h>

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>

#include "tests/test_api.h"

extern void fut_printf(const char *fmt, ...);

static const uint8_t k_dst_broadcast[6] = {0xff, 0xff, 0xff, 0xff, 0xff, 0xff};
static const uint8_t k_src_local[6] = {0x02, 0x00, 0x00, 0x00, 0x00, 0x01};

static void fut_net_selftest_thread(void *arg) {
    (void)arg;

    fut_socket_t *listener = NULL;
    fut_status_t rc = fut_net_listen(0, &listener);
    if (rc != 0 || !listener) {
        fut_printf("[FUTURANET-TEST] listen failed rc=%d\n", rc);
        fut_test_fail(0xE1);
        return;
    }

    fut_socket_t *socket = NULL;
    rc = fut_net_accept(listener, &socket);
    if (rc != 0 || !socket) {
        fut_printf("[FUTURANET-TEST] accept failed rc=%d\n", rc);
        fut_net_close(listener);
        fut_test_fail(0xE2);
        return;
    }

    const char payload[] = "FuturaNet";
    uint8_t frame[64];
    size_t idx = 0;
    memcpy(&frame[idx], k_dst_broadcast, sizeof(k_dst_broadcast));
    idx += sizeof(k_dst_broadcast);
    memcpy(&frame[idx], k_src_local, sizeof(k_src_local));
    idx += sizeof(k_src_local);
    frame[idx++] = 0x88;
    frame[idx++] = 0xB5;
    memcpy(&frame[idx], payload, sizeof(payload) - 1);
    idx += sizeof(payload) - 1;
    size_t frame_len = idx;

    rc = fut_net_send(socket, frame, frame_len);
    if (rc != 0) {
        fut_printf("[FUTURANET-TEST] send failed rc=%d\n", rc);
        fut_net_close(socket);
        fut_test_fail(0xE3);
        return;
    }
    fut_printf("[FUTURANET-TEST] send len=%zu ✓\n", frame_len);

    uint8_t rx_buf[64];
    size_t received = 0;
    rc = fut_net_recv(socket, rx_buf, sizeof(rx_buf), &received);
    if (rc != 0) {
        fut_printf("[FUTURANET-TEST] recv failed rc=%d\n", rc);
        fut_net_close(socket);
        fut_test_fail(0xE4);
        return;
    }

    bool match = (received == frame_len) && (memcmp(rx_buf, frame, frame_len) == 0);
    if (!match) {
        fut_printf("[FUTURANET-TEST] recv mismatch (got=%zu expected=%zu)\n",
                   received,
                   frame_len);
        fut_net_close(socket);
        fut_test_fail(0xE5);
        return;
    }

    fut_printf("[FUTURANET-TEST] recv len=%zu ✓ match\n", received);

    fut_net_close(socket);
    fut_test_pass();
}

void fut_net_selftest_schedule(fut_task_t *task) {
    if (!task) {
        return;
    }

    fut_thread_t *thread = fut_thread_create(task,
                                             fut_net_selftest_thread,
                                             NULL,
                                             8 * 1024,
                                             150);
    if (!thread) {
        fut_printf("[FUTURANET-TEST] failed to schedule selftest\n");
    }
}
