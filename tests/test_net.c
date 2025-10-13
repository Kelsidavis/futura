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

    const char *provider = fut_net_primary_provider();
    fut_printf("[FUTURANET-TEST] provider=%s\n", provider);

    /* Burst test */
    const size_t burst = 64;
    size_t sent = 0;
    for (size_t i = 0; i < burst; ++i) {
        uint8_t frame[64];
        size_t idx = 0;
        memcpy(&frame[idx], k_dst_broadcast, sizeof(k_dst_broadcast));
        idx += sizeof(k_dst_broadcast);
        memcpy(&frame[idx], k_src_local, sizeof(k_src_local));
        idx += sizeof(k_src_local);
        frame[idx++] = 0x88;
        frame[idx++] = 0xB5;
        frame[idx++] = (uint8_t)(i & 0xFF);
        frame[idx++] = (uint8_t)((i >> 8) & 0xFF);
        frame[idx++] = 0xA5;
        frame[idx++] = 0x5A;

        rc = fut_net_send(socket, frame, idx);
        if (rc != 0) {
            fut_printf("[FUTURANET-TEST] burst send failed rc=%d at %zu\n", rc, i);
            fut_net_close(socket);
            fut_test_fail(0xE3);
            return;
        }
        sent++;
    }

    size_t received_total = 0;
    for (size_t i = 0; i < sent; ++i) {
        uint8_t rx_buf[96];
        size_t received = 0;
        rc = fut_net_recv_timed(socket, rx_buf, sizeof(rx_buf), &received, FUT_NET_RECV_TIMEOUT_MS);
        if (rc != 0) {
            fut_printf("[FUTURANET-TEST] burst recv failed rc=%d at %zu\n", rc, i);
            fut_net_close(socket);
            fut_test_fail(0xE4);
            return;
        }
        received_total += received;
    }
    fut_printf("[FUTURANET-TEST] burst ok (64/64)\n");

    /* MTU edge tests */
    const size_t mtu = FUT_NET_DEFAULT_MTU;
    uint8_t mtu_buf[FUT_NET_DEFAULT_MTU + 4];
    memset(mtu_buf, 0xAB, sizeof(mtu_buf));
    size_t good_len = mtu - 1;
    rc = fut_net_send(socket, mtu_buf, good_len);
    if (rc != 0) {
        fut_printf("[FUTURANET-TEST] mtu send failed rc=%d\n", rc);
        fut_net_close(socket);
        fut_test_fail(0xE6);
        return;
    }

    size_t recv_len = 0;
    rc = fut_net_recv_timed(socket, mtu_buf, sizeof(mtu_buf), &recv_len, FUT_NET_RECV_TIMEOUT_MS);
    if (rc != 0 || recv_len != good_len) {
        fut_printf("[FUTURANET-TEST] mtu recv mismatch rc=%d len=%zu\n", rc, recv_len);
        fut_net_close(socket);
        fut_test_fail(0xE7);
        return;
    }

    rc = fut_net_send(socket, mtu_buf, mtu + 1);
    if (rc != -EMSGSIZE) {
        fut_printf("[FUTURANET-TEST] mtu oversize rc=%d\n", rc);
        fut_net_close(socket);
        fut_test_fail(0xE8);
        return;
    }
    fut_printf("[FUTURANET-TEST] mtu ok\n");

    /* Timeout behavior */
    size_t timed_len = 0;
    rc = fut_net_recv_timed(socket, mtu_buf, sizeof(mtu_buf), &timed_len, 50);
    if (rc != -EAGAIN) {
        fut_printf("[FUTURANET-TEST] timeout expected EAGAIN rc=%d\n", rc);
        fut_net_close(socket);
        fut_test_fail(0xE9);
        return;
    }
    fut_printf("[FUTURANET-TEST] timeout EAGAIN ok\n");

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
