/* hci_tests.c - Tests for kernel/hci.c
 *
 * Copyright (c) 2026 Kelsi Davis
 * Licensed under the MPL v2.0 — see LICENSE for details.
 */

#include <kernel/hci.h>
#include <kernel/errno.h>
#include <kernel/kprintf.h>
#include <string.h>

extern void fut_test_pass(void);
extern void fut_test_fail(uint16_t code);

#define HCI_TEST_PASS(name) \
    do { \
        fut_printf("[HCI-TEST] PASS: %s\n", name); \
        fut_test_pass(); \
    } while (0)

#define HCI_TEST_FAIL(name, code) \
    do { \
        fut_printf("[HCI-TEST] FAIL: %s (code=%u)\n", name, (unsigned)(code)); \
        fut_test_fail((uint16_t)(code)); \
    } while (0)

/* ============================================================
 *   Mock HCI transport
 * ============================================================ */

typedef struct {
    int open_calls;
    int close_calls;
    int send_cmd_calls;
    int send_acl_calls;
    uint8_t last_cmd[FUT_HCI_CMD_PKT_MAX];
    size_t  last_cmd_len;
    bool    fail_open;
} mock_state_t;

static int mock_send_cmd(void *cookie, const uint8_t *pkt, size_t len)
{
    mock_state_t *m = (mock_state_t *)cookie;
    m->send_cmd_calls++;
    if (len <= FUT_HCI_CMD_PKT_MAX) {
        memcpy(m->last_cmd, pkt, len);
        m->last_cmd_len = len;
    }
    return 0;
}

static int mock_send_acl(void *cookie, const uint8_t *pkt, size_t len)
{
    mock_state_t *m = (mock_state_t *)cookie;
    (void)pkt;
    (void)len;
    m->send_acl_calls++;
    return 0;
}

static int mock_open(void *cookie)
{
    mock_state_t *m = (mock_state_t *)cookie;
    m->open_calls++;
    return m->fail_open ? -EIO : 0;
}

static void mock_close(void *cookie)
{
    mock_state_t *m = (mock_state_t *)cookie;
    m->close_calls++;
}

static const fut_hci_ops_t mock_ops = {
    .send_cmd = mock_send_cmd,
    .send_acl = mock_send_acl,
    .open     = mock_open,
    .close    = mock_close,
};

/* ============================================================
 *   Tests
 * ============================================================ */

static int sink_events_received;
static uint8_t sink_last_pkt_type;
static int test_sink(void *cookie, uint8_t pkt_type,
                     const uint8_t *pkt, size_t len)
{
    (void)cookie;
    (void)pkt;
    (void)len;
    sink_events_received++;
    sink_last_pkt_type = pkt_type;
    return 0;
}

void fut_hci_test_thread(void *arg)
{
    (void)arg;
    fut_printf("[HCI-TEST] starting HCI core tests\n");
    fut_hci_reset();

    mock_state_t mock = {0};

    /* T1: register with NULL ops → -EINVAL */
    {
        int rc = fut_hci_register("bad", FUT_HCI_TYPE_PCIE, NULL, &mock);
        if (rc == -EINVAL) HCI_TEST_PASS("register(NULL ops)");
        else { HCI_TEST_FAIL("register(NULL ops)", 1); return; }
    }

    /* T2: register with ops missing required callbacks → -EINVAL */
    {
        static const fut_hci_ops_t bad_ops = {0};
        int rc = fut_hci_register("bad", FUT_HCI_TYPE_PCIE, &bad_ops, &mock);
        if (rc == -EINVAL) HCI_TEST_PASS("register(incomplete ops)");
        else { HCI_TEST_FAIL("register(incomplete ops)", 2); return; }
    }

    /* T3: register valid mock → returns index 0 */
    int idx;
    {
        idx = fut_hci_register("mock", FUT_HCI_TYPE_PCIE, &mock_ops, &mock);
        if (idx == 0) HCI_TEST_PASS("register(valid)");
        else { HCI_TEST_FAIL("register(valid)", 3); return; }
    }

    /* T4: dev_count reflects registration */
    {
        if (fut_hci_dev_count() == 1) HCI_TEST_PASS("dev_count after register");
        else { HCI_TEST_FAIL("dev_count after register", 4); return; }
    }

    /* T5: send_cmd before open → -ENODEV */
    {
        uint8_t pkt[] = { 0x03, 0x0C, 0x00 };
        int rc = fut_hci_send_cmd(idx, pkt, sizeof(pkt));
        if (rc == -ENODEV) HCI_TEST_PASS("send_cmd before open");
        else { HCI_TEST_FAIL("send_cmd before open", 5); return; }
    }

    /* T6: dev_open calls ops->open */
    {
        int rc = fut_hci_dev_open(idx);
        if (rc == 0 && mock.open_calls == 1) HCI_TEST_PASS("dev_open");
        else { HCI_TEST_FAIL("dev_open", 6); return; }
    }

    /* T7: send_cmd after open routes to mock */
    {
        uint8_t pkt[] = { 0x03, 0x0C, 0x00 };  /* HCI_Reset opcode */
        int rc = fut_hci_send_cmd(idx, pkt, sizeof(pkt));
        if (rc == 0 && mock.send_cmd_calls == 1 &&
            mock.last_cmd_len == 3 &&
            mock.last_cmd[0] == 0x03 && mock.last_cmd[1] == 0x0C) {
            HCI_TEST_PASS("send_cmd routes to transport");
        } else {
            HCI_TEST_FAIL("send_cmd routes to transport", 7);
            return;
        }
    }

    /* T8: event sink delivery */
    {
        sink_events_received = 0;
        sink_last_pkt_type   = 0;
        fut_hci_set_event_sink(idx, test_sink, NULL);

        uint8_t evt[] = { 0x0E, 0x04, 0x01, 0x03, 0x0C, 0x00 };
        int rc = fut_hci_dispatch_event(idx, FUT_HCI_EVT_PKT,
                                         evt, sizeof(evt));
        if (rc == 0 && sink_events_received == 1 &&
            sink_last_pkt_type == FUT_HCI_EVT_PKT) {
            HCI_TEST_PASS("event sink delivery");
        } else {
            HCI_TEST_FAIL("event sink delivery", 8);
            return;
        }
    }

    /* T9: dispatch with no sink returns 0 (silent drop) */
    {
        fut_hci_set_event_sink(idx, NULL, NULL);
        uint8_t evt[] = { 0x0E, 0x04 };
        int rc = fut_hci_dispatch_event(idx, FUT_HCI_EVT_PKT,
                                         evt, sizeof(evt));
        if (rc == 0) HCI_TEST_PASS("dispatch silently drops without sink");
        else { HCI_TEST_FAIL("dispatch silent drop", 9); return; }
    }

    /* T10: dev_close clears open flag */
    {
        int rc = fut_hci_dev_close(idx);
        if (rc == 0 && mock.close_calls == 1) {
            const fut_hci_dev_t *d = fut_hci_dev_get(idx);
            if (d && !d->open) HCI_TEST_PASS("dev_close clears open");
            else { HCI_TEST_FAIL("dev_close clears open", 10); return; }
        } else { HCI_TEST_FAIL("dev_close", 10); return; }
    }

    /* T11: send_cmd len > FUT_HCI_CMD_PKT_MAX → -EINVAL */
    {
        fut_hci_dev_open(idx);
        static uint8_t big[FUT_HCI_CMD_PKT_MAX + 1];
        int rc = fut_hci_send_cmd(idx, big, sizeof(big));
        if (rc == -EINVAL) HCI_TEST_PASS("send_cmd oversized");
        else { HCI_TEST_FAIL("send_cmd oversized", 11); return; }
    }

    /* T12: unregister removes the device */
    {
        int rc = fut_hci_unregister(idx);
        if (rc == 0 && fut_hci_dev_count() == 0 &&
            fut_hci_dev_get(idx) == NULL) {
            HCI_TEST_PASS("unregister removes device");
        } else {
            HCI_TEST_FAIL("unregister", 12);
            return;
        }
    }

    /* T13: unregister of free slot is idempotent */
    {
        int rc = fut_hci_unregister(idx);
        if (rc == 0) HCI_TEST_PASS("unregister idempotent");
        else { HCI_TEST_FAIL("unregister idempotent", 13); return; }
    }

    /* T14: build_cmd opcode layout (HCI_Reset is 0x0C03 = OGF 0x03, OCF 0x0003) */
    {
        uint8_t pkt[8] = {0};
        int len = fut_hci_build_cmd(FUT_HCI_OP_RESET, NULL, 0,
                                     pkt, sizeof(pkt));
        if (len == 3 && pkt[0] == 0x03 && pkt[1] == 0x0C && pkt[2] == 0x00) {
            HCI_TEST_PASS("build_cmd(HCI_Reset)");
        } else {
            fut_printf("[HCI-TEST] got len=%d pkt=%02x %02x %02x\n",
                       len, pkt[0], pkt[1], pkt[2]);
            HCI_TEST_FAIL("build_cmd(HCI_Reset)", 14);
            return;
        }
    }

    /* T15: build_cmd with params copies payload */
    {
        uint8_t params[] = { 0xDE, 0xAD, 0xBE, 0xEF };
        uint8_t pkt[16] = {0};
        int len = fut_hci_build_cmd(FUT_HCI_OP_LE_SET_SCAN_ENABLE,
                                     params, sizeof(params),
                                     pkt, sizeof(pkt));
        if (len == 7 && pkt[2] == 4 &&
            pkt[3] == 0xDE && pkt[4] == 0xAD &&
            pkt[5] == 0xBE && pkt[6] == 0xEF) {
            HCI_TEST_PASS("build_cmd(with params)");
        } else {
            HCI_TEST_FAIL("build_cmd(with params)", 15);
            return;
        }
    }

    /* T16: build_cmd into too-small buffer → -EINVAL */
    {
        uint8_t params[16];
        uint8_t pkt[5];  /* needs 3 + 16 = 19 */
        memset(params, 0, sizeof(params));
        int len = fut_hci_build_cmd(FUT_HCI_OP_RESET, params, sizeof(params),
                                     pkt, sizeof(pkt));
        if (len == -EINVAL) HCI_TEST_PASS("build_cmd(buffer too small)");
        else { HCI_TEST_FAIL("build_cmd(buffer too small)", 16); return; }
    }

    /* T17: dispatch_event with invalid pkt_type → -EINVAL */
    mock_state_t mock2 = {0};
    int idx2 = -1;
    {
        idx2 = fut_hci_register("mock2", FUT_HCI_TYPE_VIRTIO,
                                 &mock_ops, &mock2);
        if (idx2 < 0) { HCI_TEST_FAIL("re-register for T17", 17); return; }
        fut_hci_dev_open(idx2);
        fut_hci_set_event_sink(idx2, test_sink, NULL);

        uint8_t evt[] = { 0x01, 0x02 };
        int rc = fut_hci_dispatch_event(idx2, 0x00, evt, sizeof(evt));
        int rc2 = fut_hci_dispatch_event(idx2, 0x06, evt, sizeof(evt));
        if (rc == -EINVAL && rc2 == -EINVAL) {
            HCI_TEST_PASS("dispatch_event rejects invalid pkt_type");
        } else {
            HCI_TEST_FAIL("dispatch_event invalid pkt_type", 17);
            return;
        }
    }

    /* T18: dev_find returns the registered index for an exact match */
    {
        int found = fut_hci_dev_find("mock2");
        if (found == idx2) HCI_TEST_PASS("dev_find(exact match)");
        else { HCI_TEST_FAIL("dev_find exact", 18); return; }
    }

    /* T19: dev_find for unknown name returns -ENODEV */
    {
        int found = fut_hci_dev_find("does-not-exist");
        if (found == -ENODEV) HCI_TEST_PASS("dev_find(unknown)");
        else { HCI_TEST_FAIL("dev_find unknown", 19); return; }
    }

    /* T20: dev_find(NULL) returns -EINVAL */
    {
        int found = fut_hci_dev_find(NULL);
        if (found == -EINVAL) HCI_TEST_PASS("dev_find(NULL)");
        else { HCI_TEST_FAIL("dev_find NULL", 20); return; }
    }

    fut_hci_unregister(idx2);

    fut_printf("[HCI-TEST] all HCI core tests passed\n");
    fut_hci_reset();
}
