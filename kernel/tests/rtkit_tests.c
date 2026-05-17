/* rtkit_tests.c - apple_rtkit NULL-guard tests
 *
 * Copyright (c) 2026 Kelsi Davis
 * Licensed under the MPL v2.0 — see LICENSE for details.
 *
 * Every apple_rtkit_* public function dereferences a ctx pointer
 * that the caller is trusted to keep valid.  Production code passes
 * the address returned by apple_rtkit_init, which never returns a
 * bad pointer.  But the guards exist to keep a misuse from
 * corrupting random memory; these tests assert they fire.
 *
 * ARM64-only (apple_rtkit lives in platform/arm64/).
 */

#ifdef __aarch64__

#include <platform/arm64/apple_rtkit.h>
#include <kernel/kprintf.h>
#include <stdint.h>
#include <stddef.h>

extern void fut_test_pass(void);
extern void fut_test_fail(uint16_t code);

#define RTK_PASS(name) \
    do { \
        fut_printf("[RTKIT-TEST] PASS: %s\n", name); \
        fut_test_pass(); \
    } while (0)

#define RTK_FAIL(name, code) \
    do { \
        fut_printf("[RTKIT-TEST] FAIL: %s (code=%u)\n", name, (unsigned)(code)); \
        fut_test_fail((uint16_t)(code)); \
    } while (0)

static void noop_handler(void *cookie, uint8_t endpoint, uint64_t msg) {
    (void)cookie; (void)endpoint; (void)msg;
}

void fut_rtkit_test_thread(void *arg)
{
    (void)arg;
    fut_printf("[RTKIT-TEST] starting apple_rtkit NULL-guard tests\n");

    /* T1: init(0) returns NULL — no mailbox addr means no RTKit */
    {
        apple_rtkit_ctx_t *ctx = apple_rtkit_init(0);
        if (ctx == NULL) RTK_PASS("init(mailbox_base=0)");
        else { RTK_FAIL("init(0)", 1); return; }
    }

    /* T2: boot(NULL) returns false */
    {
        if (apple_rtkit_boot(NULL) == false) RTK_PASS("boot(NULL)");
        else { RTK_FAIL("boot(NULL)", 2); return; }
    }

    /* T3: send_message(NULL, ...) returns false */
    {
        if (apple_rtkit_send_message(NULL, 1, 0x1234) == false) {
            RTK_PASS("send_message(NULL ctx)");
        } else {
            RTK_FAIL("send_message(NULL)", 3);
            return;
        }
    }

    /* T4: recv_message(NULL, ...) returns false */
    {
        uint8_t ep = 0;
        uint64_t msg = 0;
        if (apple_rtkit_recv_message(NULL, &ep, &msg) == false) {
            RTK_PASS("recv_message(NULL ctx)");
        } else {
            RTK_FAIL("recv_message(NULL)", 4);
            return;
        }
    }

    /* T5: register_endpoint(NULL, ...) returns false */
    {
        if (apple_rtkit_register_endpoint(NULL, 0x37,
                                           noop_handler, NULL) == false) {
            RTK_PASS("register_endpoint(NULL ctx)");
        } else {
            RTK_FAIL("register_endpoint(NULL)", 5);
            return;
        }
    }

    /* T6: start_endpoint(NULL, ...) returns false */
    {
        if (apple_rtkit_start_endpoint(NULL, 0x37) == false) {
            RTK_PASS("start_endpoint(NULL ctx)");
        } else {
            RTK_FAIL("start_endpoint(NULL)", 6);
            return;
        }
    }

    /* T7: process_messages(NULL) returns 0 */
    {
        if (apple_rtkit_process_messages(NULL) == 0) {
            RTK_PASS("process_messages(NULL ctx)");
        } else {
            RTK_FAIL("process_messages(NULL)", 7);
            return;
        }
    }

    /* T8: shutdown(NULL) doesn't crash */
    {
        apple_rtkit_shutdown(NULL);
        RTK_PASS("shutdown(NULL ctx)");
    }

    fut_printf("[RTKIT-TEST] all apple_rtkit NULL-guard tests passed\n");
}

#else /* !__aarch64__ */

void fut_rtkit_test_thread(void *arg) { (void)arg; }

#endif /* __aarch64__ */
