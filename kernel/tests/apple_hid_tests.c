/* apple_hid_tests.c - NULL/init guards for apple_hid public API
 *
 * Copyright (c) 2026 Kelsi Davis
 * Licensed under the MPL v2.0 — see LICENSE for details.
 *
 * apple_hid drives the SPI keyboard and I2C trackpad on Apple
 * Silicon laptops.  On QEMU virt the Apple-platform branch is
 * skipped, so init never runs and every public function should
 * defensively return its documented sentinel (or simply not crash
 * for callback registration / poll).
 */

#ifdef __aarch64__

#include <platform/arm64/apple_hid.h>
#include <kernel/kprintf.h>
#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>

extern void fut_test_pass(void);
extern void fut_test_fail(uint16_t code);

#define HID_PASS(name) \
    do { \
        fut_printf("[HID-TEST] PASS: %s\n", name); \
        fut_test_pass(); \
    } while (0)

#define HID_FAIL(name, code) \
    do { \
        fut_printf("[HID-TEST] FAIL: %s (code=%u)\n", name, (unsigned)(code)); \
        fut_test_fail((uint16_t)(code)); \
    } while (0)

static void noop_key_cb(uint8_t keycode, uint8_t modifiers, bool pressed)
{
    (void)keycode; (void)modifiers; (void)pressed;
}

void fut_apple_hid_test_thread(void *arg)
{
    (void)arg;
    fut_printf("[HID-TEST] starting apple_hid guard tests\n");

    /* T1: init(NULL info) → -1 */
    {
        if (apple_hid_init(NULL) == -1) HID_PASS("init(NULL info)");
        else { HID_FAIL("init(NULL)", 1); return; }
    }

    /* T2: has_key() without init → false (g_parser is NULL) */
    {
        if (apple_hid_has_key() == false) HID_PASS("has_key(no init)");
        else { HID_FAIL("has_key(no init)", 2); return; }
    }

    /* T3: getchar() without init → 0 */
    {
        if (apple_hid_getchar() == 0) HID_PASS("getchar(no init)");
        else { HID_FAIL("getchar(no init)", 3); return; }
    }

    /* T4: poll() without init → no-op (safe to call) */
    {
        apple_hid_poll();
        HID_PASS("poll(no init) doesn't crash");
    }

    /* T5: register_key_callback() — simple state set, safe with NULL */
    {
        apple_hid_register_key_callback(NULL);
        apple_hid_register_key_callback(noop_key_cb);
        apple_hid_register_key_callback(NULL);
        HID_PASS("register_key_callback set/clear");
    }

    /* T6: register_touch_callback() — same pattern */
    {
        apple_hid_register_touch_callback(NULL);
        HID_PASS("register_touch_callback(NULL)");
    }

    /* T7: platform_init(NULL info) → -1 */
    {
        if (apple_hid_platform_init(NULL) == -1) {
            HID_PASS("platform_init(NULL info)");
        } else {
            HID_FAIL("platform_init(NULL)", 7);
            return;
        }
    }

    fut_printf("[HID-TEST] all apple_hid guard tests passed\n");
}

#else /* !__aarch64__ */

void fut_apple_hid_test_thread(void *arg) { (void)arg; }

#endif /* __aarch64__ */
