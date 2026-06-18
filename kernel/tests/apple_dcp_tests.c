/* apple_dcp_tests.c - NULL guards for apple_dcp Rust FFI + C wrapper
 *
 * Copyright (c) 2026 Kelsi Davis
 * Licensed under the MPL v2.0 — see LICENSE for details.
 *
 * Most apple_dcp public surface is the Rust FFI exposed by
 * drivers/rust/apple_dcp.  Every accessor explicitly checks
 * `dcp.is_null()` before dereferencing — these tests assert the
 * NULL guards return the documented sentinel value.
 *
 * Plus one C-wrapper test for fut_apple_dcp_platform_init.
 */

#ifdef __aarch64__

#include <platform/arm64/apple_dcp.h>
#include <kernel/kprintf.h>
#include <stdint.h>
#include <stddef.h>

extern void fut_test_pass(void);
extern void fut_test_fail(uint16_t code);

#define DCP_PASS(name) \
    do { \
        fut_printf("[DCP-TEST] PASS: %s\n", name); \
        fut_test_pass(); \
    } while (0)

#define DCP_FAIL(name, code) \
    do { \
        fut_printf("[DCP-TEST] FAIL: %s (code=%u)\n", name, (unsigned)(code)); \
        fut_test_fail((uint16_t)(code)); \
    } while (0)

void fut_apple_dcp_test_thread(void *arg)
{
    (void)arg;
    fut_printf("[DCP-TEST] starting apple_dcp guard tests\n");

    /* T1: rust_apple_dcp_swap_pending(NULL) → 0 */
    {
        if (rust_apple_dcp_swap_pending(NULL) == 0) {
            DCP_PASS("swap_pending(NULL)");
        } else { DCP_FAIL("swap_pending(NULL)", 1); return; }
    }

    /* T2: rust_apple_dcp_swap_take_complete(NULL) → 0 */
    {
        if (rust_apple_dcp_swap_take_complete(NULL) == 0) {
            DCP_PASS("swap_take_complete(NULL)");
        } else { DCP_FAIL("swap_take_complete(NULL)", 2); return; }
    }

    /* T3: rust_apple_dcp_mode_width(NULL) → 0 */
    {
        if (rust_apple_dcp_mode_width(NULL) == 0) {
            DCP_PASS("mode_width(NULL)");
        } else { DCP_FAIL("mode_width(NULL)", 3); return; }
    }

    /* T4: rust_apple_dcp_mode_height(NULL) → 0 */
    {
        if (rust_apple_dcp_mode_height(NULL) == 0) {
            DCP_PASS("mode_height(NULL)");
        } else { DCP_FAIL("mode_height(NULL)", 4); return; }
    }

    /* T5: rust_apple_dcp_mode_stride(NULL) → 0 */
    {
        if (rust_apple_dcp_mode_stride(NULL) == 0) {
            DCP_PASS("mode_stride(NULL)");
        } else { DCP_FAIL("mode_stride(NULL)", 5); return; }
    }

    /* T6: rust_apple_dcp_mode_format(NULL) → 0 */
    {
        if (rust_apple_dcp_mode_format(NULL) == 0) {
            DCP_PASS("mode_format(NULL)");
        } else { DCP_FAIL("mode_format(NULL)", 6); return; }
    }

    /* T7: rust_apple_dcp_mode_is_set(NULL) → 0 (not set) */
    {
        if (rust_apple_dcp_mode_is_set(NULL) == 0) {
            DCP_PASS("mode_is_set(NULL)");
        } else { DCP_FAIL("mode_is_set(NULL)", 7); return; }
    }

    /* T8: fut_apple_dcp_platform_init(NULL info) → -1 */
    {
        if (fut_apple_dcp_platform_init(NULL) == -1) {
            DCP_PASS("platform_init(NULL info)");
        } else { DCP_FAIL("platform_init(NULL)", 8); return; }
    }

    /* T9: register_surface(NULL, ...) → -1 */
    {
        int32_t rc = rust_apple_dcp_register_surface(NULL, 0x100000,
                                                      1920, 1080, 1920 * 4,
                                                      APPLE_DCP_FMT_BGRA8888);
        if (rc == -1) DCP_PASS("register_surface(NULL)");
        else { DCP_FAIL("register_surface(NULL)", 9); return; }
    }

    /* T10: unregister_surface(NULL, ...) → no-op (no crash) */
    {
        rust_apple_dcp_unregister_surface(NULL, 0);
        DCP_PASS("unregister_surface(NULL) no-op");
    }

    /* T11: surface_iova(NULL, ...) → 0 */
    {
        if (rust_apple_dcp_surface_iova(NULL, 0) == 0) {
            DCP_PASS("surface_iova(NULL)");
        } else { DCP_FAIL("surface_iova(NULL)", 11); return; }
    }

    /* T12: set_mode(NULL, ...) → no-op (no crash) */
    {
        rust_apple_dcp_set_mode(NULL, 1920, 1080, 60, APPLE_DCP_FMT_BGRA8888);
        DCP_PASS("set_mode(NULL) no-op");
    }

    /* T13: get_mode(NULL, &out) → 0 */
    {
        apple_dcp_mode_t out = {0};
        if (rust_apple_dcp_get_mode(NULL, &out) == 0) {
            DCP_PASS("get_mode(NULL dcp)");
        } else { DCP_FAIL("get_mode(NULL dcp)", 13); return; }
    }

    /* T14: swap_submit_build(NULL, ...) → 0 */
    {
        if (rust_apple_dcp_swap_submit_build(NULL, 0) == 0) {
            DCP_PASS("swap_submit_build(NULL)");
        } else { DCP_FAIL("swap_submit_build(NULL)", 14); return; }
    }

    /* T15: set_backlight_msg(NULL, ...) → 0 */
    {
        if (rust_apple_dcp_set_backlight_msg(NULL, 128) == 0) {
            DCP_PASS("set_backlight_msg(NULL)");
        } else { DCP_FAIL("set_backlight_msg(NULL)", 15); return; }
    }

    /* T16: set_power_msg(NULL, ...) → 0 */
    {
        if (rust_apple_dcp_set_power_msg(NULL, APPLE_DCP_POWER_ON) == 0) {
            DCP_PASS("set_power_msg(NULL)");
        } else { DCP_FAIL("set_power_msg(NULL)", 16); return; }
    }

    /* T17: handle_msg(NULL, ...) → 0xFF (unknown message type sentinel) */
    {
        if (rust_apple_dcp_handle_msg(NULL, 0) == 0xFF) {
            DCP_PASS("handle_msg(NULL)");
        } else { DCP_FAIL("handle_msg(NULL)", 17); return; }
    }

    /* T18: rust_apple_dcp_backlight(NULL) → 0 */
    {
        if (rust_apple_dcp_backlight(NULL) == 0) {
            DCP_PASS("rust_backlight(NULL)");
        } else { DCP_FAIL("rust_backlight(NULL)", 18); return; }
    }

    /* T19: rust_apple_dcp_power_state(NULL) → 0 */
    {
        if (rust_apple_dcp_power_state(NULL) == 0) {
            DCP_PASS("rust_power_state(NULL)");
        } else { DCP_FAIL("rust_power_state(NULL)", 19); return; }
    }

    /* T20: apple_dcp_set_backlight without init → -1 */
    {
        if (apple_dcp_set_backlight(128) == -1) {
            DCP_PASS("set_backlight(no init)");
        } else { DCP_FAIL("set_backlight(no init)", 20); return; }
    }

    /* T21: apple_dcp_get_backlight without init → 0xFF */
    {
        if (apple_dcp_get_backlight() == 0xFF) {
            DCP_PASS("get_backlight(no init)");
        } else { DCP_FAIL("get_backlight(no init)", 21); return; }
    }

    /* T22: apple_dcp_set_power(invalid state) → -1
     * (also -1 because not initialised, but exercises the call) */
    {
        if (apple_dcp_set_power(99) == -1) {
            DCP_PASS("set_power(invalid)");
        } else { DCP_FAIL("set_power(invalid)", 22); return; }
    }

    /* T23: apple_dcp_set_power(valid state, but not init) → -1 */
    {
        if (apple_dcp_set_power(APPLE_DCP_POWER_ON) == -1) {
            DCP_PASS("set_power(no init)");
        } else { DCP_FAIL("set_power(no init)", 23); return; }
    }

    /* T24: apple_dcp_get_power_state without init → 0xFF */
    {
        if (apple_dcp_get_power_state() == 0xFF) {
            DCP_PASS("get_power_state(no init)");
        } else { DCP_FAIL("get_power_state(no init)", 24); return; }
    }

    /* T25: apple_dcp_get_mode(NULL out) → -1 */
    {
        if (apple_dcp_get_mode(NULL) == -1) {
            DCP_PASS("get_mode(NULL out)");
        } else { DCP_FAIL("get_mode(NULL out)", 25); return; }
    }

    /* T26: apple_dcp_get_mode(&out) without init → -1 */
    {
        apple_dcp_mode_t out;
        if (apple_dcp_get_mode(&out) == -1) {
            DCP_PASS("get_mode(no init)");
        } else { DCP_FAIL("get_mode(no init)", 26); return; }
    }

    fut_printf("[DCP-TEST] all apple_dcp guard tests passed\n");
}

#else /* !__aarch64__ */

void fut_apple_dcp_test_thread(void *arg) { (void)arg; }

#endif /* __aarch64__ */
