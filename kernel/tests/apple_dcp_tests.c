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

    fut_printf("[DCP-TEST] all apple_dcp guard tests passed\n");
}

#else /* !__aarch64__ */

void fut_apple_dcp_test_thread(void *arg) { (void)arg; }

#endif /* __aarch64__ */
