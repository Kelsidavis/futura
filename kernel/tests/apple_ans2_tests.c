/* apple_ans2_tests.c - NULL-guard tests for apple_ans2 Rust FFI
 *
 * Copyright (c) 2026 Kelsi Davis
 * Licensed under the MPL v2.0 — see LICENSE for details.
 *
 * apple_ans2 is the Rust Apple NVMe / Storage Controller driver.
 * The C wrapper (apple_ans2.c) is one entry point; this exercises
 * the Rust FFI directly to catch NULL-pointer regressions.
 */

#ifdef __aarch64__

#include <platform/arm64/apple_ans2.h>
#include <kernel/kprintf.h>
#include <stdint.h>
#include <stddef.h>

extern void fut_test_pass(void);
extern void fut_test_fail(uint16_t code);

#define ANS2_PASS(name) \
    do { \
        fut_printf("[ANS2-TEST] PASS: %s\n", name); \
        fut_test_pass(); \
    } while (0)

#define ANS2_FAIL(name, code) \
    do { \
        fut_printf("[ANS2-TEST] FAIL: %s (code=%u)\n", name, (unsigned)(code)); \
        fut_test_fail((uint16_t)(code)); \
    } while (0)

void fut_apple_ans2_test_thread(void *arg)
{
    (void)arg;
    fut_printf("[ANS2-TEST] starting apple_ans2 NULL-guard tests\n");

    /* T1: free(NULL) → no-op */
    {
        rust_ans2_free(NULL);
        ANS2_PASS("free(NULL) no-op");
    }

    /* T2: read(NULL, ...) → -1 */
    {
        uint8_t buf[512] = {0};
        if (rust_ans2_read(NULL, 0, 1, buf) == -1) ANS2_PASS("read(NULL ctrl)");
        else { ANS2_FAIL("read(NULL ctrl)", 2); return; }
    }

    /* T3: write(NULL, ...) → -1 */
    {
        uint8_t buf[512] = {0};
        if (rust_ans2_write(NULL, 0, 1, buf) == -1) ANS2_PASS("write(NULL ctrl)");
        else { ANS2_FAIL("write(NULL ctrl)", 3); return; }
    }

    /* T4: is_ready(NULL) → 0 */
    {
        if (rust_ans2_is_ready(NULL) == 0) ANS2_PASS("is_ready(NULL)");
        else { ANS2_FAIL("is_ready(NULL)", 4); return; }
    }

    /* T5: max_lba(NULL) → 0 */
    {
        if (rust_ans2_max_lba(NULL) == 0) ANS2_PASS("max_lba(NULL)");
        else { ANS2_FAIL("max_lba(NULL)", 5); return; }
    }

    /* T6: sector_size(NULL) → 0 */
    {
        if (rust_ans2_sector_size(NULL) == 0) ANS2_PASS("sector_size(NULL)");
        else { ANS2_FAIL("sector_size(NULL)", 6); return; }
    }

    /* T7: poll(NULL) → no-op */
    {
        rust_ans2_poll(NULL);
        ANS2_PASS("poll(NULL) no-op");
    }

    fut_printf("[ANS2-TEST] all apple_ans2 NULL-guard tests passed\n");
}

#else /* !__aarch64__ */

void fut_apple_ans2_test_thread(void *arg) { (void)arg; }

#endif /* __aarch64__ */
