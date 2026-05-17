/* apple_smc_tests.c - NULL-guard tests for apple_smc Rust FFI
 *
 * Copyright (c) 2026 Kelsi Davis
 * Licensed under the MPL v2.0 — see LICENSE for details.
 *
 * apple_smc backs apple_power's battery / thermal / fan readouts.
 * Every FFI function checks smc.is_null() and returns either -22
 * (EINVAL), 0, or INT_MIN sentinel depending on the return type.
 */

#ifdef __aarch64__

#include <platform/arm64/apple_smc.h>
#include <kernel/kprintf.h>
#include <stdint.h>
#include <stddef.h>
#include <limits.h>

extern void fut_test_pass(void);
extern void fut_test_fail(uint16_t code);

#define SMC_PASS(name) \
    do { \
        fut_printf("[SMC-TEST] PASS: %s\n", name); \
        fut_test_pass(); \
    } while (0)

#define SMC_FAIL(name, code) \
    do { \
        fut_printf("[SMC-TEST] FAIL: %s (code=%u)\n", name, (unsigned)(code)); \
        fut_test_fail((uint16_t)(code)); \
    } while (0)

void fut_apple_smc_test_thread(void *arg)
{
    (void)arg;
    fut_printf("[SMC-TEST] starting apple_smc NULL-guard tests\n");

    /* T1: init(base=0) → NULL */
    {
        if (rust_smc_init(0) == NULL) SMC_PASS("init(base=0)");
        else { SMC_FAIL("init(base=0)", 1); return; }
    }

    /* T2: free(NULL) → no-op */
    {
        rust_smc_free(NULL);
        SMC_PASS("free(NULL) no-op");
    }

    /* T3: read_key(NULL, ...) → -22 */
    {
        uint8_t buf[8] = {0};
        if (rust_smc_read_key(NULL, 0, buf, sizeof(buf)) == -22) {
            SMC_PASS("read_key(NULL smc)");
        } else { SMC_FAIL("read_key(NULL smc)", 3); return; }
    }

    /* T4: write_key(NULL, ...) → -22 */
    {
        uint8_t data[] = {0xDE, 0xAD};
        if (rust_smc_write_key(NULL, 0, data, sizeof(data)) == -22) {
            SMC_PASS("write_key(NULL smc)");
        } else { SMC_FAIL("write_key(NULL smc)", 4); return; }
    }

    /* T5: cpu_temp_mc(NULL) → INT_MIN sentinel */
    {
        if (rust_smc_cpu_temp_mc(NULL) == INT_MIN) SMC_PASS("cpu_temp(NULL)");
        else { SMC_FAIL("cpu_temp(NULL)", 5); return; }
    }

    /* T6: fan0_rpm(NULL) → 0 */
    {
        if (rust_smc_fan0_rpm(NULL) == 0) SMC_PASS("fan0_rpm(NULL)");
        else { SMC_FAIL("fan0_rpm(NULL)", 6); return; }
    }

    /* T7: ac_present(NULL) → 0 */
    {
        if (rust_smc_ac_present(NULL) == 0) SMC_PASS("ac_present(NULL)");
        else { SMC_FAIL("ac_present(NULL)", 7); return; }
    }

    /* T8: key_count(NULL) → 0 */
    {
        if (rust_smc_key_count(NULL) == 0) SMC_PASS("key_count(NULL)");
        else { SMC_FAIL("key_count(NULL)", 8); return; }
    }

    /* T9: key_info(NULL, ...) → -22 */
    {
        SmcKeyInfo info = {0};
        if (rust_smc_key_info(NULL, 0, &info) == -22) {
            SMC_PASS("key_info(NULL smc)");
        } else { SMC_FAIL("key_info(NULL smc)", 9); return; }
    }

    fut_printf("[SMC-TEST] all apple_smc NULL-guard tests passed\n");
}

#else /* !__aarch64__ */

void fut_apple_smc_test_thread(void *arg) { (void)arg; }

#endif /* __aarch64__ */
