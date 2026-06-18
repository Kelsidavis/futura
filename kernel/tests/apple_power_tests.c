/* apple_power_tests.c - NULL-guard tests for apple_power public API
 *
 * Copyright (c) 2026 Kelsi Davis
 * Licensed under the MPL v2.0 — see LICENSE for details.
 *
 * apple_power tracks battery / CPU temp / GPU temp / fan RPM via
 * Apple SMC.  Its public accessors all return sentinel values
 * (`-1`, `0x80000000`, `false`, `0`) when the driver hasn't been
 * initialised — on QEMU virt (test platform) initialisation is
 * skipped because there's no SMC.  These tests assert the
 * sentinels fire correctly.  ARM64-only.
 */

#ifdef __aarch64__

#include <platform/arm64/apple_power.h>
#include <kernel/kprintf.h>
#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>

extern void fut_test_pass(void);
extern void fut_test_fail(uint16_t code);

#define POW_PASS(name) \
    do { \
        fut_printf("[POWER-TEST] PASS: %s\n", name); \
        fut_test_pass(); \
    } while (0)

#define POW_FAIL(name, code) \
    do { \
        fut_printf("[POWER-TEST] FAIL: %s (code=%u)\n", name, (unsigned)(code)); \
        fut_test_fail((uint16_t)(code)); \
    } while (0)

void fut_apple_power_test_thread(void *arg)
{
    (void)arg;
    fut_printf("[POWER-TEST] starting apple_power NULL-guard tests\n");

    /* T1: update(NULL state) → -1 */
    {
        int rc = apple_power_update(NULL);
        if (rc == -1) POW_PASS("update(NULL state)");
        else { POW_FAIL("update(NULL state)", 1); return; }
    }

    /* T2: update without init → -1 (g_power_initialized=false) */
    {
        apple_power_state_t state;
        int rc = apple_power_update(&state);
        if (rc == -1) POW_PASS("update(valid state, no init)");
        else { POW_FAIL("update(no init)", 2); return; }
    }

    /* T3: cpu_temp without init → 0x80000000 sentinel */
    {
        int32_t t = apple_power_cpu_temp();
        if ((uint32_t)t == 0x80000000u) POW_PASS("cpu_temp(no init)");
        else { POW_FAIL("cpu_temp(no init)", 3); return; }
    }

    /* T4: gpu_temp without init → 0x80000000 */
    {
        int32_t t = apple_power_gpu_temp();
        if ((uint32_t)t == 0x80000000u) POW_PASS("gpu_temp(no init)");
        else { POW_FAIL("gpu_temp(no init)", 4); return; }
    }

    /* T5: ac_present without init → false */
    {
        if (apple_power_ac_present() == false) {
            POW_PASS("ac_present(no init)");
        } else {
            POW_FAIL("ac_present(no init)", 5);
            return;
        }
    }

    /* T6: battery_pct without init → 0 */
    {
        if (apple_power_battery_pct() == 0) POW_PASS("battery_pct(no init)");
        else { POW_FAIL("battery_pct(no init)", 6); return; }
    }

    /* T7: set_fan_rpm without init → -1 */
    {
        int rc = apple_power_set_fan_rpm(2000);
        if (rc == -1) POW_PASS("set_fan_rpm(no init)");
        else { POW_FAIL("set_fan_rpm(no init)", 7); return; }
    }

    /* T8: ambient_temp without init → 0x80000000 */
    {
        int32_t t = apple_power_ambient_temp();
        if ((uint32_t)t == 0x80000000u) POW_PASS("ambient_temp(no init)");
        else { POW_FAIL("ambient_temp(no init)", 8); return; }
    }

    /* T9: fan_rpm without init → 0 */
    {
        if (apple_power_fan_rpm() == 0) POW_PASS("fan_rpm(no init)");
        else { POW_FAIL("fan_rpm(no init)", 9); return; }
    }

    /* T10: fan_target_rpm without init → 0 */
    {
        if (apple_power_fan_target_rpm() == 0) POW_PASS("fan_target_rpm(no init)");
        else { POW_FAIL("fan_target_rpm(no init)", 10); return; }
    }

    /* T11: platform_init(NULL) → -1 */
    {
        int rc = apple_power_platform_init(NULL);
        if (rc == -1) POW_PASS("platform_init(NULL info)");
        else { POW_FAIL("platform_init(NULL info)", 11); return; }
    }

    fut_printf("[POWER-TEST] all apple_power NULL-guard tests passed\n");
}

#else /* !__aarch64__ */

void fut_apple_power_test_thread(void *arg) { (void)arg; }

#endif /* __aarch64__ */
