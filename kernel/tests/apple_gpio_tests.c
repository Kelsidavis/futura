/* apple_gpio_tests.c - NULL-guard tests for apple_gpio Rust FFI
 *
 * Copyright (c) 2026 Kelsi Davis
 * Licensed under the MPL v2.0 — see LICENSE for details.
 *
 * apple_gpio drives the Apple pinctrl GPIO controller — used by
 * apple_bcm for WL_REG_ON / BT_REG_ON.  Every function checks
 * gpio.is_null() before dereferencing.
 */

#ifdef __aarch64__

#include <platform/arm64/apple_gpio.h>
#include <kernel/kprintf.h>
#include <stdint.h>
#include <stddef.h>

extern void fut_test_pass(void);
extern void fut_test_fail(uint16_t code);

#define GPIO_PASS(name) \
    do { \
        fut_printf("[GPIO-TEST] PASS: %s\n", name); \
        fut_test_pass(); \
    } while (0)

#define GPIO_FAIL(name, code) \
    do { \
        fut_printf("[GPIO-TEST] FAIL: %s (code=%u)\n", name, (unsigned)(code)); \
        fut_test_fail((uint16_t)(code)); \
    } while (0)

void fut_apple_gpio_test_thread(void *arg)
{
    (void)arg;
    fut_printf("[GPIO-TEST] starting apple_gpio NULL-guard tests\n");

    /* T1: init(base=0, ...) → NULL */
    {
        if (rust_gpio_init(0, 256) == NULL) GPIO_PASS("init(base=0)");
        else { GPIO_FAIL("init(base=0)", 1); return; }
    }

    /* T2: init(base!=0, npins=0) → NULL */
    {
        if (rust_gpio_init(0x1000, 0) == NULL) GPIO_PASS("init(npins=0)");
        else { GPIO_FAIL("init(npins=0)", 2); return; }
    }

    /* T3: free(NULL) → no-op */
    {
        rust_gpio_free(NULL);
        GPIO_PASS("free(NULL) no-op");
    }

    /* T4: set_direction(NULL, ...) → no-op */
    {
        rust_gpio_set_direction(NULL, 5, 1);
        GPIO_PASS("set_direction(NULL) no-op");
    }

    /* T5: get_direction(NULL, ...) → 0 */
    {
        if (rust_gpio_get_direction(NULL, 5) == 0) GPIO_PASS("get_direction(NULL)");
        else { GPIO_FAIL("get_direction(NULL)", 5); return; }
    }

    /* T6: set_output(NULL, ...) → no-op */
    {
        rust_gpio_set_output(NULL, 5, 1);
        GPIO_PASS("set_output(NULL) no-op");
    }

    /* T7: get_input(NULL, ...) → 0 */
    {
        if (rust_gpio_get_input(NULL, 5) == 0) GPIO_PASS("get_input(NULL)");
        else { GPIO_FAIL("get_input(NULL)", 7); return; }
    }

    /* T8: toggle(NULL, ...) → no-op */
    {
        rust_gpio_toggle(NULL, 5);
        GPIO_PASS("toggle(NULL) no-op");
    }

    /* T9: npins(NULL) → 0 */
    {
        if (rust_gpio_npins(NULL) == 0) GPIO_PASS("npins(NULL)");
        else { GPIO_FAIL("npins(NULL)", 9); return; }
    }

    fut_printf("[GPIO-TEST] all apple_gpio NULL-guard tests passed\n");
}

#else /* !__aarch64__ */

void fut_apple_gpio_test_thread(void *arg) { (void)arg; }

#endif /* __aarch64__ */
