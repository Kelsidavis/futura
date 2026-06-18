/* apple_aic_tests.c - NULL/init guards for apple_aic + apple_ans2
 *
 * Copyright (c) 2026 Kelsi Davis
 * Licensed under the MPL v2.0 — see LICENSE for details.
 *
 * apple_aic is the Apple Interrupt Controller (CPU-local + AIC
 * dispatch).  apple_ans2 is the Apple NVMe / Storage Controller.
 * Both check their respective init flag before doing real work.
 * On QEMU virt neither is initialised; these tests assert the
 * guards return correct sentinels.
 */

#ifdef __aarch64__

#include <platform/arm64/apple_aic.h>
#include <platform/arm64/apple_ans2.h>
#include <kernel/kprintf.h>
#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>

extern void fut_test_pass(void);
extern void fut_test_fail(uint16_t code);

#define AIC_PASS(name) \
    do { \
        fut_printf("[AIC-TEST] PASS: %s\n", name); \
        fut_test_pass(); \
    } while (0)

#define AIC_FAIL(name, code) \
    do { \
        fut_printf("[AIC-TEST] FAIL: %s (code=%u)\n", name, (unsigned)(code)); \
        fut_test_fail((uint16_t)(code)); \
    } while (0)

/* Dummy dispatch target for the register/unregister guard tests —
 * never actually invoked because the AIC isn't initialised on QEMU
 * virt, but gives register_handler a valid non-NULL callback. */
static void aic_test_dummy_handler(uint32_t irq, void *cookie)
{
    (void)irq;
    (void)cookie;
}

void fut_apple_aic_test_thread(void *arg)
{
    (void)arg;
    fut_printf("[AIC-TEST] starting apple_aic + apple_ans2 guard tests\n");

    /* T1: aic_init(NULL info) → false */
    {
        if (fut_apple_aic_init(NULL) == false) AIC_PASS("aic_init(NULL)");
        else { AIC_FAIL("aic_init(NULL)", 1); return; }
    }

    /* T2: is_pending() without init → false */
    {
        if (fut_apple_aic_is_pending(42) == false) AIC_PASS("is_pending(no init)");
        else { AIC_FAIL("is_pending(no init)", 2); return; }
    }

    /* T3: whoami() without init → 0 */
    {
        if (fut_apple_aic_whoami() == 0) AIC_PASS("whoami(no init)");
        else { AIC_FAIL("whoami(no init)", 3); return; }
    }

    /* T4: enable_irq / disable_irq / send_ipi / ack_ipi / ack_irq
     * are void-returning; just confirm they don't crash. */
    {
        fut_apple_aic_enable_irq(42);
        fut_apple_aic_disable_irq(42);
        fut_apple_aic_send_ipi(0, 1);
        fut_apple_aic_ack_ipi(1);
        fut_apple_aic_ack_irq(1);
        AIC_PASS("void operations(no init) don't crash");
    }

    /* T5: ans2_platform_init(NULL info) → false */
    {
        if (fut_apple_ans2_platform_init(NULL) == false) {
            AIC_PASS("ans2_platform_init(NULL)");
        } else {
            AIC_FAIL("ans2_platform_init(NULL)", 5);
            return;
        }
    }

    /* T6: register_handler without init → no-op (no crash) */
    {
        fut_apple_aic_register_handler(42, aic_test_dummy_handler, NULL);
        AIC_PASS("register_handler(no init) doesn't crash");
    }

    /* T7: unregister_handler without init → no-op (no crash) */
    {
        fut_apple_aic_unregister_handler(42);
        AIC_PASS("unregister_handler(no init) doesn't crash");
    }

    fut_printf("[AIC-TEST] all apple_aic + apple_ans2 guard tests passed\n");
}

#else /* !__aarch64__ */

void fut_apple_aic_test_thread(void *arg) { (void)arg; }

#endif /* __aarch64__ */
