/* pmgr_tests.c - Tests for apple_pmgr error paths
 *
 * Copyright (c) 2026 Kelsi Davis
 * Licensed under the MPL v2.0 — see LICENSE for details.
 *
 * apple_pmgr is initialised inside the Apple-platform branch of
 * fut_platform_init.  On QEMU virt (where the kernel test harness
 * runs) it stays uninitialised, so every call into it hits the
 * no-init guard paths.  These tests assert those guard paths
 * return the documented errno values rather than e.g. crashing on
 * a NULL MMIO dereference.  ARM64-only because apple_pmgr lives in
 * platform/arm64/.
 */

#ifdef __aarch64__

#include <platform/arm64/apple_pmgr.h>
#include <kernel/errno.h>
#include <kernel/kprintf.h>
#include <stdint.h>
#include <stddef.h>

extern void fut_test_pass(void);
extern void fut_test_fail(uint16_t code);

#define PMGR_PASS(name) \
    do { \
        fut_printf("[PMGR-TEST] PASS: %s\n", name); \
        fut_test_pass(); \
    } while (0)

#define PMGR_FAIL(name, code) \
    do { \
        fut_printf("[PMGR-TEST] FAIL: %s (code=%u)\n", name, (unsigned)(code)); \
        fut_test_fail((uint16_t)(code)); \
    } while (0)

void fut_pmgr_test_thread(void *arg)
{
    (void)arg;
    fut_printf("[PMGR-TEST] starting apple_pmgr error-path tests\n");

    /* T1: apple_pmgr_enable without init returns -ENODEV */
    {
        int rc = apple_pmgr_enable(0x100);
        if (rc == -ENODEV) PMGR_PASS("enable without init");
        else { PMGR_FAIL("enable without init", 1); return; }
    }

    /* T2: apple_pmgr_disable without init returns -ENODEV */
    {
        int rc = apple_pmgr_disable(0x100);
        if (rc == -ENODEV) PMGR_PASS("disable without init");
        else { PMGR_FAIL("disable without init", 2); return; }
    }

    /* T3: apple_pmgr_state without init returns 0xFF sentinel */
    {
        uint8_t s = apple_pmgr_state(0x100);
        if (s == 0xFFu) PMGR_PASS("state without init");
        else { PMGR_FAIL("state without init", 3); return; }
    }

    /* T4: apple_pmgr_enable_domains_for with NULL node_path → -EINVAL */
    {
        int rc = apple_pmgr_enable_domains_for(0, NULL);
        if (rc == -EINVAL || rc == -ENODEV) {
            PMGR_PASS("enable_domains_for(NULL path)");
        } else {
            PMGR_FAIL("enable_domains_for(NULL path)", 4);
            return;
        }
    }

    /* T5: apple_pmgr_enable_domains_any with NULL list → -EINVAL */
    {
        int rc = apple_pmgr_enable_domains_any(0, NULL);
        if (rc == -EINVAL) PMGR_PASS("enable_domains_any(NULL list)");
        else { PMGR_FAIL("enable_domains_any(NULL list)", 5); return; }
    }

    /* T6: apple_pmgr_enable_domains_any with empty list → -ENOENT */
    {
        static const char *const empty_list[] = { NULL };
        int rc = apple_pmgr_enable_domains_any(0, empty_list);
        if (rc == -ENOENT) PMGR_PASS("enable_domains_any(empty list)");
        else { PMGR_FAIL("enable_domains_any(empty)", 6); return; }
    }

    /* T7: apple_pmgr_stats reads back zero counters on a clean run.
     * (Apple-platform driver init didn't execute under QEMU virt, so
     * no apple_pmgr_enable calls happened.) */
    {
        uint32_t ok = 0xDEAD, fail = 0xBEEF;
        apple_pmgr_stats(&ok, &fail);
        if (ok == 0 && fail == 0) PMGR_PASS("stats clean on non-Apple");
        else {
            fut_printf("[PMGR-TEST] got ok=%u fail=%u\n", ok, fail);
            PMGR_FAIL("stats clean", 7);
            return;
        }
    }

    /* T8: apple_pmgr_stats handles NULL pointers gracefully */
    {
        apple_pmgr_stats(NULL, NULL);
        /* If we got here without crashing, the NULL-guards work. */
        PMGR_PASS("stats(NULL, NULL)");
    }

    /* T9: disable_domains_for without init → -ENODEV */
    {
        int rc = apple_pmgr_disable_domains_for(0, "/soc/dcp");
        if (rc == -ENODEV) PMGR_PASS("disable_domains_for(no init)");
        else { PMGR_FAIL("disable_domains_for(no init)", 9); return; }
    }

    /* T10: disable_domains_any(NULL list) → -EINVAL */
    {
        if (apple_pmgr_disable_domains_any(0, NULL) == -EINVAL) {
            PMGR_PASS("disable_domains_any(NULL list)");
        } else {
            PMGR_FAIL("disable_domains_any(NULL list)", 10);
            return;
        }
    }

    /* T11: disable_domains_any(empty list) → -ENOENT */
    {
        static const char *const empty_list[] = { NULL };
        if (apple_pmgr_disable_domains_any(0, empty_list) == -ENOENT) {
            PMGR_PASS("disable_domains_any(empty list)");
        } else {
            PMGR_FAIL("disable_domains_any(empty list)", 11);
            return;
        }
    }

    /* T12: stats3 reports all three counters; NULL-safe */
    {
        uint32_t en = 0xDEAD, fa = 0xBEEF, di = 0xC0DE;
        apple_pmgr_stats3(&en, &fa, &di);
        if (en == 0 && fa == 0 && di == 0) {
            PMGR_PASS("stats3 zero on non-Apple");
        } else {
            fut_printf("[PMGR-TEST] got en=%u fa=%u di=%u\n", en, fa, di);
            PMGR_FAIL("stats3 zero on non-Apple", 12);
            return;
        }
        /* All-NULL must not crash. */
        apple_pmgr_stats3(NULL, NULL, NULL);
        PMGR_PASS("stats3(NULL, NULL, NULL)");
    }

    fut_printf("[PMGR-TEST] all apple_pmgr error-path tests passed\n");
}

#else /* !__aarch64__ */

/* apple_pmgr is ARM64-only; x86_64 link doesn't pull in the symbol. */
void fut_pmgr_test_thread(void *arg) { (void)arg; }

#endif /* __aarch64__ */
