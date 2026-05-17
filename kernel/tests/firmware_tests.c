/* firmware_tests.c - Tests for kernel/firmware.c
 *
 * Copyright (c) 2026 Kelsi Davis
 * Licensed under the MPL v2.0 — see LICENSE for details.
 */

#include <kernel/firmware.h>
#include <kernel/errno.h>
#include <kernel/kprintf.h>
#include <stddef.h>

extern void fut_test_pass(void);
extern void fut_test_fail(uint16_t code);

#define FW_TEST_PASS(name) \
    do { \
        fut_printf("[FW-TEST] PASS: %s\n", name); \
        fut_test_pass(); \
    } while (0)

#define FW_TEST_FAIL(name, code) \
    do { \
        fut_printf("[FW-TEST] FAIL: %s (code=%u)\n", name, (unsigned)(code)); \
        fut_test_fail((uint16_t)(code)); \
    } while (0)

static const uint8_t test_blob_alpha[] = "ALPHA-firmware-content";
static const uint8_t test_blob_beta[]  = "BETA-firmware-content";

static int test_provider_count;
static int never_returns_provider(const char *name,
                                  const void **out_data,
                                  size_t *out_size)
{
    (void)name;
    (void)out_data;
    (void)out_size;
    test_provider_count++;
    return -ENOENT;
}

void fut_firmware_test_thread(void *arg)
{
    (void)arg;
    fut_printf("[FW-TEST] starting firmware loader tests\n");

    /* Always start from a clean slate.  Other tests in this run will
     * not have touched firmware state, but apple_bcm_platform_init
     * may have on Apple platforms — wipe so the assertions hold
     * regardless of platform-init order. */
    fut_firmware_reset_providers();

    /* T1: NULL args → -EINVAL */
    {
        const void *d = NULL;
        size_t s = 0;
        if (fut_firmware_load(NULL, &d, &s) == -EINVAL) {
            FW_TEST_PASS("load(NULL name) returns -EINVAL");
        } else {
            FW_TEST_FAIL("load(NULL name)", 1);
            return;
        }
    }

    /* T2: Unknown name → -ENOENT */
    {
        const void *d = NULL;
        size_t s = 0;
        int rc = fut_firmware_load("does-not-exist", &d, &s);
        if (rc == -ENOENT && d == NULL && s == 0) {
            FW_TEST_PASS("load(unknown) returns -ENOENT");
        } else {
            FW_TEST_FAIL("load(unknown)", 2);
            return;
        }
    }

    /* T3: embed + load round-trip */
    {
        int rc = fut_firmware_embed("alpha",
                                     test_blob_alpha,
                                     sizeof(test_blob_alpha));
        if (rc != 0) {
            FW_TEST_FAIL("embed(alpha)", 3);
            return;
        }
        const void *d = NULL;
        size_t s = 0;
        rc = fut_firmware_load("alpha", &d, &s);
        if (rc == 0 && d == test_blob_alpha && s == sizeof(test_blob_alpha)) {
            FW_TEST_PASS("embed+load round-trip");
        } else {
            FW_TEST_FAIL("embed+load round-trip", 4);
            return;
        }
    }

    /* T4: duplicate embed → -EEXIST */
    {
        int rc = fut_firmware_embed("alpha",
                                     test_blob_alpha,
                                     sizeof(test_blob_alpha));
        if (rc == -EEXIST) {
            FW_TEST_PASS("embed(duplicate) returns -EEXIST");
        } else {
            FW_TEST_FAIL("embed(duplicate)", 5);
            return;
        }
    }

    /* T5: embed with NULL data → -EINVAL */
    {
        int rc = fut_firmware_embed("bogus", NULL, 16);
        if (rc == -EINVAL) {
            FW_TEST_PASS("embed(NULL data) returns -EINVAL");
        } else {
            FW_TEST_FAIL("embed(NULL data)", 6);
            return;
        }
    }

    /* T6: embed with size=0 → -EINVAL */
    {
        int rc = fut_firmware_embed("zerosize", test_blob_beta, 0);
        if (rc == -EINVAL) {
            FW_TEST_PASS("embed(size=0) returns -EINVAL");
        } else {
            FW_TEST_FAIL("embed(size=0)", 7);
            return;
        }
    }

    /* T7: load with NULL out_data → -EINVAL */
    {
        size_t s = 0;
        int rc = fut_firmware_load("alpha", NULL, &s);
        if (rc == -EINVAL) {
            FW_TEST_PASS("load(NULL out_data) returns -EINVAL");
        } else {
            FW_TEST_FAIL("load(NULL out_data)", 8);
            return;
        }
    }

    /* T8: provider registration idempotent + walked in order */
    {
        fut_firmware_reset_providers();
        test_provider_count = 0;

        int rc = fut_firmware_register_provider(never_returns_provider);
        if (rc != 0) {
            FW_TEST_FAIL("register_provider(first)", 9);
            return;
        }
        /* Duplicate registration is a silent no-op. */
        rc = fut_firmware_register_provider(never_returns_provider);
        if (rc != 0) {
            FW_TEST_FAIL("register_provider(duplicate)", 10);
            return;
        }

        const void *d = NULL;
        size_t s = 0;
        rc = fut_firmware_load("anything", &d, &s);
        /* never_returns_provider always returns -ENOENT; embedded
         * provider auto-registers via the load path and also has
         * nothing.  Total provider visits: 2 (custom + embedded). */
        if (rc == -ENOENT && test_provider_count == 1) {
            FW_TEST_PASS("register_provider idempotent + walk order");
        } else {
            fut_printf("[FW-TEST] rc=%d visits=%d\n",
                       rc, test_provider_count);
            FW_TEST_FAIL("provider walk", 11);
            return;
        }
    }

    /* T9: NULL probe rejected */
    {
        int rc = fut_firmware_register_provider(NULL);
        if (rc == -EINVAL) {
            FW_TEST_PASS("register_provider(NULL) returns -EINVAL");
        } else {
            FW_TEST_FAIL("register_provider(NULL)", 12);
            return;
        }
    }

    /* T10: reset clears state cleanly */
    {
        fut_firmware_reset_providers();
        int rc = fut_firmware_embed("post-reset",
                                     test_blob_beta,
                                     sizeof(test_blob_beta));
        if (rc != 0) {
            FW_TEST_FAIL("embed after reset", 13);
            return;
        }
        const void *d = NULL;
        size_t s = 0;
        rc = fut_firmware_load("post-reset", &d, &s);
        if (rc == 0 && d == test_blob_beta) {
            FW_TEST_PASS("reset + re-embed round-trip");
        } else {
            FW_TEST_FAIL("reset + re-embed", 14);
            return;
        }
    }

    /* T11: embed_binary computes size correctly */
    {
        fut_firmware_reset_providers();
        const uint8_t *start = test_blob_alpha;
        const uint8_t *end   = test_blob_alpha + sizeof(test_blob_alpha);
        int rc = fut_firmware_embed_binary("binary-alpha", start, end);
        if (rc != 0) {
            FW_TEST_FAIL("embed_binary", 15);
            return;
        }
        const void *d = NULL;
        size_t s = 0;
        rc = fut_firmware_load("binary-alpha", &d, &s);
        if (rc == 0 && d == test_blob_alpha && s == sizeof(test_blob_alpha)) {
            FW_TEST_PASS("embed_binary computes size + roundtrips");
        } else {
            FW_TEST_FAIL("embed_binary round-trip", 16);
            return;
        }
    }

    /* T12: embed_binary with end < start → -EINVAL */
    {
        int rc = fut_firmware_embed_binary("bad",
                                            test_blob_alpha + 5,
                                            test_blob_alpha);
        if (rc == -EINVAL) FW_TEST_PASS("embed_binary(end<start)");
        else { FW_TEST_FAIL("embed_binary bad range", 17); return; }
    }

    /* T13: embed_binary with end == start → -EINVAL (zero size) */
    {
        int rc = fut_firmware_embed_binary("empty",
                                            test_blob_alpha,
                                            test_blob_alpha);
        if (rc == -EINVAL) FW_TEST_PASS("embed_binary(empty)");
        else { FW_TEST_FAIL("embed_binary empty", 18); return; }
    }

    /* T14: count accessors track state correctly */
    {
        fut_firmware_reset_providers();
        if (fut_firmware_provider_count() != 0 ||
            fut_firmware_embed_count() != 0) {
            FW_TEST_FAIL("count zero after reset", 19);
            return;
        }
        if (fut_firmware_embed("count1", test_blob_alpha,
                                sizeof(test_blob_alpha)) != 0) {
            FW_TEST_FAIL("embed for count test", 20);
            return;
        }
        /* embed also lazy-registers the embedded provider, so
         * provider_count goes 0 → 1 and embed_count goes 0 → 1. */
        if (fut_firmware_embed_count() == 1 &&
            fut_firmware_provider_count() == 1) {
            FW_TEST_PASS("count accessors track state");
        } else {
            FW_TEST_FAIL("count accessors", 21);
            return;
        }
    }

    fut_printf("[FW-TEST] all firmware loader tests passed\n");

    /* Leave the firmware table empty so any later platform-init
     * registration (apple_bcm on Apple, future FS provider) starts
     * from a clean state. */
    fut_firmware_reset_providers();
}
