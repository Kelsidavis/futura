/* apple_dart_tests.c - NULL guards for apple_dart Rust FFI
 *
 * Copyright (c) 2026 Kelsi Davis
 * Licensed under the MPL v2.0 — see LICENSE for details.
 *
 * apple_dart is the Rust IOMMU driver (drivers/rust/apple_dart).
 * Every FFI checks `dart.is_null()` and returns -22 (Rust's EINVAL
 * value, propagated through the FFI as a raw int) or 0/no-op for
 * void functions.  These tests assert those guards.
 */

#ifdef __aarch64__

#include <platform/arm64/apple_dart.h>
#include <kernel/kprintf.h>
#include <stdint.h>
#include <stddef.h>

extern void fut_test_pass(void);
extern void fut_test_fail(uint16_t code);

#define DART_PASS(name) \
    do { \
        fut_printf("[DART-TEST] PASS: %s\n", name); \
        fut_test_pass(); \
    } while (0)

#define DART_FAIL(name, code) \
    do { \
        fut_printf("[DART-TEST] FAIL: %s (code=%u)\n", name, (unsigned)(code)); \
        fut_test_fail((uint16_t)(code)); \
    } while (0)

/* Forward declarations for FFI not in the C header. */
extern int32_t rust_dart_map(AppleDart *dart, uint32_t sid,
                              uint64_t iova, uint64_t phys,
                              uint64_t size, uint32_t prot);
extern int32_t rust_dart_unmap(AppleDart *dart, uint32_t sid,
                                uint64_t iova, uint64_t size);
extern uint64_t rust_dart_iova_to_phys(const AppleDart *dart,
                                        uint32_t sid, uint64_t iova);
extern void rust_dart_flush_tlb_all(const AppleDart *dart);
extern void rust_dart_flush_tlb_stream(const AppleDart *dart, uint32_t sid);

void fut_apple_dart_test_thread(void *arg)
{
    (void)arg;
    fut_printf("[DART-TEST] starting apple_dart NULL-guard tests\n");

    /* T1: free(NULL) → no-op (no crash) */
    {
        rust_dart_free(NULL);
        DART_PASS("free(NULL) no-op");
    }

    /* T2: enable_stream(NULL, ...) → -22 */
    {
        if (rust_dart_enable_stream(NULL, 0) == -22) {
            DART_PASS("enable_stream(NULL)");
        } else { DART_FAIL("enable_stream(NULL)", 2); return; }
    }

    /* T3: disable_stream(NULL, ...) → -22 */
    {
        if (rust_dart_disable_stream(NULL, 0) == -22) {
            DART_PASS("disable_stream(NULL)");
        } else { DART_FAIL("disable_stream(NULL)", 3); return; }
    }

    /* T4: map(NULL, ...) → -22 */
    {
        int32_t rc = rust_dart_map(NULL, 0, 0x1000, 0x2000, 0x1000,
                                    DART_PROT_READ | DART_PROT_WRITE);
        if (rc == -22) DART_PASS("map(NULL)");
        else { DART_FAIL("map(NULL)", 4); return; }
    }

    /* T5: unmap(NULL, ...) → -22 */
    {
        int32_t rc = rust_dart_unmap(NULL, 0, 0x1000, 0x1000);
        if (rc == -22) DART_PASS("unmap(NULL)");
        else { DART_FAIL("unmap(NULL)", 5); return; }
    }

    /* T6: iova_to_phys(NULL, ...) → 0 */
    {
        if (rust_dart_iova_to_phys(NULL, 0, 0x1000) == 0) {
            DART_PASS("iova_to_phys(NULL)");
        } else { DART_FAIL("iova_to_phys(NULL)", 6); return; }
    }

    /* T7: flush_tlb_all(NULL) → no-op */
    {
        rust_dart_flush_tlb_all(NULL);
        DART_PASS("flush_tlb_all(NULL) no-op");
    }

    /* T8: flush_tlb_stream(NULL, ...) → no-op */
    {
        rust_dart_flush_tlb_stream(NULL, 0);
        DART_PASS("flush_tlb_stream(NULL) no-op");
    }

    fut_printf("[DART-TEST] all apple_dart guard tests passed\n");
}

#else /* !__aarch64__ */

void fut_apple_dart_test_thread(void *arg) { (void)arg; }

#endif /* __aarch64__ */
