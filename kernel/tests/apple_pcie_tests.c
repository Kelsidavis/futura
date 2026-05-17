/* apple_pcie_tests.c - NULL guards for apple_pcie Rust FFI
 *
 * Copyright (c) 2026 Kelsi Davis
 * Licensed under the MPL v2.0 — see LICENSE for details.
 *
 * apple_pcie exposes a large Rust FFI surface that every Apple PCIe
 * consumer (xHCI, BCM, future MSI users) calls into.  Every function
 * defensively checks `pcie.is_null()` before dereferencing.  These
 * tests assert the documented sentinel for each guard:
 *
 *   - config reads: 0xFFFFFFFF / 0xFFFF / 0xFF (matching PCI "device
 *     not present" semantics)
 *   - port_link_up / speed / width / scan_devices: 0
 *   - find_cap: 0 (no capability found)
 *   - free / setup_msi / handle_irq / cfg_write32: no-op
 */

#ifdef __aarch64__

#include <platform/arm64/apple_pcie.h>
#include <kernel/kprintf.h>
#include <stdint.h>
#include <stddef.h>

extern void fut_test_pass(void);
extern void fut_test_fail(uint16_t code);

#define PCIE_PASS(name) \
    do { \
        fut_printf("[PCIE-TEST] PASS: %s\n", name); \
        fut_test_pass(); \
    } while (0)

#define PCIE_FAIL(name, code) \
    do { \
        fut_printf("[PCIE-TEST] FAIL: %s (code=%u)\n", name, (unsigned)(code)); \
        fut_test_fail((uint16_t)(code)); \
    } while (0)

void fut_apple_pcie_test_thread(void *arg)
{
    (void)arg;
    fut_printf("[PCIE-TEST] starting apple_pcie NULL-guard tests\n");

    /* T1: free(NULL) → no-op */
    {
        rust_apple_pcie_free(NULL);
        PCIE_PASS("free(NULL) no-op");
    }

    /* T2: port_link_up(NULL, 0) → 0 */
    {
        if (rust_apple_pcie_port_link_up(NULL, 0) == 0) {
            PCIE_PASS("port_link_up(NULL)");
        } else { PCIE_FAIL("port_link_up(NULL)", 2); return; }
    }

    /* T3: port_speed(NULL, 0) → 0 */
    {
        if (rust_apple_pcie_port_speed(NULL, 0) == 0) {
            PCIE_PASS("port_speed(NULL)");
        } else { PCIE_FAIL("port_speed(NULL)", 3); return; }
    }

    /* T4: port_width(NULL, 0) → 0 */
    {
        if (rust_apple_pcie_port_width(NULL, 0) == 0) {
            PCIE_PASS("port_width(NULL)");
        } else { PCIE_FAIL("port_width(NULL)", 4); return; }
    }

    /* T5: cfg_read32(NULL, ...) → 0xFFFFFFFF (PCI "device not present") */
    {
        if (rust_apple_pcie_cfg_read32(NULL, 0, 0, 0, 0) == 0xFFFFFFFFu) {
            PCIE_PASS("cfg_read32(NULL) → 0xFFFFFFFF");
        } else { PCIE_FAIL("cfg_read32(NULL)", 5); return; }
    }

    /* T6: cfg_read16(NULL, ...) → 0xFFFF */
    {
        if (rust_apple_pcie_cfg_read16(NULL, 0, 0, 0, 0) == 0xFFFFu) {
            PCIE_PASS("cfg_read16(NULL) → 0xFFFF");
        } else { PCIE_FAIL("cfg_read16(NULL)", 6); return; }
    }

    /* T7: cfg_read8(NULL, ...) → 0xFF */
    {
        if (rust_apple_pcie_cfg_read8(NULL, 0, 0, 0, 0) == 0xFFu) {
            PCIE_PASS("cfg_read8(NULL) → 0xFF");
        } else { PCIE_FAIL("cfg_read8(NULL)", 7); return; }
    }

    /* T8: cfg_write32(NULL, ...) → no-op (no crash) */
    {
        rust_apple_pcie_cfg_write32(NULL, 0, 0, 0, 0, 0xDEADBEEF);
        PCIE_PASS("cfg_write32(NULL) no-op");
    }

    /* T9: find_cap(NULL, ...) → 0 (no capability found) */
    {
        if (rust_apple_pcie_find_cap(NULL, 0, 0, 0, 0x10) == 0) {
            PCIE_PASS("find_cap(NULL)");
        } else { PCIE_FAIL("find_cap(NULL)", 9); return; }
    }

    /* T10: setup_msi(NULL, ...) → no-op */
    {
        rust_apple_pcie_setup_msi(NULL, 0, 0xCAFEBABE, 32);
        PCIE_PASS("setup_msi(NULL) no-op");
    }

    /* T11: handle_irq(NULL, ...) → no-op */
    {
        rust_apple_pcie_handle_irq(NULL, 0);
        PCIE_PASS("handle_irq(NULL) no-op");
    }

    /* T12: scan_devices(NULL) → 0 */
    {
        if (rust_apple_pcie_scan_devices(NULL) == 0) {
            PCIE_PASS("scan_devices(NULL)");
        } else { PCIE_FAIL("scan_devices(NULL)", 12); return; }
    }

    fut_printf("[PCIE-TEST] all apple_pcie NULL-guard tests passed\n");
}

#else /* !__aarch64__ */

void fut_apple_pcie_test_thread(void *arg) { (void)arg; }

#endif /* __aarch64__ */
