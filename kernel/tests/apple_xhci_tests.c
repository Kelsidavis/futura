/* apple_xhci_tests.c - NULL/init guards for apple_xhci public API
 *
 * Copyright (c) 2026 Kelsi Davis
 * Licensed under the MPL v2.0 — see LICENSE for details.
 *
 * apple_xhci hangs off the Apple PCIe RC and drives USB type-C
 * ports on Apple Silicon laptops.  On QEMU virt the Apple-platform
 * branch is skipped; init never runs.  Every public function
 * checks g_xhci.initialized before doing real work.
 */

#ifdef __aarch64__

#include <platform/arm64/apple_xhci.h>
#include <kernel/kprintf.h>
#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>

extern void fut_test_pass(void);
extern void fut_test_fail(uint16_t code);

#define XHCI_PASS(name) \
    do { \
        fut_printf("[XHCI-TEST] PASS: %s\n", name); \
        fut_test_pass(); \
    } while (0)

#define XHCI_FAIL(name, code) \
    do { \
        fut_printf("[XHCI-TEST] FAIL: %s (code=%u)\n", name, (unsigned)(code)); \
        fut_test_fail((uint16_t)(code)); \
    } while (0)

void fut_apple_xhci_test_thread(void *arg)
{
    (void)arg;
    fut_printf("[XHCI-TEST] starting apple_xhci guard tests\n");

    /* T1: init(NULL info) → -1 */
    {
        if (apple_xhci_init(NULL) == -1) XHCI_PASS("init(NULL info)");
        else { XHCI_FAIL("init(NULL)", 1); return; }
    }

    /* T2: enumerate() without init → -1 */
    {
        if (apple_xhci_enumerate() == -1) XHCI_PASS("enumerate(no init)");
        else { XHCI_FAIL("enumerate(no init)", 2); return; }
    }

    /* T3: get_device() without init → false */
    {
        xhci_usb_device_t dev;
        if (apple_xhci_get_device(0, &dev) == false) {
            XHCI_PASS("get_device(no init)");
        } else {
            XHCI_FAIL("get_device(no init)", 3);
            return;
        }
    }

    /* T4: get_device() with NULL out → false */
    {
        if (apple_xhci_get_device(0, NULL) == false) {
            XHCI_PASS("get_device(NULL out)");
        } else {
            XHCI_FAIL("get_device(NULL out)", 4);
            return;
        }
    }

    /* T5: control_transfer without init → -1 */
    {
        uint8_t buf[8] = {0};
        int rc = apple_xhci_control_transfer(0, 0x80, 0x06, 0x0100, 0,
                                              buf, sizeof(buf));
        if (rc == -1) XHCI_PASS("control_transfer(no init)");
        else { XHCI_FAIL("control_transfer(no init)", 5); return; }
    }

    /* T6: bulk_transfer without init → -1 */
    {
        uint8_t buf[8] = {0};
        int rc = apple_xhci_bulk_transfer(0, 0x81, buf, sizeof(buf));
        if (rc == -1) XHCI_PASS("bulk_transfer(no init)");
        else { XHCI_FAIL("bulk_transfer(no init)", 6); return; }
    }

    /* T7: platform_init(NULL info) → -1 */
    {
        if (apple_xhci_platform_init(NULL) == -1) {
            XHCI_PASS("platform_init(NULL info)");
        } else {
            XHCI_FAIL("platform_init(NULL)", 7);
            return;
        }
    }

    fut_printf("[XHCI-TEST] all apple_xhci guard tests passed\n");
}

#else /* !__aarch64__ */

void fut_apple_xhci_test_thread(void *arg) { (void)arg; }

#endif /* __aarch64__ */
