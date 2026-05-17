/* apple_bcm_tests.c - Tests for apple_bcm Rust FFI surface
 *
 * Copyright (c) 2026 Kelsi Davis
 * Licensed under the MPL v2.0 — see LICENSE for details.
 *
 * Exercises the chip-classification + firmware-name lookup paths in
 * the apple_bcm crate (drivers/rust/apple_bcm/src/lib.rs).  The
 * production code calls these functions from PCIe-walk context on
 * Apple hardware — testing them here verifies the FFI surface works
 * on any kernel build and that the chip-ID table matches what the C
 * header declares.
 *
 * Linked unconditionally — the Rust .a is part of the kernel image
 * on both x86_64 and ARM64, so the test runs everywhere.
 */

/* apple_bcm is an Apple Silicon driver — the Rust crate only builds
 * for aarch64-unknown-none, so the FFI symbols (rust_apple_bcm_*)
 * are absent from the x86_64 link.  Compile this test as a no-op
 * outside ARM64. */
#ifdef __aarch64__

#include <platform/arm64/apple_bcm.h>
#include <kernel/kprintf.h>
#include <string.h>
#include <stdint.h>

extern void fut_test_pass(void);
extern void fut_test_fail(uint16_t code);

#define BCM_PASS(name) \
    do { \
        fut_printf("[BCM-TEST] PASS: %s\n", name); \
        fut_test_pass(); \
    } while (0)

#define BCM_FAIL(name, code) \
    do { \
        fut_printf("[BCM-TEST] FAIL: %s (code=%u)\n", name, (unsigned)(code)); \
        fut_test_fail((uint16_t)(code)); \
    } while (0)

static int str_eq(const char *a, const char *b)
{
    if (!a || !b) return 0;
    while (*a && *b) { if (*a != *b) return 0; a++; b++; }
    return *a == 0 && *b == 0;
}

void fut_apple_bcm_test_thread(void *arg)
{
    (void)arg;
    fut_printf("[BCM-TEST] starting apple_bcm FFI tests\n");

    /* T1: BCM4377 (0x14E4:0x4425) → chip id 1 / name "BCM4377" */
    {
        uint32_t chip = rust_apple_bcm_classify(0x14E4, 0x4425);
        if (chip == BCM_CHIP_BCM4377 &&
            str_eq(rust_apple_bcm_chip_name(chip), "BCM4377")) {
            BCM_PASS("classify(BCM4377)");
        } else {
            BCM_FAIL("classify(BCM4377)", 1);
            return;
        }
    }

    /* T2: BCM4378 (0x14E4:0x4433) → chip id 2 / name "BCM4378" */
    {
        uint32_t chip = rust_apple_bcm_classify(0x14E4, 0x4433);
        if (chip == BCM_CHIP_BCM4378 &&
            str_eq(rust_apple_bcm_chip_name(chip), "BCM4378")) {
            BCM_PASS("classify(BCM4378 dev=0x4433)");
        } else {
            BCM_FAIL("classify(BCM4378 dev=0x4433)", 2);
            return;
        }
    }

    /* T3: alt BCM4378 device id (0x4434) → same family */
    {
        uint32_t chip = rust_apple_bcm_classify(0x14E4, 0x4434);
        if (chip == BCM_CHIP_BCM4378) BCM_PASS("classify(BCM4378 dev=0x4434)");
        else { BCM_FAIL("classify(BCM4378 dev=0x4434)", 3); return; }
    }

    /* T4: BCM4387 (M2/M3) */
    {
        uint32_t chip = rust_apple_bcm_classify(0x14E4, 0x4438);
        if (chip == BCM_CHIP_BCM4387 &&
            str_eq(rust_apple_bcm_chip_name(chip), "BCM4387")) {
            BCM_PASS("classify(BCM4387)");
        } else {
            BCM_FAIL("classify(BCM4387)", 4);
            return;
        }
    }

    /* T5: wrong vendor ID → BCM_CHIP_UNKNOWN */
    {
        uint32_t chip = rust_apple_bcm_classify(0x10EC, 0x4425);
        if (chip == BCM_CHIP_UNKNOWN) BCM_PASS("classify(wrong vendor)");
        else { BCM_FAIL("classify(wrong vendor)", 5); return; }
    }

    /* T6: unknown device ID with correct vendor → BCM_CHIP_UNKNOWN */
    {
        uint32_t chip = rust_apple_bcm_classify(0x14E4, 0x9999);
        if (chip == BCM_CHIP_UNKNOWN) BCM_PASS("classify(unknown device)");
        else { BCM_FAIL("classify(unknown device)", 6); return; }
    }

    /* T7: WiFi firmware name follows Asahi pattern */
    {
        const char *fw = rust_apple_bcm_wifi_fw_base(BCM_CHIP_BCM4378);
        if (fw && str_eq(fw, "brcmfmac4378-pcie.apple")) {
            BCM_PASS("wifi_fw_base(BCM4378)");
        } else {
            BCM_FAIL("wifi_fw_base(BCM4378)", 7);
            return;
        }
    }

    /* T8: BT firmware name follows Asahi pattern (capitalised model code) */
    {
        const char *fw = rust_apple_bcm_bt_fw_base(BCM_CHIP_BCM4387);
        if (fw && str_eq(fw, "BCM4387C2")) {
            BCM_PASS("bt_fw_base(BCM4387)");
        } else {
            BCM_FAIL("bt_fw_base(BCM4387)", 8);
            return;
        }
    }

    /* T9: firmware name for unknown chip returns "unknown" (not NULL) */
    {
        const char *fw = rust_apple_bcm_wifi_fw_base(BCM_CHIP_UNKNOWN);
        if (fw && str_eq(fw, "unknown")) BCM_PASS("wifi_fw_base(unknown)");
        else { BCM_FAIL("wifi_fw_base(unknown)", 9); return; }
    }

    /* T10: chip name for unknown id returns "unknown-bcm" */
    {
        const char *name = rust_apple_bcm_chip_name(BCM_CHIP_UNKNOWN);
        if (name && str_eq(name, "unknown-bcm")) BCM_PASS("chip_name(unknown)");
        else { BCM_FAIL("chip_name(unknown)", 10); return; }
    }

    fut_printf("[BCM-TEST] all apple_bcm FFI tests passed\n");
}

#else /* !__aarch64__ */

/* On x86_64 the apple_bcm Rust crate isn't linked.  Provide a stub
 * runner so kernel_main.c can call it unconditionally.  The
 * planned_tests bump is also ARM64-guarded so the counter stays in
 * sync. */
void fut_apple_bcm_test_thread(void *arg) { (void)arg; }

#endif /* __aarch64__ */
