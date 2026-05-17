/* dtb_walker_tests.c - Tests for fut_dtb_find_compat_u32_cell
 *
 * Copyright (c) 2026 Kelsi Davis
 * Licensed under the MPL v2.0 — see LICENSE for details.
 *
 * Constructs a minimal in-memory DTB that contains one node with a
 * `compatible` string and an `apple,bootstrap-gpios` property, then
 * exercises the walker's compatible-substring match + cell extract.
 *
 * The DTB binary format used here follows the Devicetree
 * Specification Release 0.4-rc1 §5:
 *   - Magic 0xD00DFEED (big-endian)
 *   - Header (40 bytes)
 *   - mem_rsvmap (16 bytes of zeros = empty list)
 *   - structure block (4-byte aligned tokens)
 *   - strings block (concatenated NUL-terminated names)
 */

/* fut_dtb_find_compat_u32_cell lives in kernel/dtb/arm64_dtb.c which
 * is ARM64-only.  Compile this test as a no-op on x86_64 so the
 * symbol-resolution stage doesn't trip. */
#ifdef __aarch64__

#include <stdint.h>
#include <stddef.h>
#include <platform/arm64/dtb.h>
#include <kernel/kprintf.h>
#include <kernel/errno.h>

extern void fut_test_pass(void);
extern void fut_test_fail(uint16_t code);

#define DTB_PASS(name) \
    do { \
        fut_printf("[DTB-TEST] PASS: %s\n", name); \
        fut_test_pass(); \
    } while (0)

#define DTB_FAIL(name, code) \
    do { \
        fut_printf("[DTB-TEST] FAIL: %s (code=%u)\n", name, (unsigned)(code)); \
        fut_test_fail((uint16_t)(code)); \
    } while (0)

/* Pre-built minimal DTB.  Layout offsets:
 *
 *   0x00..0x28  Header (40 bytes)
 *   0x28..0x38  Reserved memory map (zero terminator, 16 bytes)
 *   0x38..0x8C  Structure block (84 bytes)
 *   0x8C..0xAD  Strings block (33 bytes)
 *   total      0xAD = 173 (round up to 0xB0 = 176 below)
 *
 * Structure block payload:
 *   FDT_BEGIN_NODE  ""              root node
 *     FDT_BEGIN_NODE  "test"
 *       FDT_PROP "compatible"             value "bcm4378-test\0"  (13B)
 *       FDT_PROP "apple,bootstrap-gpios"  value <0x1 0xAE 0x0>     (12B)
 *     FDT_END_NODE
 *   FDT_END_NODE
 *   FDT_END
 */
#define DTB_TOTALSIZE 176

static const uint8_t synthetic_dtb[DTB_TOTALSIZE] __attribute__((aligned(8))) = {
    /* ----- Header (40 bytes, all big-endian u32) ----- */
    0xD0, 0x0D, 0xFE, 0xED,  /* magic */
    0x00, 0x00, 0x00, 0xB0,  /* totalsize = 176 */
    0x00, 0x00, 0x00, 0x38,  /* off_dt_struct = 56 */
    0x00, 0x00, 0x00, 0x8C,  /* off_dt_strings = 140 */
    0x00, 0x00, 0x00, 0x28,  /* off_mem_rsvmap = 40 */
    0x00, 0x00, 0x00, 0x11,  /* version = 17 */
    0x00, 0x00, 0x00, 0x10,  /* last_comp_version = 16 */
    0x00, 0x00, 0x00, 0x00,  /* boot_cpuid_phys = 0 */
    0x00, 0x00, 0x00, 0x21,  /* size_dt_strings = 33 */
    0x00, 0x00, 0x00, 0x54,  /* size_dt_struct = 84 */

    /* ----- mem_rsvmap (16 bytes of zeros = empty list) ----- */
    0,0,0,0, 0,0,0,0, 0,0,0,0, 0,0,0,0,

    /* ----- Structure block (84 bytes) ----- */
    /* FDT_BEGIN_NODE "" */
    0x00,0x00,0x00,0x01,  0x00,0x00,0x00,0x00,
    /* FDT_BEGIN_NODE "test" (5 bytes incl. NUL, padded to 8) */
    0x00,0x00,0x00,0x01,
    't','e','s','t', 0x00, 0,0,0,
    /* FDT_PROP { len=13, nameoff=0 } + "bcm4378-test\0" + 3-byte pad */
    0x00,0x00,0x00,0x03,
    0x00,0x00,0x00,0x0D,  /* len = 13 */
    0x00,0x00,0x00,0x00,  /* nameoff -> "compatible" at strings offset 0 */
    'b','c','m','4','3','7','8','-','t','e','s','t', 0x00, 0,0,0,
    /* FDT_PROP { len=12, nameoff=11 } + 3 cells [0x1, 0xAE, 0x0] */
    0x00,0x00,0x00,0x03,
    0x00,0x00,0x00,0x0C,  /* len = 12 */
    0x00,0x00,0x00,0x0B,  /* nameoff -> "apple,bootstrap-gpios" at offset 11 */
    0x00,0x00,0x00,0x01,  /* cell 0: phandle (don't care) */
    0x00,0x00,0x00,0xAE,  /* cell 1: pin number 174 */
    0x00,0x00,0x00,0x00,  /* cell 2: flags */
    /* FDT_END_NODE (close "test") */
    0x00,0x00,0x00,0x02,
    /* FDT_END_NODE (close root) */
    0x00,0x00,0x00,0x02,
    /* FDT_END */
    0x00,0x00,0x00,0x09,

    /* ----- Strings block (33 bytes) ----- */
    'c','o','m','p','a','t','i','b','l','e', 0x00,
    'a','p','p','l','e',',','b','o','o','t','s','t','r','a','p','-','g','p','i','o','s', 0x00,

    /* Padding to 176 */
    0,0,0,
};

void fut_dtb_walker_test_thread(void *arg)
{
    (void)arg;
    fut_printf("[DTB-TEST] starting DT walker tests\n");

    uint64_t dtb = (uint64_t)(uintptr_t)synthetic_dtb;

    /* T1: synthetic DTB validates */
    {
        bool ok = fut_dtb_validate(dtb);
        if (ok) DTB_PASS("validate synthetic DTB");
        else { DTB_FAIL("validate synthetic DTB", 1); return; }
    }

    /* T2: substring match on compatible finds the node, cell 1 = 0xAE */
    {
        int64_t pin = fut_dtb_find_compat_u32_cell(dtb, "bcm4378",
                                                    "apple,bootstrap-gpios", 1);
        if (pin == 0xAE) DTB_PASS("find_compat_u32_cell(cell=1)");
        else {
            fut_printf("[DTB-TEST] got pin=%ld\n", (long)pin);
            DTB_FAIL("find_compat_u32_cell(cell=1)", 2);
            return;
        }
    }

    /* T3: cell 0 returns the phandle value (0x01) */
    {
        int64_t phandle = fut_dtb_find_compat_u32_cell(dtb, "bcm4378",
                                                       "apple,bootstrap-gpios", 0);
        if (phandle == 0x01) DTB_PASS("find_compat_u32_cell(cell=0)");
        else { DTB_FAIL("find_compat_u32_cell(cell=0)", 3); return; }
    }

    /* T4: cell 2 returns flags (0x00) */
    {
        int64_t flags = fut_dtb_find_compat_u32_cell(dtb, "bcm4378",
                                                     "apple,bootstrap-gpios", 2);
        if (flags == 0x00) DTB_PASS("find_compat_u32_cell(cell=2)");
        else { DTB_FAIL("find_compat_u32_cell(cell=2)", 4); return; }
    }

    /* T5: cell 3 exceeds property length → -1 */
    {
        int64_t v = fut_dtb_find_compat_u32_cell(dtb, "bcm4378",
                                                 "apple,bootstrap-gpios", 3);
        if (v == -1) DTB_PASS("find_compat_u32_cell(out-of-range cell)");
        else { DTB_FAIL("find_compat_u32_cell(out-of-range)", 5); return; }
    }

    /* T6: unknown compatible → -1 */
    {
        int64_t v = fut_dtb_find_compat_u32_cell(dtb, "no-such-chip",
                                                 "apple,bootstrap-gpios", 1);
        if (v == -1) DTB_PASS("find_compat_u32_cell(unknown compat)");
        else { DTB_FAIL("find_compat_u32_cell(unknown compat)", 6); return; }
    }

    /* T7: matching compat but unknown property → -1 */
    {
        int64_t v = fut_dtb_find_compat_u32_cell(dtb, "bcm4378",
                                                 "no-such-property", 0);
        if (v == -1) DTB_PASS("find_compat_u32_cell(unknown property)");
        else { DTB_FAIL("find_compat_u32_cell(unknown property)", 7); return; }
    }

    /* T8: NULL inputs → -1 */
    {
        if (fut_dtb_find_compat_u32_cell(dtb, NULL, "foo", 0) == -1 &&
            fut_dtb_find_compat_u32_cell(dtb, "bcm4378", NULL, 0) == -1) {
            DTB_PASS("find_compat_u32_cell(NULL args)");
        } else {
            DTB_FAIL("find_compat_u32_cell(NULL args)", 8);
            return;
        }
    }

    fut_printf("[DTB-TEST] all DT walker tests passed\n");
}

#else /* !__aarch64__ */

/* x86_64 doesn't link kernel/dtb/arm64_dtb.c; runner is a no-op so
 * kernel_main can call it unconditionally.  planned_tests bump is
 * also ARM64-guarded. */
void fut_dtb_walker_test_thread(void *arg) { (void)arg; }

#endif /* __aarch64__ */
