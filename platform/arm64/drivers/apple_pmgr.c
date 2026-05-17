/* apple_pmgr.c - Apple Silicon Power Manager (clock gate) helper
 *
 * Copyright (c) 2026 Kelsi Davis
 * Licensed under the MPL v2.0 — see LICENSE for details.
 *
 * Implementation of include/platform/arm64/apple_pmgr.h.  Pure MMIO
 * — no Rust crate needed because the operation is a single read-
 * modify-write + poll loop, and the register layout is documented by
 * Asahi rather than requiring driver state.
 *
 * Callers find their peripheral's PS-register byte offset in one of
 * two ways:
 *   1. The DT `apple,power-domain` property on the peripheral's node
 *      (preferred — survives across SoC revisions).
 *   2. A hardcoded constant from Asahi documentation when the DT
 *      doesn't carry the property.
 *
 * This file deliberately doesn't try to do the DT lookup for callers;
 * each driver knows what it needs and what fallback knowledge it has.
 */

#include <platform/arm64/apple_pmgr.h>
#include <platform/platform.h>
#include <kernel/errno.h>

extern void fut_platform_udelay(uint32_t usec);

/* pmgr base in the kernel peripheral VA window — 0 until init. */
static volatile uint32_t *g_pmgr_va;

static inline uint32_t pmgr_r32(uint32_t off)
{
    return g_pmgr_va[off / 4];
}
static inline void pmgr_w32(uint32_t off, uint32_t val)
{
    g_pmgr_va[off / 4] = val;
}

int apple_pmgr_init(const fut_platform_info_t *info)
{
    if (!info || info->pmgr_base == 0) {
        g_pmgr_va = NULL;
        return -ENODEV;
    }
    g_pmgr_va = (volatile uint32_t *)fut_kernel_peripheral_va(info->pmgr_base);
    fut_printf("[pmgr] base PA 0x%lx → VA %p\n",
               (unsigned long)info->pmgr_base, (void *)g_pmgr_va);
    return 0;
}

static int wait_for_state(uint32_t ps_offset, uint8_t want)
{
    /* Apple's pmgr typically completes a transition in <1ms but Asahi
     * uses a 100ms timeout for headroom on the rare slow domain. */
    for (uint32_t spins = 0; spins < 100; spins++) {
        uint32_t reg = pmgr_r32(ps_offset);
        uint8_t actual = (uint8_t)((reg & APPLE_PMGR_PS_ACTUAL_MASK)
                                    >> APPLE_PMGR_PS_ACTUAL_SHIFT);
        if (actual == want) return 0;
        fut_platform_udelay(1000u);
    }
    return -EIO;
}

int apple_pmgr_enable(uint32_t ps_offset)
{
    if (!g_pmgr_va) return -ENODEV;

    uint32_t reg = pmgr_r32(ps_offset);
    uint32_t target = (uint8_t)(reg & APPLE_PMGR_PS_TARGET_MASK);
    if (target == APPLE_PMGR_PS_ON) {
        /* Already requested-on; just confirm the actual state. */
        return wait_for_state(ps_offset, APPLE_PMGR_PS_ON);
    }

    pmgr_w32(ps_offset, (reg & ~APPLE_PMGR_PS_TARGET_MASK)
                          | APPLE_PMGR_PS_ON);

    int rc = wait_for_state(ps_offset, APPLE_PMGR_PS_ON);
    if (rc != 0) {
        fut_printf("[pmgr] enable ps_offset=0x%x timed out "
                   "(reg now=0x%08x)\n",
                   (unsigned)ps_offset,
                   (unsigned)pmgr_r32(ps_offset));
    }
    return rc;
}

int apple_pmgr_disable(uint32_t ps_offset)
{
    if (!g_pmgr_va) return -ENODEV;

    uint32_t reg = pmgr_r32(ps_offset);
    pmgr_w32(ps_offset, reg & ~APPLE_PMGR_PS_TARGET_MASK);
    return wait_for_state(ps_offset, 0);
}

uint8_t apple_pmgr_state(uint32_t ps_offset)
{
    if (!g_pmgr_va) return 0xFFu;
    uint32_t reg = pmgr_r32(ps_offset);
    return (uint8_t)((reg & APPLE_PMGR_PS_ACTUAL_MASK)
                      >> APPLE_PMGR_PS_ACTUAL_SHIFT);
}

/* Pull power-domain phandles from `node_path`'s power-domains
 * property, resolve each to a pmgr-pwrstate node, and enable.  Bound
 * the parse at a small fixed buffer; Apple devices typically list
 * <= 8 power domains. */
#define APPLE_PMGR_MAX_DOMAINS  16

int apple_pmgr_enable_domains_for(uint64_t dtb_ptr, const char *node_path)
{
    if (!g_pmgr_va) return -ENODEV;
    if (!node_path) return -EINVAL;

    uint32_t buf[APPLE_PMGR_MAX_DOMAINS];
    size_t prop_len = fut_dtb_get_property(dtb_ptr, node_path,
                                            "power-domains",
                                            buf, sizeof(buf));
    if (prop_len == 0 || prop_len < sizeof(uint32_t)) {
        return -ENOENT;
    }

    uint32_t ncells = (uint32_t)(prop_len / sizeof(uint32_t));
    if (ncells > APPLE_PMGR_MAX_DOMAINS) ncells = APPLE_PMGR_MAX_DOMAINS;

    int enabled = 0;
    for (uint32_t i = 0; i < ncells; i++) {
        /* DT cells are stored big-endian. */
        uint32_t raw = buf[i];
        uint32_t phandle =
            ((raw & 0xFFu) << 24) |
            ((raw & 0xFF00u) << 8) |
            ((raw & 0xFF0000u) >> 8) |
            ((raw & 0xFF000000u) >> 24);

        int64_t off = fut_dtb_phandle_reg(dtb_ptr, phandle);
        if (off < 0) {
            fut_printf("[pmgr] phandle 0x%x for %s unresolved\n",
                       (unsigned)phandle, node_path);
            continue;
        }
        int rc = apple_pmgr_enable((uint32_t)off);
        if (rc == 0) {
            enabled++;
            fut_printf("[pmgr] %s domain @0x%x: enabled\n",
                       node_path, (unsigned)off);
        } else {
            fut_printf("[pmgr] %s domain @0x%x: enable failed rc=%d\n",
                       node_path, (unsigned)off, rc);
        }
    }

    return enabled;
}
