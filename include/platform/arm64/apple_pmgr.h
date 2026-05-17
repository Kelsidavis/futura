/* apple_pmgr.h - Apple Silicon Power Manager (clock gate) helper
 *
 * Copyright (c) 2026 Kelsi Davis
 * Licensed under the MPL v2.0 — see LICENSE for details.
 *
 * Apple SoCs gate per-peripheral clocks through the pmgr block.  Each
 * peripheral has a 32-bit power-state register at a fixed offset; the
 * standard layout is:
 *
 *   bits 0-3 (PS_TARGET):   desired power state — software writes 0xF to enable
 *   bits 4-7 (PS_ACTUAL):   current power state — hardware reports back, must
 *                           read 0xF for the clock to be considered live
 *   bits 28-31 (PS_AUTO_*): auto power-down hints, leave at reset defaults
 *
 * Asahi documents the per-peripheral register offsets in the DT
 * `apple,power-domain` property of each device node.  This helper
 * intentionally exposes only the byte offset so callers can pass
 * either a hardcoded constant or a DT-derived value without the
 * driver needing to know the DT format.
 */

#ifndef __FUTURA_APPLE_PMGR_H__
#define __FUTURA_APPLE_PMGR_H__

#include <stdint.h>
#include <stdbool.h>
#include <platform/arm64/dtb.h>

/* PS register bit layout */
#define APPLE_PMGR_PS_TARGET_MASK   0x0000000Fu
#define APPLE_PMGR_PS_ACTUAL_MASK   0x000000F0u
#define APPLE_PMGR_PS_ACTUAL_SHIFT  4
#define APPLE_PMGR_PS_ON            0xFu

/* Initialise pmgr from platform info.  Cached for subsequent
 * apple_pmgr_enable / _disable / _state calls.  Returns 0 on success,
 * -ENODEV when info->pmgr_base is 0 (no DT entry, or not Apple). */
int apple_pmgr_init(const fut_platform_info_t *info);

/* Drive PS_TARGET=0xF for the peripheral whose PS register lives at
 * `ps_offset` bytes from pmgr_base, then poll up to 100ms for
 * PS_ACTUAL to read back 0xF.  Returns 0 on success, -EIO on
 * timeout, -ENODEV when pmgr wasn't initialised. */
int apple_pmgr_enable(uint32_t ps_offset);

/* Inverse of enable: drive PS_TARGET=0 and wait for PS_ACTUAL=0. */
int apple_pmgr_disable(uint32_t ps_offset);

/* Read PS_ACTUAL for a peripheral, or 0xFF on error. */
uint8_t apple_pmgr_state(uint32_t ps_offset);

/* For a DT node at `node_path`, read its `power-domains` property (a
 * list of u32 phandles to pmgr-pwrstate sub-nodes, single-cell per
 * Asahi convention), resolve each phandle to the corresponding pmgr
 * register offset, and call apple_pmgr_enable on it.  Returns the
 * count of domains successfully enabled, or a negative errno.
 *
 * Use case: bring up every power domain a device needs without
 * hardcoding per-SoC tables — read the DT instead.  Each Apple SoC
 * generation (t8103, t6000, t8112, ...) has different pmgr offsets
 * for the same logical domain, but the device's `power-domains`
 * property carries the right phandles for whatever DT m1n1 hands us.
 */
int apple_pmgr_enable_domains_for(uint64_t dtb_ptr, const char *node_path);

/* Convenience wrapper: try a NULL-terminated list of candidate DT
 * paths, calling apple_pmgr_enable_domains_for on each until one
 * returns > 0 (some domain successfully enabled).  Returns the
 * count from the first successful path, or -ENOENT if none matched.
 *
 * Same DT m1n1 / Asahi may name a device under several paths
 * across SoC revisions (`/soc/dcp@…`, `/soc/dcp`, `/arm-io/dcp`);
 * callers list every form they want to support. */
int apple_pmgr_enable_domains_any(uint64_t dtb_ptr,
                                  const char *const *paths);

#endif /* __FUTURA_APPLE_PMGR_H__ */
