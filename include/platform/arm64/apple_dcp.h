/* apple_dcp.h - Apple Display Co-Processor (DCP) Driver Header
 *
 * Copyright (c) 2025 Kelsi Davis
 * Licensed under the MPL v2.0 — see LICENSE for details.
 *
 * Apple DCP driver for display output on Apple Silicon (M1/M2/M3).
 * Uses RTKit mailbox IPC; DART IOMMU is required to map framebuffer
 * pages into the co-processor's view of memory.
 *
 * The state machine + protocol layer (surface table, swap pending /
 * complete, current mode / backlight / power, RTKit message builders
 * and the receive dispatcher) lives in drivers/rust/apple_dcp.  Page
 * allocation, DART mapping, and the actual RTKit boot orchestration
 * stay in apple_dcp.c so the kernel page allocator and DART driver
 * can be called natively.
 *
 * Reference: Asahi Linux drivers/gpu/drm/apple/dcp.c
 */

#ifndef __FUTURA_APPLE_DCP_H__
#define __FUTURA_APPLE_DCP_H__

#include <stdint.h>
#include <stdbool.h>
#include <platform/arm64/dtb.h>

/* Number of swap-chain surface slots the Rust DCP driver maintains.
 * Must match MAX_SURFACES in drivers/rust/apple_dcp/src/lib.rs. */
#define APPLE_DCP_MAX_SURFACES   4

/* DCP pixel formats — used when building modes / surfaces from C. */
#define APPLE_DCP_FMT_BGRA8888  0x00000001
#define APPLE_DCP_FMT_RGBA8888  0x00000002
#define APPLE_DCP_FMT_RGB565    0x00000003

/* DCP power states */
#define APPLE_DCP_POWER_OFF     0
#define APPLE_DCP_POWER_ON      1
#define APPLE_DCP_POWER_STANDBY 2

/* DCP application endpoint */
#define APPLE_DCP_ENDPOINT      0x20

/* ============================================================
 *   Platform Integration
 * ============================================================ */

/**
 * Initialize DCP for the platform.  Called from platform_init.c and
 * kernel_main.c.  Performs DART setup, RTKit boot, mode set, surface
 * allocation, and registers the panel with the generic framebuffer
 * layer.  Gates on info->has_dcp so non-Apple ARM64 builds skip.
 *
 * @return: 0 on success, 0 (not-applicable) on non-Apple platforms,
 *          negative on hard failure.
 */
int fut_apple_dcp_platform_init(const fut_platform_info_t *info);

/* ============================================================
 *   Rust driver FFI (drivers/rust/apple_dcp)
 * ============================================================ */

typedef struct AppleDcp AppleDcp;

typedef struct {
    uint32_t width;
    uint32_t height;
    uint32_t refresh_rate;
    uint32_t pixel_format;
    uint32_t stride;
} apple_dcp_mode_t;

/** Reset the singleton DCP state and return its handle. */
AppleDcp *rust_apple_dcp_new(void);

/** Register a DART-mapped surface.  Returns slot idx (0-3) or -1. */
int32_t rust_apple_dcp_register_surface(AppleDcp *dcp, uint64_t iova,
                                         uint32_t width, uint32_t height,
                                         uint32_t stride, uint32_t format);
void    rust_apple_dcp_unregister_surface(AppleDcp *dcp, int32_t idx);
uint64_t rust_apple_dcp_surface_iova(const AppleDcp *dcp, int32_t idx);

/** Mode getters / setter.  `set_mode` computes stride from format. */
void rust_apple_dcp_set_mode(AppleDcp *dcp, uint32_t width, uint32_t height,
                              uint32_t refresh_rate, uint32_t pixel_format);
int32_t rust_apple_dcp_get_mode(const AppleDcp *dcp, apple_dcp_mode_t *out);
uint32_t rust_apple_dcp_mode_width(const AppleDcp *dcp);
uint32_t rust_apple_dcp_mode_height(const AppleDcp *dcp);
uint32_t rust_apple_dcp_mode_stride(const AppleDcp *dcp);
uint32_t rust_apple_dcp_mode_format(const AppleDcp *dcp);
int32_t  rust_apple_dcp_mode_is_set(const AppleDcp *dcp);

/** Swap-chain state machine. */
uint64_t rust_apple_dcp_swap_submit_build(AppleDcp *dcp, int32_t surface_idx);
int32_t  rust_apple_dcp_swap_pending(const AppleDcp *dcp);
int32_t  rust_apple_dcp_swap_take_complete(AppleDcp *dcp);

/** Backlight / power message builders.  Caller sends via RTKit. */
uint64_t rust_apple_dcp_set_backlight_msg(AppleDcp *dcp, uint8_t level);
uint64_t rust_apple_dcp_set_power_msg(AppleDcp *dcp, uint8_t state);

/** Cached state accessors (no side effects). */
uint8_t  rust_apple_dcp_backlight(const AppleDcp *dcp);
uint8_t  rust_apple_dcp_power_state(const AppleDcp *dcp);

/** RTKit handler thunk target — pass the received 64-bit message in. */
uint8_t  rust_apple_dcp_handle_msg(AppleDcp *dcp, uint64_t msg);

/* ============================================================
 *   Backlight / Power public API (C wrappers)
 *
 * These thin C wrappers compose the Rust message builders with
 * apple_rtkit_send_message so callers don't have to touch RTKit
 * directly.  All four return negative on failure (not initialised
 * or bad arg); set_* return 0 on success, get_* return the cached
 * value or 0xFF / 0xFF sentinel on no-init.
 * ============================================================ */

/**
 * Set the panel backlight level (0..255).
 * @return 0 on success, -1 if DCP isn't up.
 */
int     apple_dcp_set_backlight(uint8_t level);

/**
 * Read the cached backlight level last applied via set_backlight().
 * @return level in 0..255, or 0xFF if DCP isn't up.
 */
uint8_t apple_dcp_get_backlight(void);

/**
 * Set DCP power state (APPLE_DCP_POWER_OFF / ON / STANDBY).
 * @return 0 on success, -1 if DCP isn't up or state is unknown.
 */
int     apple_dcp_set_power(uint8_t state);

/**
 * Read the cached DCP power state.
 * @return APPLE_DCP_POWER_*, or 0xFF if DCP isn't up.
 */
uint8_t apple_dcp_get_power_state(void);

/**
 * Copy the active display mode (resolution / refresh / format / stride)
 * into *out.  This is the C-level counterpart to the backlight/power
 * getters — consumers that want the panel geometry without reaching
 * into the framebuffer layer or the raw Rust FFI use this.
 * @param out: destination mode struct (must be non-NULL).
 * @return 0 on success, -1 if DCP isn't up, out is NULL, or no mode
 *         has been set yet.
 */
int apple_dcp_get_mode(apple_dcp_mode_t *out);

#endif /* __FUTURA_APPLE_DCP_H__ */
