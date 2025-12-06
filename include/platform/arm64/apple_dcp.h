/* apple_dcp.h - Apple Display Co-Processor (DCP) Driver Header
 *
 * Copyright (c) 2025 Kelsi Davis
 * Licensed under the MPL v2.0 — see LICENSE for details.
 *
 * Apple DCP driver for display output on Apple Silicon (M1/M2/M3).
 * Uses RTKit mailbox-based IPC similar to ANS2 driver.
 *
 * DCP Protocol Overview:
 * - DCP is a co-processor that manages display pipeline
 * - Uses RTKit for IPC communication
 * - Requires DART IOMMU for framebuffer mapping
 * - Supports mode setting, swap chains, and backlight control
 *
 * Reference: Asahi Linux apple-dcp driver
 */

#ifndef __FUTURA_APPLE_DCP_H__
#define __FUTURA_APPLE_DCP_H__

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>
#include <platform/arm64/dtb.h>

/* ============================================================
 *   DCP Constants
 * ============================================================ */

/* DCP application endpoint (typically 0x20-0x2F range) */
#define APPLE_DCP_ENDPOINT      0x20

/* Maximum number of framebuffer surfaces for swap chain */
#define APPLE_DCP_MAX_SURFACES  4

/* Display pixel formats */
#define APPLE_DCP_FMT_BGRA8888  0x00000001  /* 32-bit BGRA */
#define APPLE_DCP_FMT_RGBA8888  0x00000002  /* 32-bit RGBA */
#define APPLE_DCP_FMT_RGB565    0x00000003  /* 16-bit RGB565 */

/* DCP power states */
#define APPLE_DCP_POWER_OFF     0
#define APPLE_DCP_POWER_ON      1
#define APPLE_DCP_POWER_STANDBY 2

/* DCP message types (based on Asahi Linux reverse engineering) */
#define APPLE_DCP_MSG_SET_MODE      0x0001  /* Set display mode */
#define APPLE_DCP_MSG_SWAP_START    0x0002  /* Start swap to new buffer */
#define APPLE_DCP_MSG_SWAP_COMPLETE 0x0003  /* Swap completed notification */
#define APPLE_DCP_MSG_BACKLIGHT     0x0004  /* Set backlight level */
#define APPLE_DCP_MSG_POWER         0x0005  /* Power state change */
#define APPLE_DCP_MSG_MODE_LIST     0x0006  /* Get available modes */
#define APPLE_DCP_MSG_GET_INFO      0x0007  /* Get display info */

/* ============================================================
 *   DCP Structures
 * ============================================================ */

/* Forward declaration */
struct apple_rtkit_ctx;

/**
 * Display mode information
 */
typedef struct {
    uint32_t width;              /* Horizontal resolution */
    uint32_t height;             /* Vertical resolution */
    uint32_t refresh_rate;       /* Refresh rate in Hz */
    uint32_t pixel_format;       /* Pixel format (APPLE_DCP_FMT_*) */
    uint32_t stride;             /* Bytes per scanline */
} apple_dcp_mode_t;

/**
 * Framebuffer surface descriptor
 */
typedef struct {
    uint64_t phys_addr;          /* Physical address (IOMMU mapped) */
    uint64_t iova;               /* IOMMU virtual address */
    uint32_t width;
    uint32_t height;
    uint32_t stride;
    uint32_t format;
    bool allocated;              /* Surface is allocated */
} apple_dcp_surface_t;

/**
 * DCP controller context
 */
typedef struct {
    /* MMIO base addresses */
    volatile uint8_t *dcp_base;  /* DCP register base (mapped) */
    uint64_t dcp_phys;           /* Physical address */
    uint64_t mailbox_phys;       /* RTKit mailbox physical address */

    /* RTKit co-processor IPC */
    struct apple_rtkit_ctx *rtkit;  /* RTKit context */
    uint8_t dcp_endpoint;        /* DCP application endpoint */

    /* Current display mode */
    apple_dcp_mode_t current_mode;
    bool mode_set;               /* Mode has been set */

    /* Framebuffer surfaces (swap chain) */
    apple_dcp_surface_t surfaces[APPLE_DCP_MAX_SURFACES];
    uint32_t num_surfaces;       /* Number of allocated surfaces */
    uint32_t current_surface;    /* Currently displayed surface */
    uint32_t next_surface;       /* Next surface to display */

    /* Display state */
    uint32_t display_id;         /* Display identifier */
    uint8_t power_state;         /* Current power state */
    uint8_t backlight;           /* Backlight level (0-255) */
    bool display_enabled;        /* Display output enabled */

    /* Synchronization */
    volatile bool swap_pending;  /* Swap is in progress */
    volatile bool swap_complete; /* Swap has completed */

    /* Statistics */
    uint64_t swaps_completed;    /* Total completed swaps */
    uint64_t frames_dropped;     /* Dropped frames due to overrun */
} apple_dcp_ctrl_t;

/* ============================================================
 *   DCP API Functions
 * ============================================================ */

/**
 * Initialize DCP driver.
 * Discovers DCP hardware from device tree and initializes RTKit.
 *
 * @param info: Platform information with DCP addresses
 * @return: DCP controller context, or NULL on failure
 */
apple_dcp_ctrl_t *fut_apple_dcp_init(const fut_platform_info_t *info);

/**
 * Shutdown DCP driver.
 * Powers off display and releases resources.
 *
 * @param dcp: DCP controller context
 */
void fut_apple_dcp_shutdown(apple_dcp_ctrl_t *dcp);

/**
 * Set display mode.
 * Configures display resolution and pixel format.
 *
 * @param dcp: DCP controller context
 * @param width: Horizontal resolution
 * @param height: Vertical resolution
 * @param refresh_rate: Refresh rate in Hz (0 for default)
 * @return: true on success
 */
bool fut_apple_dcp_set_mode(apple_dcp_ctrl_t *dcp, uint32_t width, uint32_t height,
                             uint32_t refresh_rate);

/**
 * Allocate framebuffer surface.
 * Allocates physical memory and maps it through IOMMU for DCP access.
 *
 * @param dcp: DCP controller context
 * @param width: Surface width
 * @param height: Surface height
 * @param format: Pixel format
 * @return: Surface index (0-3), or -1 on failure
 */
int fut_apple_dcp_alloc_surface(apple_dcp_ctrl_t *dcp, uint32_t width, uint32_t height,
                                 uint32_t format);

/**
 * Free framebuffer surface.
 *
 * @param dcp: DCP controller context
 * @param surface_idx: Surface index to free
 */
void fut_apple_dcp_free_surface(apple_dcp_ctrl_t *dcp, int surface_idx);

/**
 * Submit surface for display.
 * Initiates swap to the specified surface.
 *
 * @param dcp: DCP controller context
 * @param surface_idx: Surface index to display
 * @return: true on success
 */
bool fut_apple_dcp_swap_submit(apple_dcp_ctrl_t *dcp, int surface_idx);

/**
 * Wait for swap completion.
 * Blocks until the current swap operation completes.
 *
 * @param dcp: DCP controller context
 * @param timeout_ms: Timeout in milliseconds (0 for no timeout)
 * @return: true if swap completed, false on timeout
 */
bool fut_apple_dcp_swap_wait(apple_dcp_ctrl_t *dcp, uint32_t timeout_ms);

/**
 * Set backlight level.
 *
 * @param dcp: DCP controller context
 * @param level: Backlight level (0-255, 0=off, 255=max)
 * @return: true on success
 */
bool fut_apple_dcp_set_backlight(apple_dcp_ctrl_t *dcp, uint8_t level);

/**
 * Set power state.
 *
 * @param dcp: DCP controller context
 * @param state: Power state (APPLE_DCP_POWER_*)
 * @return: true on success
 */
bool fut_apple_dcp_set_power(apple_dcp_ctrl_t *dcp, uint8_t state);

/**
 * Get surface physical address.
 * Returns the CPU-accessible physical address for drawing.
 *
 * @param dcp: DCP controller context
 * @param surface_idx: Surface index
 * @return: Physical address, or 0 if invalid
 */
uint64_t fut_apple_dcp_get_surface_addr(apple_dcp_ctrl_t *dcp, int surface_idx);

/**
 * Get current display mode.
 *
 * @param dcp: DCP controller context
 * @param mode_out: Output mode information
 * @return: true if mode is set
 */
bool fut_apple_dcp_get_mode(apple_dcp_ctrl_t *dcp, apple_dcp_mode_t *mode_out);

/* ============================================================
 *   Platform Integration
 * ============================================================ */

/**
 * Initialize DCP for platform.
 * Called from platform_init.c for Apple Silicon platforms.
 *
 * @param info: Platform information
 * @return: 0 on success, negative error on failure
 */
int fut_apple_dcp_platform_init(const fut_platform_info_t *info);

/**
 * Probe framebuffer from DCP.
 * Integrates with generic framebuffer layer.
 *
 * @param dcp: DCP controller context
 * @return: 0 on success
 */
int fb_probe_from_dcp(apple_dcp_ctrl_t *dcp);

#endif /* __FUTURA_APPLE_DCP_H__ */
