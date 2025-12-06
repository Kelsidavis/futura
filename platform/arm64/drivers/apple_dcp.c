/* apple_dcp.c - Apple Display Co-Processor (DCP) Driver Implementation
 *
 * Copyright (c) 2025 Kelsi Davis
 * Licensed under the MPL v2.0 — see LICENSE for details.
 *
 * Apple DCP driver for display output on Apple Silicon (M1/M2/M3).
 * Uses RTKit mailbox-based IPC for co-processor communication.
 *
 * Implementation follows the pattern established by apple_ans2.c
 * with DCP-specific protocol adaptations.
 *
 * Reference: Asahi Linux apple-dcp driver
 */

#include <platform/arm64/apple_dcp.h>
#include <platform/arm64/apple_rtkit.h>
#include <platform/platform.h>
#include <kernel/fut_memory.h>
#include <string.h>

/* ============================================================
 *   Register Access Macros
 * ============================================================ */

#define DCP_READ32(ctrl, offset) \
    (*((volatile uint32_t *)((ctrl)->dcp_base + (offset))))

#define DCP_WRITE32(ctrl, offset, val) \
    (*((volatile uint32_t *)((ctrl)->dcp_base + (offset))) = (val))

#define DCP_READ64(ctrl, offset) \
    (*((volatile uint64_t *)((ctrl)->dcp_base + (offset))))

#define DCP_WRITE64(ctrl, offset, val) \
    (*((volatile uint64_t *)((ctrl)->dcp_base + (offset))) = (val))

/* ============================================================
 *   DCP Register Offsets (Placeholder - Real offsets TBD)
 * ============================================================ */

/* These offsets are placeholders based on typical Apple SoC patterns.
 * Real offsets must be determined from:
 * 1. Device tree parsing
 * 2. Asahi Linux reverse engineering
 * 3. m1n1 bootloader documentation
 */
#define DCP_REG_CTRL        0x0000  /* Control register */
#define DCP_REG_STATUS      0x0004  /* Status register */
#define DCP_REG_IRQ_STATUS  0x0008  /* Interrupt status */
#define DCP_REG_IRQ_ENABLE  0x000C  /* Interrupt enable */
#define DCP_REG_FB_BASE     0x0100  /* Framebuffer base address */
#define DCP_REG_FB_STRIDE   0x0104  /* Framebuffer stride */
#define DCP_REG_FB_SIZE     0x0108  /* Framebuffer size (W<<16 | H) */
#define DCP_REG_FB_FORMAT   0x010C  /* Framebuffer pixel format */

/* Status bits */
#define DCP_STATUS_READY    (1 << 0)
#define DCP_STATUS_BUSY     (1 << 1)
#define DCP_STATUS_VSYNC    (1 << 2)

/* ============================================================
 *   RTKit Message Handler
 * ============================================================ */

static void apple_dcp_rtkit_handler(void *cookie, uint8_t endpoint, uint64_t msg) {
    apple_dcp_ctrl_t *ctrl = (apple_dcp_ctrl_t *)cookie;

    if (!ctrl) {
        return;
    }

    /* Extract message components */
    uint8_t tag = (msg >> 0) & 0xFF;
    uint8_t type = (msg >> 8) & 0xFF;
    uint16_t code = (msg >> 16) & 0xFFFF;

    /* Log all RTKit messages for debugging */
    fut_printf("[DCP] RTKit message from endpoint 0x%02x: tag=%u type=0x%02x code=0x%04x msg=0x%016lx\n",
               endpoint, tag, type, code, (unsigned long)msg);

    /* Handle specific message types */
    switch (type) {
        case 0x01:  /* Power notification */
            fut_printf("[DCP] RTKit power notification: code=0x%04x\n", code);
            break;

        case 0x02:  /* Error notification */
            fut_printf("[DCP] RTKit error notification: code=0x%04x\n", code);
            break;

        case 0x03:  /* Swap complete notification */
            fut_printf("[DCP] Swap complete notification\n");
            ctrl->swap_pending = false;
            ctrl->swap_complete = true;
            ctrl->swaps_completed++;
            break;

        case 0x04:  /* VSync notification */
            /* VSync event - can be used for synchronization */
            break;

        default:
            fut_printf("[DCP] RTKit unknown message type 0x%02x\n", type);
            break;
    }
}

/* ============================================================
 *   Surface Management
 * ============================================================ */

int fut_apple_dcp_alloc_surface(apple_dcp_ctrl_t *dcp, uint32_t width, uint32_t height,
                                 uint32_t format) {
    if (!dcp) {
        return -1;
    }

    /* Find free surface slot */
    int idx = -1;
    for (int i = 0; i < APPLE_DCP_MAX_SURFACES; i++) {
        if (!dcp->surfaces[i].allocated) {
            idx = i;
            break;
        }
    }

    if (idx < 0) {
        fut_printf("[DCP] No free surface slots\n");
        return -1;
    }

    /* Calculate surface size */
    uint32_t bpp = (format == APPLE_DCP_FMT_RGB565) ? 2 : 4;
    uint32_t stride = width * bpp;
    size_t size = (size_t)stride * height;

    /* Align to page boundary */
    size_t num_pages = (size + 4095) / 4096;
    size = num_pages * 4096;

    /* Allocate physical memory */
    uint64_t phys = (uint64_t)fut_pmm_alloc_pages(num_pages);
    if (phys == 0) {
        fut_printf("[DCP] Failed to allocate surface memory (%lu pages)\n",
                   (unsigned long)num_pages);
        return -1;
    }

    /* Clear the surface */
    memset((void *)phys, 0, size);

    /* Initialize surface descriptor */
    apple_dcp_surface_t *surf = &dcp->surfaces[idx];
    surf->phys_addr = phys;
    surf->iova = phys;  /* TODO: DART IOMMU mapping */
    surf->width = width;
    surf->height = height;
    surf->stride = stride;
    surf->format = format;
    surf->allocated = true;

    dcp->num_surfaces++;

    fut_printf("[DCP] Allocated surface %d: %ux%u, stride=%u, phys=0x%lx\n",
               idx, width, height, stride, (unsigned long)phys);

    return idx;
}

void fut_apple_dcp_free_surface(apple_dcp_ctrl_t *dcp, int surface_idx) {
    if (!dcp || surface_idx < 0 || surface_idx >= APPLE_DCP_MAX_SURFACES) {
        return;
    }

    apple_dcp_surface_t *surf = &dcp->surfaces[surface_idx];
    if (!surf->allocated) {
        return;
    }

    /* TODO: DART IOMMU unmapping */

    /* Free physical memory */
    if (surf->phys_addr) {
        size_t size = (size_t)surf->stride * surf->height;
        size_t num_pages = (size + 4095) / 4096;
        fut_pmm_free_pages((void *)surf->phys_addr, num_pages);
    }

    /* Clear surface descriptor */
    memset(surf, 0, sizeof(apple_dcp_surface_t));
    dcp->num_surfaces--;

    fut_printf("[DCP] Freed surface %d\n", surface_idx);
}

uint64_t fut_apple_dcp_get_surface_addr(apple_dcp_ctrl_t *dcp, int surface_idx) {
    if (!dcp || surface_idx < 0 || surface_idx >= APPLE_DCP_MAX_SURFACES) {
        return 0;
    }

    apple_dcp_surface_t *surf = &dcp->surfaces[surface_idx];
    if (!surf->allocated) {
        return 0;
    }

    return surf->phys_addr;
}

/* ============================================================
 *   Mode Setting
 * ============================================================ */

bool fut_apple_dcp_set_mode(apple_dcp_ctrl_t *dcp, uint32_t width, uint32_t height,
                             uint32_t refresh_rate) {
    if (!dcp || !dcp->rtkit) {
        return false;
    }

    if (refresh_rate == 0) {
        refresh_rate = 60;  /* Default to 60Hz */
    }

    /* Build set mode message
     * Format: [type:8][width:12][height:12][refresh:8][format:8][reserved:16]
     * This is a placeholder format - real format TBD from Asahi Linux
     */
    uint64_t msg = 0;
    msg |= ((uint64_t)APPLE_DCP_MSG_SET_MODE << 0);   /* Message type */
    msg |= ((uint64_t)(width & 0xFFF) << 8);          /* Width */
    msg |= ((uint64_t)(height & 0xFFF) << 20);        /* Height */
    msg |= ((uint64_t)(refresh_rate & 0xFF) << 32);   /* Refresh rate */
    msg |= ((uint64_t)APPLE_DCP_FMT_BGRA8888 << 40);  /* Pixel format */

    fut_printf("[DCP] Setting mode: %ux%u @ %uHz\n", width, height, refresh_rate);

    /* Send mode setting message via RTKit */
    bool ret = apple_rtkit_send_message(dcp->rtkit, dcp->dcp_endpoint, msg);
    if (!ret) {
        fut_printf("[DCP] Failed to send set mode message\n");
        return false;
    }

    /* Update current mode */
    dcp->current_mode.width = width;
    dcp->current_mode.height = height;
    dcp->current_mode.refresh_rate = refresh_rate;
    dcp->current_mode.pixel_format = APPLE_DCP_FMT_BGRA8888;
    dcp->current_mode.stride = width * 4;  /* BGRA = 4 bytes per pixel */
    dcp->mode_set = true;

    return true;
}

bool fut_apple_dcp_get_mode(apple_dcp_ctrl_t *dcp, apple_dcp_mode_t *mode_out) {
    if (!dcp || !mode_out) {
        return false;
    }

    if (!dcp->mode_set) {
        return false;
    }

    *mode_out = dcp->current_mode;
    return true;
}

/* ============================================================
 *   Buffer Swapping
 * ============================================================ */

bool fut_apple_dcp_swap_submit(apple_dcp_ctrl_t *dcp, int surface_idx) {
    if (!dcp || !dcp->rtkit) {
        return false;
    }

    if (surface_idx < 0 || surface_idx >= APPLE_DCP_MAX_SURFACES) {
        return false;
    }

    apple_dcp_surface_t *surf = &dcp->surfaces[surface_idx];
    if (!surf->allocated) {
        fut_printf("[DCP] Surface %d not allocated\n", surface_idx);
        return false;
    }

    /* Check if swap is already pending */
    if (dcp->swap_pending) {
        fut_printf("[DCP] Swap already pending, dropping frame\n");
        dcp->frames_dropped++;
        return false;
    }

    /* Build swap submit message
     * Format: [type:8][surface:8][phys_lo:24][phys_hi:24]
     */
    uint64_t msg = 0;
    msg |= ((uint64_t)APPLE_DCP_MSG_SWAP_START << 0);
    msg |= ((uint64_t)surface_idx << 8);
    msg |= ((surf->iova >> 0) & 0xFFFFFF) << 16;
    msg |= ((surf->iova >> 24) & 0xFFFFFF) << 40;

    /* Mark swap as pending */
    dcp->swap_pending = true;
    dcp->swap_complete = false;
    dcp->next_surface = surface_idx;

    /* Send swap message */
    bool ret = apple_rtkit_send_message(dcp->rtkit, dcp->dcp_endpoint, msg);
    if (!ret) {
        dcp->swap_pending = false;
        fut_printf("[DCP] Failed to send swap message\n");
        return false;
    }

    return true;
}

bool fut_apple_dcp_swap_wait(apple_dcp_ctrl_t *dcp, uint32_t timeout_ms) {
    if (!dcp) {
        return false;
    }

    if (!dcp->swap_pending) {
        return true;  /* No swap pending */
    }

    /* Poll for completion */
    /* TODO: Use proper wait queue when available */
    uint32_t elapsed = 0;
    while (dcp->swap_pending && (timeout_ms == 0 || elapsed < timeout_ms)) {
        /* Poll RTKit for messages */
        apple_rtkit_poll(dcp->rtkit);

        /* Small delay */
        for (volatile int i = 0; i < 1000; i++) {
            __asm__ volatile("" ::: "memory");
        }
        elapsed++;
    }

    if (dcp->swap_complete) {
        dcp->current_surface = dcp->next_surface;
        return true;
    }

    return false;
}

/* ============================================================
 *   Backlight and Power Control
 * ============================================================ */

bool fut_apple_dcp_set_backlight(apple_dcp_ctrl_t *dcp, uint8_t level) {
    if (!dcp || !dcp->rtkit) {
        return false;
    }

    /* Build backlight message */
    uint64_t msg = 0;
    msg |= ((uint64_t)APPLE_DCP_MSG_BACKLIGHT << 0);
    msg |= ((uint64_t)level << 8);

    bool ret = apple_rtkit_send_message(dcp->rtkit, dcp->dcp_endpoint, msg);
    if (ret) {
        dcp->backlight = level;
    }

    return ret;
}

bool fut_apple_dcp_set_power(apple_dcp_ctrl_t *dcp, uint8_t state) {
    if (!dcp || !dcp->rtkit) {
        return false;
    }

    /* Build power message */
    uint64_t msg = 0;
    msg |= ((uint64_t)APPLE_DCP_MSG_POWER << 0);
    msg |= ((uint64_t)state << 8);

    bool ret = apple_rtkit_send_message(dcp->rtkit, dcp->dcp_endpoint, msg);
    if (ret) {
        dcp->power_state = state;
        dcp->display_enabled = (state == APPLE_DCP_POWER_ON);
    }

    return ret;
}

/* ============================================================
 *   Initialization and Shutdown
 * ============================================================ */

/* Static DCP context (single display support) */
static apple_dcp_ctrl_t g_dcp_ctrl;
static bool g_dcp_initialized = false;

apple_dcp_ctrl_t *fut_apple_dcp_init(const fut_platform_info_t *info) {
    if (!info) {
        return NULL;
    }

    if (g_dcp_initialized) {
        fut_printf("[DCP] Already initialized\n");
        return &g_dcp_ctrl;
    }

    /* Verify DCP is available */
    if (!info->has_dcp || info->dcp_base == 0) {
        fut_printf("[DCP] DCP not available on this platform\n");
        return NULL;
    }

    fut_printf("[DCP] Initializing Apple DCP...\n");
    fut_printf("[DCP] DCP base: 0x%lx\n", (unsigned long)info->dcp_base);
    fut_printf("[DCP] Mailbox base: 0x%lx\n", (unsigned long)info->dcp_mailbox_base);

    /* Initialize controller context */
    memset(&g_dcp_ctrl, 0, sizeof(g_dcp_ctrl));
    g_dcp_ctrl.dcp_phys = info->dcp_base;
    g_dcp_ctrl.mailbox_phys = info->dcp_mailbox_base;
    g_dcp_ctrl.dcp_endpoint = APPLE_DCP_ENDPOINT;

    /* Map MMIO registers */
    g_dcp_ctrl.dcp_base = (volatile uint8_t *)info->dcp_base;

    /* Initialize RTKit context */
    g_dcp_ctrl.rtkit = apple_rtkit_init(info->dcp_mailbox_base);
    if (!g_dcp_ctrl.rtkit) {
        fut_printf("[DCP] Failed to initialize RTKit\n");
        return NULL;
    }

    /* Boot RTKit co-processor */
    fut_printf("[DCP] Booting RTKit co-processor...\n");
    bool boot_ok = apple_rtkit_boot(g_dcp_ctrl.rtkit);
    if (!boot_ok) {
        fut_printf("[DCP] Failed to boot RTKit\n");
        return NULL;
    }

    /* Register DCP endpoint handler */
    apple_rtkit_register_endpoint(g_dcp_ctrl.rtkit, g_dcp_ctrl.dcp_endpoint,
                                   apple_dcp_rtkit_handler, &g_dcp_ctrl);

    /* Start DCP application endpoint */
    fut_printf("[DCP] Starting DCP endpoint 0x%02x...\n", g_dcp_ctrl.dcp_endpoint);
    bool ep_ok = apple_rtkit_start_endpoint(g_dcp_ctrl.rtkit, g_dcp_ctrl.dcp_endpoint);
    if (!ep_ok) {
        fut_printf("[DCP] Failed to start DCP endpoint\n");
        return NULL;
    }

    /* Set initial power state */
    fut_apple_dcp_set_power(&g_dcp_ctrl, APPLE_DCP_POWER_ON);

    /* Set default mode if panel dimensions are known */
    if (info->display_width > 0 && info->display_height > 0) {
        fut_apple_dcp_set_mode(&g_dcp_ctrl, info->display_width, info->display_height, 60);
    }

    g_dcp_initialized = true;
    fut_printf("[DCP] Initialization complete\n");

    return &g_dcp_ctrl;
}

void fut_apple_dcp_shutdown(apple_dcp_ctrl_t *dcp) {
    if (!dcp || !g_dcp_initialized) {
        return;
    }

    fut_printf("[DCP] Shutting down...\n");

    /* Power off display */
    fut_apple_dcp_set_power(dcp, APPLE_DCP_POWER_OFF);

    /* Free all surfaces */
    for (int i = 0; i < APPLE_DCP_MAX_SURFACES; i++) {
        if (dcp->surfaces[i].allocated) {
            fut_apple_dcp_free_surface(dcp, i);
        }
    }

    /* Shutdown RTKit */
    if (dcp->rtkit) {
        apple_rtkit_shutdown(dcp->rtkit);
        dcp->rtkit = NULL;
    }

    g_dcp_initialized = false;
    fut_printf("[DCP] Shutdown complete\n");
}

/* ============================================================
 *   Platform Integration
 * ============================================================ */

int fut_apple_dcp_platform_init(const fut_platform_info_t *info) {
    if (!info) {
        return -1;
    }

    /* Only initialize on Apple Silicon platforms */
    if (info->type != PLATFORM_APPLE_M1 &&
        info->type != PLATFORM_APPLE_M2 &&
        info->type != PLATFORM_APPLE_M3) {
        return 0;  /* Not an error, just not applicable */
    }

    /* Initialize DCP driver */
    apple_dcp_ctrl_t *dcp = fut_apple_dcp_init(info);
    if (!dcp) {
        fut_printf("[DCP] Platform init failed\n");
        return -1;
    }

    /* Probe framebuffer */
    return fb_probe_from_dcp(dcp);
}

int fb_probe_from_dcp(apple_dcp_ctrl_t *dcp) {
    if (!dcp || !dcp->mode_set) {
        return -1;
    }

    /* Allocate primary framebuffer surface */
    int fb_idx = fut_apple_dcp_alloc_surface(dcp,
                                              dcp->current_mode.width,
                                              dcp->current_mode.height,
                                              dcp->current_mode.pixel_format);
    if (fb_idx < 0) {
        fut_printf("[DCP] Failed to allocate framebuffer surface\n");
        return -1;
    }

    /* Submit initial frame */
    fut_apple_dcp_swap_submit(dcp, fb_idx);

    fut_printf("[DCP] Framebuffer initialized: %ux%u\n",
               dcp->current_mode.width, dcp->current_mode.height);

    /* TODO: Register with generic framebuffer layer */
    /* This will integrate with existing fb.h infrastructure */

    return 0;
}
