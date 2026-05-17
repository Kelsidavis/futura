/* apple_dcp.c - Apple Display Co-Processor — Rust-backed wrapper
 *
 * Copyright (c) 2025 Kelsi Davis
 * Licensed under the MPL v2.0 — see LICENSE for details.
 *
 * The DCP state machine + protocol layer (surface table, swap
 * pending/complete, current mode, backlight/power tracking, RTKit
 * message builders and the receive dispatcher) lives in
 * drivers/rust/apple_dcp.  This C file keeps the parts that depend
 * on kernel-only services:
 *
 *   1. Page allocation for surface buffers (fut_malloc_pages).
 *   2. DART IOMMU mapping (rust_dart_init / rust_dart_map already
 *      Rust internally, just called from C since we own the IOVA
 *      allocator).
 *   3. RTKit context boot via the C apple_rtkit_* wrappers (which
 *      themselves now forward to rust_rtkit_*).
 *   4. Registering the panel with the kernel framebuffer subsystem.
 *
 * Everything else flows through the new rust_apple_dcp_* FFI.
 *
 * Compat note: fut_apple_dcp_platform_init() gates on
 * info->type == PLATFORM_APPLE_M[1-4] so RPi / QEMU virt boots
 * never reach the DCP code path.
 */

#include <platform/arm64/apple_dcp.h>
#include <platform/arm64/apple_dart.h>
#include <platform/arm64/apple_rtkit.h>
#include <platform/arm64/memory/pmap.h>
#include <platform/platform.h>
#include <kernel/fut_memory.h>
#include <kernel/fb.h>
#include <string.h>

/* C-side state — only the resources that don't belong in Rust. */
static struct {
    AppleDcp *dcp;             /* Rust state handle */
    apple_rtkit_ctx_t *rtkit;
    AppleDart *dart;
    uint32_t dart_stream_id;
    uint64_t next_iova;
    /* Mirror of registered surfaces so shutdown can DART-unmap. */
    struct {
        uint64_t phys;
        uint64_t iova;
        size_t size;
        bool valid;
    } surfaces[4];
    bool initialized;
} g_dcp;

/* ============================================================
 *   RTKit message handler — thunks into Rust
 * ============================================================ */

static void apple_dcp_rtkit_handler(void *cookie, uint8_t endpoint, uint64_t msg) {
    AppleDcp *dcp = (AppleDcp *)cookie;
    if (!dcp) return;
    uint8_t mtype = rust_apple_dcp_handle_msg(dcp, msg);
    /* Log unknown types so reverse-engineering deltas show up; SWAP_COMPLETE
     * (0x03) is the only one Rust acts on, the rest are advisory. */
    if (mtype != 0x03) {
        fut_printf("[DCP] RTKit ep=0x%02x type=0x%02x msg=0x%016lx\n",
                   endpoint, mtype, (unsigned long)msg);
    }
}

/* ============================================================
 *   Surface allocation + DART mapping
 * ============================================================ */

static int dcp_alloc_surface(uint32_t width, uint32_t height, uint32_t format) {
    /* Compute bytes-per-pixel + stride + page-aligned size. */
    uint32_t bpp = (format == APPLE_DCP_FMT_RGB565) ? 2 : 4;
    uint64_t stride64 = (uint64_t)width * bpp;
    uint64_t size64   = stride64 * height;
    if (stride64 > 0xFFFFFFFFULL || size64 > (256ULL * 1024 * 1024)) {
        fut_printf("[DCP] Surface too large (%ux%u)\n", width, height);
        return -1;
    }
    uint32_t stride   = (uint32_t)stride64;
    size_t   num_pages = ((size_t)size64 + 4095) / 4096;
    size_t   size      = num_pages * 4096;

    /* Allocate pages and zero them. */
    uint64_t phys = (uint64_t)fut_malloc_pages(num_pages);
    if (phys == 0) {
        fut_printf("[DCP] Page allocation failed (%lu pages)\n",
                   (unsigned long)num_pages);
        return -1;
    }
    memset((void *)phys, 0, size);

    /* Map through DART or fall back to identity. */
    uint64_t iova;
    if (g_dcp.dart) {
        iova = g_dcp.next_iova;
        g_dcp.next_iova += size;
        int rc = rust_dart_map(g_dcp.dart, g_dcp.dart_stream_id,
                                iova, phys, (uint64_t)size,
                                DART_PROT_READ | DART_PROT_WRITE);
        if (rc != 0) {
            fut_printf("[DCP] DART map failed: %d\n", rc);
            fut_free_pages((void *)phys, num_pages);
            return -1;
        }
    } else {
        iova = phys;
    }

    int idx = rust_apple_dcp_register_surface(g_dcp.dcp, iova,
                                               width, height, stride, format);
    if (idx < 0) {
        fut_printf("[DCP] All surface slots full\n");
        fut_free_pages((void *)phys, num_pages);
        return -1;
    }

    if ((size_t)idx < (sizeof(g_dcp.surfaces) / sizeof(g_dcp.surfaces[0]))) {
        g_dcp.surfaces[idx].phys  = phys;
        g_dcp.surfaces[idx].iova  = iova;
        g_dcp.surfaces[idx].size  = size;
        g_dcp.surfaces[idx].valid = true;
    }

    fut_printf("[DCP] Surface %d: %ux%u stride=%u phys=0x%lx iova=0x%lx\n",
               idx, width, height, stride,
               (unsigned long)phys, (unsigned long)iova);
    return idx;
}

/* ============================================================
 *   Framebuffer registration
 * ============================================================ */

static int dcp_register_fb(int fb_idx) {
    if (fb_idx < 0 || fb_idx >= 4 || !g_dcp.surfaces[fb_idx].valid) return -1;

    uint32_t width  = rust_apple_dcp_mode_width(g_dcp.dcp);
    uint32_t height = rust_apple_dcp_mode_height(g_dcp.dcp);
    uint32_t stride = rust_apple_dcp_mode_stride(g_dcp.dcp);
    uint32_t format = rust_apple_dcp_mode_format(g_dcp.dcp);

    struct fut_fb_hwinfo dcp_fb_hw = {0};
    dcp_fb_hw.phys        = g_dcp.surfaces[fb_idx].phys;
    dcp_fb_hw.length      = (uint64_t)stride * height;
    dcp_fb_hw.info.width  = width;
    dcp_fb_hw.info.height = height;
    dcp_fb_hw.info.pitch  = stride;
    dcp_fb_hw.info.bpp    = (format == APPLE_DCP_FMT_RGB565) ? 16 : 32;
    dcp_fb_hw.info.flags  = 0x00000001;  /* FB_FLAG_LINEAR */

    /* Publish to the global FB subsystem so fb_get_info() / fb_is_available()
     * reflect the DCP surface instead of the FB_PHYS_FALLBACK that
     * fb_probe_from_multiboot's ARM64 fallback seeded earlier in boot. */
    int rc = fb_set_hwinfo(&dcp_fb_hw);
    if (rc != 0) {
        fut_printf("[DCP] fb_set_hwinfo failed: %d\n", rc);
        return rc;
    }

    fut_printf("[DCP] Framebuffer: %ux%u %ubpp phys=0x%lx\n",
               width, height, dcp_fb_hw.info.bpp,
               (unsigned long)dcp_fb_hw.phys);
    return 0;
}

/* ============================================================
 *   Platform entry point
 * ============================================================ */

int fut_apple_dcp_platform_init(const fut_platform_info_t *info) {
    if (!info) return -1;

    if (info->type != PLATFORM_APPLE_M1 &&
        info->type != PLATFORM_APPLE_M2 &&
        info->type != PLATFORM_APPLE_M3 &&
        info->type != PLATFORM_APPLE_M4) {
        return 0;
    }
    if (!info->has_dcp || info->dcp_base == 0) {
        return 0;
    }

    memset(&g_dcp, 0, sizeof(g_dcp));
    g_dcp.dcp = rust_apple_dcp_new();

    fut_printf("[DCP] Init dcp=0x%lx mailbox=0x%lx\n",
               (unsigned long)info->dcp_base,
               (unsigned long)info->dcp_mailbox_base);

    /* DART IOMMU — variant 0 = t8020 (M1/M2), variant 1 = t8110
     * (M1 Pro/Max).  PA→VA via the kernel peripheral mapping window.
     * Identity fallback if no DART. */
    if (info->dart_base != 0) {
        uint64_t dart_va = fut_kernel_peripheral_va(info->dart_base);
        g_dcp.dart = rust_dart_init(dart_va, 16, 0);
        if (g_dcp.dart) {
            g_dcp.dart_stream_id = 0;
            g_dcp.next_iova      = 0x100000000ULL;
            rust_dart_enable_stream(g_dcp.dart, g_dcp.dart_stream_id);
            fut_printf("[DCP] DART up at PA 0x%lx (VA 0x%lx)\n",
                       (unsigned long)info->dart_base, (unsigned long)dart_va);
        }
    }

    /* RTKit context — apple_rtkit_* are themselves Rust thunks. */
    g_dcp.rtkit = apple_rtkit_init(info->dcp_mailbox_base);
    if (!g_dcp.rtkit) {
        fut_printf("[DCP] RTKit init failed\n");
        return -1;
    }
    if (!apple_rtkit_boot(g_dcp.rtkit)) {
        fut_printf("[DCP] RTKit boot failed\n");
        return -1;
    }
    apple_rtkit_register_endpoint(g_dcp.rtkit, APPLE_DCP_ENDPOINT,
                                   apple_dcp_rtkit_handler, g_dcp.dcp);
    if (!apple_rtkit_start_endpoint(g_dcp.rtkit, APPLE_DCP_ENDPOINT)) {
        fut_printf("[DCP] Endpoint start failed\n");
        return -1;
    }

    /* Initial power-on. */
    uint64_t pwr_msg = rust_apple_dcp_set_power_msg(g_dcp.dcp, APPLE_DCP_POWER_ON);
    if (pwr_msg) apple_rtkit_send_message(g_dcp.rtkit, APPLE_DCP_ENDPOINT, pwr_msg);

    /* Default mode from DTB-reported panel size, BGRA8888. */
    if (info->display_width > 0 && info->display_height > 0) {
        rust_apple_dcp_set_mode(g_dcp.dcp,
                                 info->display_width, info->display_height,
                                 60, APPLE_DCP_FMT_BGRA8888);
    }

    g_dcp.initialized = true;

    /* Allocate the primary framebuffer surface, submit it, register
     * with the kernel fb layer. */
    if (!rust_apple_dcp_mode_is_set(g_dcp.dcp)) {
        fut_printf("[DCP] No mode set, skipping FB probe\n");
        return 0;
    }
    int fb_idx = dcp_alloc_surface(rust_apple_dcp_mode_width(g_dcp.dcp),
                                    rust_apple_dcp_mode_height(g_dcp.dcp),
                                    rust_apple_dcp_mode_format(g_dcp.dcp));
    if (fb_idx < 0) return -1;

    uint64_t swap_msg = rust_apple_dcp_swap_submit_build(g_dcp.dcp, fb_idx);
    if (swap_msg) {
        apple_rtkit_send_message(g_dcp.rtkit, APPLE_DCP_ENDPOINT, swap_msg);
    }

    return dcp_register_fb(fb_idx);
}
