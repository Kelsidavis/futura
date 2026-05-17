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
#include <platform/arm64/apple_pmgr.h>
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

    /* fut_malloc_pages returns a kernel VA (high-half mapping); zero
     * via the VA, then convert to PA for handing to DART.  Previous
     * code stored the VA in a variable named `phys` and passed it
     * straight to rust_dart_map — the IOMMU would have been
     * programmed with the VA bit pattern interpreted as a PA,
     * pointing the DCP at the wrong physical pages and either
     * scanning out garbage or stomping unrelated kernel memory. */
    void    *va   = fut_malloc_pages(num_pages);
    if (!va) {
        fut_printf("[DCP] Page allocation failed (%lu pages)\n",
                   (unsigned long)num_pages);
        return -1;
    }
    memset(va, 0, size);
    uint64_t phys = pmap_virt_to_phys((uintptr_t)va);

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
            fut_free_pages(va, num_pages);
            return -1;
        }
    } else {
        iova = phys;
    }

    int idx = rust_apple_dcp_register_surface(g_dcp.dcp, iova,
                                               width, height, stride, format);
    if (idx < 0) {
        fut_printf("[DCP] All surface slots full\n");
        /* If we mapped through DART above, tear that mapping down now —
         * otherwise the IOMMU keeps an entry pointing at the pages
         * we're about to free, which is a use-after-free hazard for
         * the chip's next DMA cycle. */
        if (g_dcp.dart) {
            rust_dart_unmap(g_dcp.dart, g_dcp.dart_stream_id,
                            iova, (uint64_t)size);
        }
        fut_free_pages(va, num_pages);
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

/* Reverse dcp_alloc_surface — DART-unmap, free pages, drop the slot.
 * Used by failure paths in apple_dcp_init that allocate a surface
 * but then can't complete the swap-submit handshake. */
static void dcp_release_surface(int fb_idx) {
    if (fb_idx < 0 || fb_idx >= 4 || !g_dcp.surfaces[fb_idx].valid) return;
    if (g_dcp.dart) {
        rust_dart_unmap(g_dcp.dart, g_dcp.dart_stream_id,
                        g_dcp.surfaces[fb_idx].iova,
                        g_dcp.surfaces[fb_idx].size);
    }
    void *va = pmap_phys_to_virt(g_dcp.surfaces[fb_idx].phys);
    size_t num_pages = g_dcp.surfaces[fb_idx].size / 4096;
    if (va && num_pages > 0) {
        fut_free_pages(va, num_pages);
    }
    rust_apple_dcp_unregister_surface(g_dcp.dcp, fb_idx);
    g_dcp.surfaces[fb_idx].valid = false;
    g_dcp.surfaces[fb_idx].phys  = 0;
    g_dcp.surfaces[fb_idx].iova  = 0;
    g_dcp.surfaces[fb_idx].size  = 0;
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

    /* FIRST-LIGHT FAST-PATH: if m1n1 already brought up the panel
     * and exposed its framebuffer via /chosen/framebuffer, publish
     * that to the kernel fb layer BEFORE touching DCP / DART /
     * RTKit.  That way even if the DCP bring-up below fails (likely
     * on real hardware until we wire pmgr_enable() to the DCP power
     * domains — see apple_pmgr.h, blocked on per-SoC offset table or
     * DT phandle resolution of power-domains property), the kernel
     * still has a console to print to.  display_width / display_height
     * come from the DT walker and don't need DCP at all. */
    if (info->framebuffer_phys != 0 &&
        info->display_width > 0 && info->display_height > 0) {
        struct fut_fb_hwinfo m1n1_fb = {0};
        /* Prefer the actual stride from /chosen/framebuffer when
         * m1n1 published one — panels with non-power-of-2 widths or
         * driver-imposed alignment can have stride > width × 4. */
        uint32_t stride = (info->framebuffer_stride > 0)
                            ? info->framebuffer_stride
                            : (info->display_width * 4);
        m1n1_fb.phys        = info->framebuffer_phys;
        m1n1_fb.length      = (uint64_t)stride * info->display_height;
        /* Use the kernel peripheral mapping window — m1n1's FB sits
         * in DRAM at PA 0x10_0000_0000+ which is outside the
         * kernel's L2_dram window but inside kernel_l1[8..511]
         * (the 504 GiB device-nGnRE window boot.S sets up). */
        m1n1_fb.virt        = (void *)fut_kernel_peripheral_va(info->framebuffer_phys);
        m1n1_fb.info.width  = info->display_width;
        m1n1_fb.info.height = info->display_height;
        m1n1_fb.info.pitch  = stride;
        m1n1_fb.info.bpp    = 32;
        m1n1_fb.info.flags  = 0x00000001;  /* FB_FLAG_LINEAR */
        int rc = fb_set_hwinfo(&m1n1_fb);
        fut_printf("[DCP] First-light: m1n1 FB at PA 0x%lx VA %p (rc=%d)\n",
                   (unsigned long)info->framebuffer_phys, m1n1_fb.virt, rc);
    }

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

    /* Enable every pmgr power domain DCP needs.  Without this on
     * cold boot the DCP coprocessor stays in reset and RTKit boot
     * silently times out.  Resolved via DT phandles in the DCP
     * node's power-domains property — no per-SoC offset table
     * required.  Non-fatal if pmgr or the DT property is missing
     * (m1n1 likely already powered things on). */
    extern uint64_t fut_platform_get_dtb(void);
    uint64_t dtb = fut_platform_get_dtb();
    static const char *const dcp_paths[] = {
        "/soc/dcp@28200000",
        "/soc/dcp",
        "/arm-io/dcp",
        NULL,
    };
    int dcp_pmgr = apple_pmgr_enable_domains_any(dtb, dcp_paths);
    if (dcp_pmgr > 0) {
        fut_printf("[DCP] pmgr: %d domains enabled\n", dcp_pmgr);
    }

    /* RTKit context — apple_rtkit_* are themselves Rust thunks. */
    g_dcp.rtkit = apple_rtkit_init(info->dcp_mailbox_base);
    if (!g_dcp.rtkit) {
        fut_printf("[DCP] RTKit init failed\n");
        /* DART was set up earlier (line ~270); free it so we don't
         * leak the rust_dart heap allocation. */
        if (g_dcp.dart) {
            rust_dart_free(g_dcp.dart);
            g_dcp.dart = NULL;
        }
        return -1;
    }
    if (!apple_rtkit_boot(g_dcp.rtkit)) {
        fut_printf("[DCP] RTKit boot failed\n");
        apple_rtkit_shutdown(g_dcp.rtkit);
        g_dcp.rtkit = NULL;
        if (g_dcp.dart) { rust_dart_free(g_dcp.dart); g_dcp.dart = NULL; }
        return -1;
    }
    apple_rtkit_register_endpoint(g_dcp.rtkit, APPLE_DCP_ENDPOINT,
                                   apple_dcp_rtkit_handler, g_dcp.dcp);
    if (!apple_rtkit_start_endpoint(g_dcp.rtkit, APPLE_DCP_ENDPOINT)) {
        fut_printf("[DCP] Endpoint start failed\n");
        apple_rtkit_shutdown(g_dcp.rtkit);
        g_dcp.rtkit = NULL;
        if (g_dcp.dart) { rust_dart_free(g_dcp.dart); g_dcp.dart = NULL; }
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
     * with the kernel fb layer.  Even when m1n1 already published a
     * FB at the top of this function, we attempt the DCP-owned path
     * so the kernel ends up driving the display itself rather than
     * piggybacking on m1n1's mapping forever.  Failures fall back to
     * the already-registered m1n1 FB — the kernel always has *some*
     * console as long as one of the two paths succeeded. */
    if (!rust_apple_dcp_mode_is_set(g_dcp.dcp)) {
        fut_printf("[DCP] No mode set, skipping DCP-owned FB probe\n");
        return 0;
    }

    if (info->framebuffer_phys != 0) {
        fut_printf("[DCP] m1n1 FB published, attempting DCP-owned takeover\n");
    } else {
        fut_printf("[DCP] no m1n1 FB; attempting DCP-owned FB init\n");
    }

    int fb_idx = dcp_alloc_surface(rust_apple_dcp_mode_width(g_dcp.dcp),
                                    rust_apple_dcp_mode_height(g_dcp.dcp),
                                    rust_apple_dcp_mode_format(g_dcp.dcp));
    if (fb_idx < 0) {
        fut_printf("[DCP] surface alloc failed%s\n",
                   info->framebuffer_phys != 0
                     ? " — staying on m1n1 FB" : "");
        return -1;
    }

    uint64_t swap_msg = rust_apple_dcp_swap_submit_build(g_dcp.dcp, fb_idx);
    if (!swap_msg) {
        fut_printf("[DCP] swap_submit build returned 0%s\n",
                   info->framebuffer_phys != 0
                     ? " — staying on m1n1 FB" : "");
        dcp_release_surface(fb_idx);
        return -1;
    }
    apple_rtkit_send_message(g_dcp.rtkit, APPLE_DCP_ENDPOINT, swap_msg);

    /* Poll for DCP's SWAP_COMPLETE ack via RTKit before re-registering
     * the FB.  Without this we'd swap the kernel FB to a surface DCP
     * hasn't actually started scanning yet — recipe for a black
     * console even though the registration "succeeded".  DCP normally
     * acks within one frame (~16.6ms @ 60Hz); 250ms gives ample
     * headroom for slow modes and the first-frame ramp.  Each iter is
     * 1ms via fut_platform_udelay. */
    int got_ack = 0;
    for (int attempt = 0; attempt < 250; attempt++) {
        if (rust_apple_dcp_swap_take_complete(g_dcp.dcp)) {
            got_ack = 1;
            fut_printf("[DCP] swap_submit acked at attempt %d\n", attempt);
            break;
        }
        fut_platform_udelay(1000u);
    }
    if (!got_ack) {
        fut_printf("[DCP] swap_submit ack timeout (250ms)%s\n",
                   info->framebuffer_phys != 0
                     ? " — staying on m1n1 FB" : " — display is dark");
        dcp_release_surface(fb_idx);
        return -1;
    }

    int rc = dcp_register_fb(fb_idx);
    if (rc == 0) {
        fut_printf("[DCP] DCP-owned FB now active (surface %d)\n", fb_idx);
    } else {
        fut_printf("[DCP] fb_set_hwinfo failed rc=%d%s\n", rc,
                   info->framebuffer_phys != 0
                     ? " — m1n1 FB remains the active mapping" : "");
        dcp_release_surface(fb_idx);
    }
    return rc;
}
