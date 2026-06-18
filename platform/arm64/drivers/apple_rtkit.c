/* apple_rtkit.c - Apple RTKit IPC — Rust-backed wrapper
 *
 * Copyright (c) 2025 Kelsi Davis
 * Licensed under the MPL v2.0 — see LICENSE for details.
 *
 * RTKit is Apple's RTOS running on the M1/M2/M3 co-processors (ANS
 * NVMe, DCP display, AOP, SMC, etc.).  The mailbox protocol and full
 * boot sequence (HELLO → EPMAP → STARTEP → ON) live in the Rust
 * apple_rtkit crate under drivers/rust/apple_rtkit; this C file is a
 * thin glue layer that:
 *
 *   1. Allocates the legacy apple_rtkit_ctx_t struct (the header
 *      exposes it, so source-level compatibility requires keeping it)
 *      and stores the Rust RtkitCtx * in ctx->rust_ctx.
 *   2. Maps each public apple_rtkit_* function onto the corresponding
 *      rust_rtkit_* FFI call.
 *   3. Keeps the existing apple_rtkit_ctx_t signature so apple_ans2.c
 *      and apple_dcp.c link without modification — they only call the
 *      apple_rtkit_* functions and never deref struct fields, verified
 *      by grep across platform/ kernel/ drivers/.
 *
 * Compat note: this driver is only ever instantiated from
 * apple_ans2_platform_init / apple_dcp_platform_init, both of which
 * already gate on PLATFORM_APPLE_M[1-4] — so RPi / QEMU virt boots
 * never reach the Rust RTKit driver.
 */

#include <platform/arm64/apple_rtkit.h>
#include <platform/arm64/memory/pmap.h>
#include <kernel/fut_memory.h>
#include <string.h>

/* Allocator helpers — apple_rtkit_ctx_t is large (>10 KiB once the
 * endpoint table is in there), so it lives in heap pages rather than
 * the BSS singleton pattern used by smaller wrappers. */
static apple_rtkit_ctx_t *alloc_ctx(void) {
    /* fut_malloc_pages rounds up; one 4 KiB page is plenty unless the
     * MAX_ENDPOINTS define grows beyond 256. */
    const size_t bytes = sizeof(apple_rtkit_ctx_t);
    const size_t pages = (bytes + 4095) / 4096;
    apple_rtkit_ctx_t *ctx = fut_malloc_pages(pages);
    if (!ctx) return NULL;
    memset(ctx, 0, pages * 4096);
    return ctx;
}

/* ============================================================
 *   Public API — all forwards to rust_rtkit_*
 * ============================================================ */

apple_rtkit_ctx_t *apple_rtkit_init(uint64_t mailbox_base) {
    if (mailbox_base == 0) return NULL;

    apple_rtkit_ctx_t *ctx = alloc_ctx();
    if (!ctx) {
        fut_printf("[RTKit] Failed to allocate context\n");
        return NULL;
    }

    /* The Rust crate stores `base` as a raw VA-pointer and reads via
     * read_volatile, so we have to hand it a kernel VA — not the
     * DTB-supplied PA.  Convert through the kernel peripheral mapping
     * window so the same call works on QEMU virt's PL011-ish low
     * peripherals AND Apple's high-PA mailbox regions. */
    uint64_t mailbox_va = fut_kernel_peripheral_va(mailbox_base);
    ctx->rust_ctx = rust_rtkit_init(mailbox_va);
    if (!ctx->rust_ctx) {
        fut_printf("[RTKit] rust_rtkit_init(VA 0x%lx, PA 0x%lx) failed\n",
                   (unsigned long)mailbox_va, (unsigned long)mailbox_base);
        /* Release the ctx page alloc_ctx() reserved — fut_free_pages is
         * the counterpart to fut_malloc_pages (apple_rtkit_shutdown uses
         * the same calc).  The old "no free() in this kernel" note was
         * stale and leaked a page on every RTKit init failure. */
        const size_t pages = (sizeof(apple_rtkit_ctx_t) + 4095) / 4096;
        fut_free_pages(ctx, pages);
        return NULL;
    }

    ctx->mailbox_phys = mailbox_base;
    ctx->initialized  = true;
    fut_printf("[RTKit] Initialized at PA 0x%lx (VA 0x%lx)\n",
               (unsigned long)mailbox_base, (unsigned long)mailbox_va);
    return ctx;
}

bool apple_rtkit_boot(apple_rtkit_ctx_t *ctx) {
    if (!ctx || !ctx->rust_ctx) return false;
    int rc = rust_rtkit_boot(ctx->rust_ctx);
    if (rc) {
        ctx->version = rust_rtkit_version(ctx->rust_ctx);
        ctx->iop_power_state = APPLE_RTKIT_PWR_STATE_ON;
        fut_printf("[RTKit] Boot OK, version=%u\n", ctx->version);
    } else {
        fut_printf("[RTKit] Boot failed\n");
    }
    return rc != 0;
}

bool apple_rtkit_send_message(apple_rtkit_ctx_t *ctx, uint8_t endpoint, uint64_t msg) {
    if (!ctx || !ctx->rust_ctx) return false;
    return rust_rtkit_send(ctx->rust_ctx, endpoint, msg) != 0;
}

bool apple_rtkit_recv_message(apple_rtkit_ctx_t *ctx, uint8_t *endpoint_out, uint64_t *msg_out) {
    if (!ctx || !ctx->rust_ctx) return false;
    return rust_rtkit_recv_message(ctx->rust_ctx, endpoint_out, msg_out) != 0;
}

int apple_rtkit_process_messages(apple_rtkit_ctx_t *ctx) {
    if (!ctx || !ctx->rust_ctx) return 0;
    return rust_rtkit_process_messages(ctx->rust_ctx);
}

bool apple_rtkit_register_endpoint(apple_rtkit_ctx_t *ctx, uint8_t endpoint,
                                    apple_rtkit_msg_handler_t handler, void *cookie) {
    if (!ctx || !ctx->rust_ctx) return false;
    /* The C and Rust callback signatures are identical: same arg
     * order, same C ABI.  Pass the pointer through directly. */
    rust_rtkit_register_handler(ctx->rust_ctx, endpoint,
                                 (rust_rtkit_msg_handler_t)handler, cookie);
    /* Mirror into the legacy table so any source-level reader (none
     * today, but cheap to maintain) sees the same registration. */
    ctx->endpoints[endpoint].endpoint = endpoint;
    ctx->endpoints[endpoint].handler  = handler;
    ctx->endpoints[endpoint].cookie   = cookie;
    return true;
}

bool apple_rtkit_start_endpoint(apple_rtkit_ctx_t *ctx, uint8_t endpoint) {
    if (!ctx || !ctx->rust_ctx) return false;
    int rc = rust_rtkit_start_endpoint(ctx->rust_ctx, endpoint);
    if (rc) {
        ctx->endpoints[endpoint].started = true;
    }
    return rc != 0;
}

bool apple_rtkit_set_ap_power_state(apple_rtkit_ctx_t *ctx, uint8_t state) {
    if (!ctx || !ctx->rust_ctx) return false;
    int rc = rust_rtkit_set_ap_power_state(ctx->rust_ctx, state);
    if (rc) ctx->ap_power_state = state;
    return rc != 0;
}

bool apple_rtkit_set_iop_power_state(apple_rtkit_ctx_t *ctx, uint8_t state) {
    if (!ctx || !ctx->rust_ctx) return false;
    int rc = rust_rtkit_set_iop_power_state(ctx->rust_ctx, state);
    if (rc) ctx->iop_power_state = state;
    return rc != 0;
}

void apple_rtkit_shutdown(apple_rtkit_ctx_t *ctx) {
    if (!ctx) return;
    if (ctx->rust_ctx) {
        rust_rtkit_shutdown(ctx->rust_ctx);
        rust_rtkit_free(ctx->rust_ctx);
        ctx->rust_ctx    = NULL;
        ctx->initialized = false;
    }
    /* Free the page(s) we allocated in alloc_ctx() — the previous
     * "no fut_free_pages in this kernel" comment was stale; the
     * symbol exists and is the right counterpart to fut_malloc_pages. */
    const size_t bytes = sizeof(apple_rtkit_ctx_t);
    const size_t pages = (bytes + 4095) / 4096;
    fut_free_pages(ctx, pages);
}
