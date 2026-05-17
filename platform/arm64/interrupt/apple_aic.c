/* apple_aic.c - Apple Interrupt Controller (AIC) — Rust-backed wrapper
 *
 * Copyright (c) 2025 Kelsi Davis
 * Licensed under the MPL v2.0 — see LICENSE for details.
 *
 * Apple Interrupt Controller for M1/M2/M3/M4 SoCs.  This file is a
 * thin C bridge over the Rust driver in `drivers/rust/apple_aic`
 * (Asahi-Linux-derived implementation).  Per the project's
 * Rust-only-drivers policy the actual register-level work lives in
 * Rust; the C API here exists only to keep the call sites the rest
 * of the arm64 platform code already targets (fut_apple_aic_*,
 * apple_aic_handle_irq, fut_apple_irq_init) working unchanged.
 *
 * Earlier this file was a hand-rolled C stub that only knew about
 * the ARM Generic Timer IRQ.  The Rust driver carries a full handler
 * table, target-CPU routing, and IPI support — switch to it as part
 * of the Apple Silicon bring-up chain.
 */

#include <platform/arm64/apple_aic.h>
#include <platform/arm64/memory/pmap.h>
#include <platform/platform.h>
#include <string.h>
#include <stddef.h>

/* Cached context returned by rust_aic_init.  NULL until
 * fut_apple_aic_init succeeds. */
static AppleAic *aic_ctx = NULL;

/* ============================================================
 *   AIC Initialization
 * ============================================================ */

bool fut_apple_aic_init(const fut_platform_info_t *info) {
    if (!info || !info->has_aic || info->aic_base == 0) {
        fut_printf("[AIC] Error: Invalid platform info or missing AIC\n");
        return false;
    }

    /* DTB reports the AIC PA (0x23B100000 on M1).  The Rust driver
     * uses the value as a raw VA for MMIO, so convert through the
     * boot.S kernel-peripheral mapping window first. */
    uint64_t aic_va = fut_kernel_peripheral_va(info->aic_base);

    fut_printf("[AIC] Apple Interrupt Controller detected (Rust driver)\n");
    fut_printf("[AIC] PA 0x%016llx -> VA 0x%016llx\n",
               info->aic_base, aic_va);

    aic_ctx = rust_aic_init(aic_va);
    if (!aic_ctx) {
        fut_printf("[AIC] Error: rust_aic_init failed\n");
        return false;
    }

    uint32_t cpu_id = rust_aic_whoami(aic_ctx);
    fut_printf("[AIC] Initialized on CPU %u (IRQs=%u, ready=%d)\n",
               cpu_id, rust_aic_num_irqs(aic_ctx),
               rust_aic_is_ready(aic_ctx));

    return true;
}

/* ============================================================
 *   IRQ Control Functions (C API wrappers)
 * ============================================================ */

void fut_apple_aic_enable_irq(uint32_t irq_num) {
    if (aic_ctx) rust_aic_enable_irq(aic_ctx, irq_num);
}

void fut_apple_aic_disable_irq(uint32_t irq_num) {
    if (aic_ctx) rust_aic_disable_irq(aic_ctx, irq_num);
}

bool fut_apple_aic_is_pending(uint32_t irq_num) {
    if (!aic_ctx) return false;
    return rust_aic_is_pending(aic_ctx, irq_num) != 0;
}

void fut_apple_aic_ack_irq(uint32_t irq_num) {
    /* The AIC clears the event automatically on EVENT-register read.
     * The Rust driver doesn't expose a separate ack — call sites that
     * still expect one are kept happy with this no-op. */
    (void)irq_num;
}

void fut_apple_aic_send_ipi(uint32_t target_cpu, uint32_t ipi_num) {
    if (aic_ctx) rust_aic_send_ipi(aic_ctx, target_cpu, ipi_num);
}

void fut_apple_aic_ack_ipi(uint32_t ipi_num) {
    if (aic_ctx) rust_aic_ack_ipi(aic_ctx, ipi_num);
}

uint32_t fut_apple_aic_whoami(void) {
    if (!aic_ctx) return 0;
    return rust_aic_whoami(aic_ctx);
}

/* ============================================================
 *   IRQ Handler
 * ============================================================ */

void apple_aic_handle_irq(void) {
    /* Forward to the Rust dispatcher.  It reads AIC_EVENT, finds the
     * lowest pending IRQ, dispatches to the registered handler (the
     * AIC clears the event on read so no explicit ack is needed),
     * and returns. */
    if (aic_ctx) {
        rust_aic_handle_irq(aic_ctx);
    }
}

/* Apple FIQ dispatcher.
 *
 * On Apple Silicon two things fire as architectural FIQ rather than
 * via the AIC's event bitmap:
 *
 *   1. ARM Generic Timer (CPU-local) — CNTP_CTL_EL0.ISTATUS is set
 *      when the timer expires.  Asahi Linux and m1n1's FIQ dispatch
 *      both check this bit FIRST and re-arm the timer + run the
 *      tick handler directly, bypassing the AIC entirely.  Without
 *      this short-circuit the timer FIQ falls through to the AIC
 *      event-bitmap scan, finds nothing (the timer doesn't show up
 *      in AIC_EVENT), and returns without re-arming — the timer
 *      then fires continuously at the same expiry and the kernel
 *      hangs in a FIQ storm.
 *
 *   2. Fast IPIs — not implemented yet, since we're single-CPU.
 *      Add a similar short-circuit reading the IPI register when
 *      SMP brings up secondary cores.
 *
 * Anything that's not the timer falls through to the AIC dispatch
 * (some AIC events can be configured to fire as FIQ instead of IRQ,
 * though we don't currently route any that way). */
#define CNTP_CTL_ISTATUS  (1u << 2)

void apple_aic_handle_fiq(void) {
    uint64_t cntp_ctl;
    __asm__ volatile("mrs %0, cntp_ctl_el0" : "=r"(cntp_ctl));
    if (cntp_ctl & CNTP_CTL_ISTATUS) {
        /* Timer fired — re-arm via the common handler that already
         * writes CNTP_TVAL_EL0 + CNTP_CTL_EL0. */
        extern void fut_timer_irq_handler(void);
        fut_timer_irq_handler();
        return;
    }

    /* Not the timer — scan the AIC for any FIQ-routed events. */
    if (aic_ctx) {
        rust_aic_handle_irq(aic_ctx);
    }
}

/* ============================================================
 *   Platform Integration
 * ============================================================ */

void fut_apple_irq_init(const fut_platform_info_t *info) {
    if (!info || !info->has_aic) {
        fut_printf("[APPLE] Error: Platform does not support Apple AIC\n");
        return;
    }

    fut_printf("[APPLE] Initializing Apple Interrupt Controller\n");

    if (!fut_apple_aic_init(info)) {
        fut_printf("[APPLE] Error: Failed to initialize AIC\n");
        return;
    }

    /* Hook AIC dispatch into the platform-agnostic IRQ entry.  After
     * this, the asm trampoline in boot.S/fut_irq_handler delegates
     * to apple_aic_handle_irq() — which now forwards to the Rust
     * driver — instead of the GICv2 IAR/EOI flow.  Closes the
     * kernel-side half of Apple Silicon bring-up blocker #5
     * (docs/APPLE_SILICON_BRINGUP_PLAN.md). */
    extern void fut_irq_set_dispatch_backend(void (*fn)(void));
    fut_irq_set_dispatch_backend(apple_aic_handle_irq);

    /* ARM Generic Timer is delivered as FIQ on Apple Silicon — but
     * NOT through the AIC's event bitmap; the timer fires directly
     * to the CPU FIQ vector and is identified by CNTP_CTL_EL0.ISTATUS.
     * apple_aic_handle_fiq checks that bit first and re-arms via
     * fut_timer_irq_handler before falling through to the AIC scan
     * (in case some future build routes AIC events as FIQ).  Without
     * the timer short-circuit a FIQ storm would hang the kernel —
     * the timer keeps re-firing because the AIC scan doesn't re-arm
     * it. */
    extern void fut_fiq_set_dispatch_backend(void (*fn)(void));
    fut_fiq_set_dispatch_backend(apple_aic_handle_fiq);

    fut_printf("[APPLE] Apple interrupt subsystem initialized\n");
}
