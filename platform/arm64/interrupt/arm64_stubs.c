/*
 * Futura OS - ARM64 Stub Implementations
 * Copyright (C) 2025 Futura OS Project
 *
 * This file provides stub implementations for ARM64 platform of functions
 * that are either x86-64 specific or require full implementation in later phases.
 */

#include <kernel/errno.h>
#include <kernel/fut_memory.h>

/* ============================================================
 *   Test Framework Stubs (x86-64 specific)
 * ============================================================ */

void fut_tests_completed(void) {
    /* Test framework not implemented for ARM64 */
}

void fut_test_fail(const char *fmt, ...) {
    (void)fmt;
    /* Test framework not implemented for ARM64 */
}

void fut_test_pass(const char *fmt, ...) {
    (void)fmt;
    /* Test framework not implemented for ARM64 */
}

void fut_test_plan(int count) {
    (void)count;
    /* Test framework not implemented for ARM64 */
}

void fut_futfs_selftest_schedule(void) {
    /* FutureFS self-test not implemented for ARM64 */
}

void fut_perf_selftest_schedule(void) {
    /* Performance self-test not implemented for ARM64 */
}

/* ============================================================
 *   Framebuffer - Now implemented via Rust virtio-gpu driver
 * ============================================================ */
/* Framebuffer functions (fb_boot_splash, fb_is_available, etc.)
 * are now provided by kernel/video/fb_mmio.c with ARM64 support */

/* ============================================================
 *   Networking Stubs (x86-64 specific)
 * ============================================================ */

/* virtio_net_init now implemented in Rust for ARM64 - see drivers/rust/virtio_net */

/* ============================================================
 *   Userland Binary Staging Stubs (x86-64 specific)
 * ============================================================ */

int fut_stage_shell_binary(void) {
    return -ENODEV;  /* Userland not available for ARM64 */
}

int fut_stage_init_binary(void) {
    return -ENODEV;  /* Userland not available for ARM64 */
}

int fut_stage_cat_binary(void) {
    return -ENODEV;  /* Userland not available for ARM64 */
}

int fut_stage_echo_binary(void) {
    return -ENODEV;  /* Userland not available for ARM64 */
}

int fut_stage_wc_binary(void) {
    return -ENODEV;  /* Userland not available for ARM64 */
}

int fut_stage_fsd_binary(void) {
    return -ENODEV;  /* Userland not available for ARM64 */
}

int fut_stage_posixd_binary(void) {
    return -ENODEV;  /* Userland not available for ARM64 */
}

int fut_stage_fbtest_binary(void) {
    return -ENODEV;  /* Userland not available for ARM64 */
}

/* ============================================================
 *   Wayland Staging Stubs (x86-64 specific)
 * ============================================================ */

int fut_stage_wayland_compositor_binary(void) {
    return -ENODEV;  /* Wayland not available for ARM64 */
}

int fut_stage_wayland_client_binary(void) {
    return -ENODEV;  /* Wayland not available for ARM64 */
}

int fut_stage_wayland_color_client_binary(void) {
    return -ENODEV;  /* Wayland not available for ARM64 */
}

/* ============================================================
 *   Page Table Management
 * ============================================================
 * Implemented in platform/arm64/pmap.c
 * ============================================================ */

/* ============================================================
 *   Task State Segment Stubs (x86-64 specific)
 * ============================================================ */

void fut_tss_set_kernel_stack(uint32_t cpu_id, uint64_t stack_top) {
    (void)cpu_id;
    (void)stack_top;
    /* TSS not used on ARM64 */
}

/* ============================================================
 *   Context Switching (Architecture-dependent)
 * ============================================================ */

/* Context switch functions are now implemented in context_switch.S */
extern void fut_context_switch_asm(void);

/* ============================================================
 *   Hardware I/O Stubs (x86-64 specific)
 * ============================================================ */

void hal_outb(uint16_t port, uint8_t value) {
    (void)port;
    (void)value;
    /* x86-64 I/O port access not available on ARM64 */
}

/* ============================================================
 *   ARM64 Atomic Operation Symbols
 * ============================================================ */

/*
 * ARM64 atomic operations using inline assembly.
 * GCC generates calls to these libgcc helpers for C11 atomic operations.
 * We implement them using ARM64 atomic instructions (LDADD, STLR, etc.)
 */

#include <stdint.h>

/* Atomic store operations (used by atomic_store_explicit) */
void __atomic_store_8(volatile void *ptr, uint64_t val, int memorder) {
    (void)memorder;
    /* Use STLR (store-release) for atomic store */
    __asm__ volatile(
        "stlr %0, [%1]"
        :
        : "r"(val), "r"(ptr)
        : "memory"
    );
}

void __atomic_store_4(volatile void *ptr, uint32_t val, int memorder) {
    (void)memorder;
    __asm__ volatile(
        "stlr %w0, [%1]"
        :
        : "r"(val), "r"(ptr)
        : "memory"
    );
}

/* Atomic load operations (used by atomic_load_explicit) */
uint64_t __atomic_load_8(const volatile void *ptr, int memorder) {
    (void)memorder;
    uint64_t result;
    /* Use LDAR (load-acquire) for atomic load */
    __asm__ volatile(
        "ldar %0, [%1]"
        : "=r"(result)
        : "r"(ptr)
        : "memory"
    );
    return result;
}

uint32_t __atomic_load_4(const volatile void *ptr, int memorder) {
    (void)memorder;
    uint32_t result;
    __asm__ volatile(
        "ldar %w0, [%1]"
        : "=r"(result)
        : "r"(ptr)
        : "memory"
    );
    return result;
}

/* Atomic compare-and-exchange (used by atomic_compare_exchange_*) */
_Bool __atomic_compare_exchange_8(volatile void *ptr, void *expected, uint64_t desired,
                                   _Bool weak, int success_memorder, int failure_memorder) {
    (void)weak;
    (void)success_memorder;
    (void)failure_memorder;

    uint64_t *exp_ptr = (uint64_t *)expected;
    uint64_t old_val = *exp_ptr;
    uint64_t tmp;
    uint32_t store_result;
    _Bool success;

    __asm__ volatile(
        "1: ldaxr %0, [%3]\n"           // Load-exclusive with acquire
        "   cmp %0, %4\n"                // Compare with expected
        "   b.ne 2f\n"                   // Branch if not equal
        "   stlxr %w1, %5, [%3]\n"       // Store-exclusive with release
        "   cbnz %w1, 1b\n"              // Retry if store failed
        "   mov %w2, #1\n"               // Success
        "   b 3f\n"
        "2: clrex\n"                     // Clear exclusive monitor
        "   mov %w2, #0\n"               // Failure
        "3:"
        : "=&r"(tmp), "=&r"(store_result), "=&r"(success)
        : "r"(ptr), "r"(old_val), "r"(desired)
        : "cc", "memory"
    );

    if (!success) {
        *exp_ptr = tmp;
    }

    return success;
}

_Bool __atomic_compare_exchange_4(volatile void *ptr, void *expected, uint32_t desired,
                                   _Bool weak, int success_memorder, int failure_memorder) {
    (void)weak;
    (void)success_memorder;
    (void)failure_memorder;

    uint32_t *exp_ptr = (uint32_t *)expected;
    uint32_t old_val = *exp_ptr;
    uint32_t tmp;
    uint32_t store_result;
    _Bool success;

    __asm__ volatile(
        "1: ldaxr %w0, [%3]\n"
        "   cmp %w0, %w4\n"
        "   b.ne 2f\n"
        "   stlxr %w1, %w5, [%3]\n"
        "   cbnz %w1, 1b\n"
        "   mov %w2, #1\n"
        "   b 3f\n"
        "2: clrex\n"
        "   mov %w2, #0\n"
        "3:"
        : "=&r"(tmp), "=&r"(store_result), "=&r"(success)
        : "r"(ptr), "r"(old_val), "r"(desired)
        : "cc", "memory"
    );

    if (!success) {
        *exp_ptr = tmp;
    }

    return success;
}

/* ============================================================
 *   Interrupt Descriptor Table Stubs (x86-64 specific)
 * ============================================================ */

void fut_idt_set_entry(uint8_t vector, uint64_t handler, uint16_t selector, uint8_t type_attr, uint8_t ist) {
    (void)vector;
    (void)handler;
    (void)selector;
    (void)type_attr;
    (void)ist;
    /* IDT not used on ARM64 - interrupts handled via GIC */
}
