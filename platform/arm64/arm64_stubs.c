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

void fut_blk_async_selftest_schedule(void) {
    /* Block device self-test not implemented for ARM64 */
}

void fut_futfs_selftest_schedule(void) {
    /* FutureFS self-test not implemented for ARM64 */
}

void fut_net_selftest_schedule(void) {
    /* Network self-test not implemented for ARM64 */
}

void fut_perf_selftest_schedule(void) {
    /* Performance self-test not implemented for ARM64 */
}

/* ============================================================
 *   Framebuffer Stubs (x86-64 specific)
 * ============================================================ */

int fb_is_available(void) {
    return 0;  /* Framebuffer not available on ARM64 */
}

void fb_boot_splash(void) {
    /* Boot splash not implemented for ARM64 */
}

void fb_char_init(void) {
    /* Character framebuffer not implemented for ARM64 */
}

struct fb_info {
    void *base;
    int width;
    int height;
    int stride;
};

struct fb_info *fb_get_info(void) {
    return NULL;  /* Framebuffer not available on ARM64 */
}

/* ============================================================
 *   Networking Stubs (x86-64 specific)
 * ============================================================ */

int virtio_net_init(void) {
    return -ENODEV;  /* Virtio networking not implemented for ARM64 */
}

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
 *   Page Table Management Stubs
 * ============================================================ */

typedef struct pmap {
    void *root;
} pmap_t;

int pmap_map_user(pmap_t *pmap, uint64_t vaddr, uint64_t paddr, size_t size, int prot) {
    (void)pmap;
    (void)vaddr;
    (void)paddr;
    (void)size;
    (void)prot;
    return 0;  /* Success stub */
}

int pmap_probe_pte(pmap_t *pmap, uint64_t vaddr) {
    (void)pmap;
    (void)vaddr;
    return 0;  /* Entry exists stub */
}

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

/* These symbols are required by libgcc for atomic operations */
/* __aarch64_ldadd8_relax: Atomic add with relaxed semantics */
int __aarch64_ldadd8_relax(int *ptr, int val) {
    int result = *ptr;
    *ptr += val;
    return result;
}

/* __aarch64_ldadd8_acq_rel: Atomic add with acquire/release semantics */
int __aarch64_ldadd8_acq_rel(int *ptr, int val) {
    int result = *ptr;
    *ptr += val;
    __asm__ volatile("dmb ish" ::: "memory");
    return result;
}

/* __aarch64_cas8_relax: Atomic compare and swap with relaxed semantics */
int __aarch64_cas8_relax(int *ptr, int expected, int new_val) {
    int result = *ptr;
    if (result == expected) {
        *ptr = new_val;
    }
    return result;
}

/* Also provide unsigned variants */
unsigned __aarch64_ldadd8_relax_unsigned(unsigned *ptr, unsigned val) {
    unsigned result = *ptr;
    *ptr += val;
    return result;
}

unsigned __aarch64_ldadd8_acq_rel_unsigned(unsigned *ptr, unsigned val) {
    unsigned result = *ptr;
    *ptr += val;
    __asm__ volatile("dmb ish" ::: "memory");
    return result;
}

unsigned __aarch64_cas8_relax_unsigned(unsigned *ptr, unsigned expected, unsigned new_val) {
    unsigned result = *ptr;
    if (result == expected) {
        *ptr = new_val;
    }
    return result;
}

