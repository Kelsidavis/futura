/* kernel/stubs_missing.c - Test framework and stub implementations
 *
 * Copyright (c) 2025 Kelsi Davis
 * Licensed under the MPL v2.0 — see LICENSE for details.
 *
 * Provides test harness implementation and minimal stubs for linker symbols.
 */

#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdatomic.h>
#include <kernel/fut_task.h>

#if defined(__x86_64__)
#include <platform/x86_64/qemu_exit.h>
#else
#error "qemu_exit not implemented for this architecture"
#endif

#include <kernel/kprintf.h>

/* Test framework implementation */
static _Atomic bool g_tests_completed = false;
static _Atomic bool g_tests_failed = false;
static _Atomic uint16_t g_tests_planned = 0;
static _Atomic uint16_t g_tests_passed = 0;

bool fut_tests_completed(void) {
    return atomic_load_explicit(&g_tests_completed, memory_order_acquire);
}

static void mark_done(void) {
    atomic_store_explicit(&g_tests_completed, true, memory_order_release);
}

static void try_finish(void) {
    if (fut_tests_completed()) {
        return;
    }
    if (atomic_load_explicit(&g_tests_failed, memory_order_acquire)) {
        return;
    }
    uint16_t planned = atomic_load_explicit(&g_tests_planned, memory_order_acquire);
    if (planned == 0) {
        return;
    }
    uint16_t passed = atomic_load_explicit(&g_tests_passed, memory_order_acquire);

    /* Debug: Show test progress */
    fut_printf("[TEST-DEBUG] Tests passed: %u / %u\n", passed, planned);

    if (passed < planned) {
        return;
    }

    mark_done();
    fut_printf("[TEST] ALL TESTS PASSED (%u/%u)\n", passed, planned);
    qemu_exit(0);
}

void fut_test_plan(uint16_t count) {
    atomic_store_explicit(&g_tests_planned, count, memory_order_release);
    try_finish();
}

void fut_test_pass(void) {
    atomic_fetch_add_explicit(&g_tests_passed, 1, memory_order_acq_rel);
    try_finish();
}

void fut_test_fail(uint16_t code) {
    if (fut_tests_completed()) {
        return;
    }
    atomic_store_explicit(&g_tests_failed, true, memory_order_release);
    mark_done();
    uint16_t norm = (code == 0) ? 1 : code;
    fut_printf("[TEST] FAILED code=%u\n", (unsigned)norm);
    qemu_exit(norm);
}

/* Note: Framebuffer, PS2, Block register, and Perf stubs are now implemented in their respective source files */
