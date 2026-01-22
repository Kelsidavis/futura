/* kernel/tests/test_main.h - Test and selftest function declarations
 *
 * Copyright (c) 2025 Kelsi Davis
 * Licensed under the MPL v2.0 — see LICENSE for details.
 *
 * Provides declarations for kernel selftests and smoke tests.
 * Include this header instead of using scattered extern declarations.
 */

#pragma once

#include <kernel/fut_task.h>

/* ============================================================
 *   Synchronous Smoke Tests
 * ============================================================ */

/**
 * Echo syscall selftest.
 * Tests the echo syscall roundtrip with various buffer sizes.
 */
void fut_echo_selftest(void);

/**
 * Framebuffer smoke test.
 * Tests basic framebuffer operations and pixel drawing.
 */
void fut_fb_smoke(void);

/**
 * Input subsystem smoke test.
 * Tests keyboard/input event handling.
 */
void fut_input_smoke(void);

/**
 * Double exec smoke test.
 * Tests exec-after-exec scenarios.
 */
void fut_exec_double_smoke(void);

/**
 * Memory management tests.
 * Runs comprehensive MM subsystem tests.
 */
void fut_mm_tests_run(void);

/* ============================================================
 *   Asynchronous Scheduled Selftests
 *
 *   These tests schedule work to be done by a task rather than
 *   running synchronously. The task parameter receives the task
 *   context for scheduling async operations.
 * ============================================================ */

/**
 * Block device async selftest.
 * Tests asynchronous block I/O operations.
 */
void fut_blk_async_selftest_schedule(fut_task_t *task);

/**
 * FuturaFS filesystem selftest.
 * Tests FuturaFS operations and persistence.
 */
void fut_futfs_selftest_schedule(fut_task_t *task);

/**
 * Network subsystem selftest.
 * Tests TCP/IP stack and socket operations.
 */
void fut_net_selftest_schedule(fut_task_t *task);

/**
 * Performance benchmark tests.
 * Runs performance measurements for various subsystems.
 */
void fut_perf_selftest_schedule(fut_task_t *task);

/**
 * Multiprocess selftest.
 * Tests fork/exec and IPC between processes.
 */
void fut_multiprocess_selftest_schedule(fut_task_t *task);

/**
 * dup2 syscall selftest.
 * Tests file descriptor duplication.
 */
void fut_dup2_selftest_schedule(fut_task_t *task);

/**
 * Pipe selftest.
 * Tests pipe creation, reading, and writing.
 */
void fut_pipe_selftest_schedule(fut_task_t *task);

/**
 * Signal handling selftest.
 * Tests signal delivery and handling.
 */
void fut_signal_selftest_schedule(fut_task_t *task);

/**
 * Capability subsystem selftest.
 * Tests capability-based security enforcement.
 */
void fut_cap_selftest_schedule(fut_task_t *task);
