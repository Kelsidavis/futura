// SPDX-License-Identifier: MPL-2.0
/*
 * trap.h - Architecture-neutral trap and exception handling
 *
 * Copyright (c) 2025 Kelsi Davis
 * Licensed under the MPL v2.0 — see LICENSE for details.
 *
 * Provides architecture-neutral interfaces for handling CPU exceptions
 * such as page faults, general protection faults, and other traps.
 * The actual implementation is architecture-specific but the interface
 * is consistent across x86_64 and ARM64.
 *
 * Exception handling flow:
 *   1. CPU triggers exception (e.g., page fault on invalid access)
 *   2. Architecture-specific handler saves context to interrupt frame
 *   3. Handler calls architecture-neutral trap function
 *   4. Trap function determines if fault is recoverable
 *   5. If recoverable (e.g., COW, demand paging), handle and return true
 *   6. If not recoverable, return false (caller terminates process)
 */

#pragma once

#include <stdbool.h>

#if defined(__x86_64__)
#include <platform/x86_64/regs.h>
#elif defined(__aarch64__)
#include <platform/arm64/regs.h>
#endif

/**
 * Handle a page fault exception.
 *
 * Called by the architecture-specific page fault handler to process
 * the fault. Attempts to resolve the fault through:
 *   - Copy-on-write page duplication
 *   - Demand paging (loading pages from backing store)
 *   - Stack guard page expansion
 *   - Restartable user memory copy recovery
 *
 * @param frame  Interrupt frame containing CPU state at fault time
 * @return true if fault was handled and execution can continue,
 *         false if fault is unrecoverable (process should be terminated)
 *
 * The interrupt frame contains:
 *   - Faulting address (cr2 on x86_64, FAR_EL1 on ARM64)
 *   - Error code indicating fault type (read/write/execute, user/kernel)
 *   - Saved registers for context restoration
 */
bool fut_trap_handle_page_fault(fut_interrupt_frame_t *frame);
