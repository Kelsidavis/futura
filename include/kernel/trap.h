// SPDX-License-Identifier: MPL-2.0
/*
 * trap.h - Architecture-neutral trap helpers
 *
 * Provides helpers for handling architecture exceptions such as page faults.
 */

#pragma once

#include <stdbool.h>

#if defined(__x86_64__)
#include <arch/x86_64/regs.h>
#elif defined(__aarch64__)
#include <arch/arm64/regs.h>
#endif

bool fut_trap_handle_page_fault(fut_interrupt_frame_t *frame);
