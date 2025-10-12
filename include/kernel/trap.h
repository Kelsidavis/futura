// SPDX-License-Identifier: MPL-2.0
/*
 * trap.h - Architecture-neutral trap helpers
 *
 * Provides helpers for handling architecture exceptions such as page faults.
 */

#pragma once

#include <stdbool.h>

#include <arch/x86_64/regs.h>

bool fut_trap_handle_page_fault(fut_interrupt_frame_t *frame);
