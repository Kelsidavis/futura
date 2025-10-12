// SPDX-License-Identifier: MPL-2.0
/*
 * uaccess.h - Safe user memory access helpers
 *
 * Phase 1 surface for copying data between kernel space and user space
 * without relying on hardware faults.  The implementation validates that
 * the supplied user ranges fall inside the permitted VA window and that
 * present, user-accessible PTEs exist before touching memory.  Future
 * phases will integrate with full per-task VM contexts and restartable
 * copies, but the interface is intentionally stable.
 */

#pragma once

#include <stddef.h>
#include <stdint.h>

int fut_access_ok(const void *u_ptr, size_t len, int write);
int fut_copy_from_user(void *k_dst, const void *u_src, size_t n);
int fut_copy_to_user(void *u_dst, const void *k_src, size_t n);

extern uintptr_t g_user_lo;
extern uintptr_t g_user_hi;
