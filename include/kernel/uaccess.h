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

struct fut_uaccess_window {
    const void *user_ptr;    /* Base address for most recent chunk */
    size_t length;           /* Length of chunk currently being accessed */
    int to_user;             /* Non-zero if copy direction is kernel->user */
    void *resume;            /* Label to resume execution on fault */
};

const struct fut_uaccess_window *fut_uaccess_window_current(void);
void fut_uaccess_window_fault(int error);
int fut_uaccess_window_error(void);
