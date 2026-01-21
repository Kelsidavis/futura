// SPDX-License-Identifier: MPL-2.0
/*
 * uaccess.h - Safe user memory access helpers
 *
 * Copyright (c) 2025 Kelsi Davis
 * Licensed under the MPL v2.0 — see LICENSE for details.
 *
 * Provides safe primitives for copying data between kernel space and user
 * space without relying on hardware faults. The implementation validates
 * that supplied user ranges fall inside the permitted VA window and that
 * present, user-accessible PTEs exist before touching memory.
 *
 * Security model:
 *   User space pointers MUST be validated before dereferencing. A malicious
 *   or buggy userspace program could pass any pointer value, including:
 *     - NULL pointers
 *     - Kernel space addresses (attempting to read/corrupt kernel memory)
 *     - Unmapped addresses (causing page faults)
 *     - Addresses outside process's valid memory regions
 *
 *   These functions protect against all such attacks by:
 *     1. Checking pointer range against [g_user_lo, g_user_hi)
 *     2. Verifying page table entries are present and user-accessible
 *     3. Checking write permission for write operations
 *
 * Usage pattern:
 *   // System call handler receiving user pointer
 *   int sys_read(int fd, void __user *buf, size_t count) {
 *       char kbuf[PAGE_SIZE];
 *       size_t to_copy = min(count, sizeof(kbuf));
 *
 *       // Read data into kernel buffer first
 *       ssize_t got = do_read(fd, kbuf, to_copy);
 *       if (got < 0) return got;
 *
 *       // Safely copy to user space
 *       if (fut_copy_to_user(buf, kbuf, got) != 0) {
 *           return -EFAULT;  // Bad user pointer
 *       }
 *       return got;
 *   }
 *
 * Future phases will integrate with full per-task VM contexts and
 * restartable copies, but this interface is intentionally stable.
 */

#pragma once

#include <stddef.h>
#include <stdint.h>

/**
 * Validate user memory access.
 *
 * Checks whether the specified user memory range is valid for the
 * requested access type. This is a quick bounds check that verifies
 * the range falls within [g_user_lo, g_user_hi).
 *
 * @param u_ptr  User space pointer to validate
 * @param len    Length of memory region in bytes
 * @param write  Non-zero if write access is needed, zero for read-only
 * @return 0 if access is permitted, non-zero on error (e.g., -EFAULT)
 *
 * Note: This function only does bounds checking. The actual copy
 * functions perform additional PTE validation before touching memory.
 *
 * Example:
 *   if (fut_access_ok(user_buf, sizeof(struct data), 1) != 0) {
 *       return -EFAULT;  // User buffer not writable
 *   }
 */
int fut_access_ok(const void *u_ptr, size_t len, int write);

/**
 * Copy data from user space to kernel space.
 *
 * Safely copies n bytes from a user space source buffer to a kernel
 * destination buffer. Validates that the entire source range is within
 * user space bounds and is readable by the current task.
 *
 * @param k_dst  Kernel space destination buffer (must be valid)
 * @param u_src  User space source buffer (will be validated)
 * @param n      Number of bytes to copy
 * @return 0 on success, negative error code on failure
 *         -EFAULT: Invalid user pointer or access denied
 *
 * IMPORTANT: The kernel destination buffer is NOT validated. It is the
 * caller's responsibility to ensure k_dst points to valid kernel memory
 * with sufficient size.
 *
 * Example:
 *   struct user_request req;
 *   if (fut_copy_from_user(&req, user_ptr, sizeof(req)) != 0) {
 *       return -EFAULT;
 *   }
 *   // Now safe to use req
 */
int fut_copy_from_user(void *k_dst, const void *u_src, size_t n);

/**
 * Copy data from kernel space to user space.
 *
 * Safely copies n bytes from a kernel source buffer to a user space
 * destination buffer. Validates that the entire destination range is
 * within user space bounds and is writable by the current task.
 *
 * @param u_dst  User space destination buffer (will be validated)
 * @param k_src  Kernel space source buffer (must be valid)
 * @param n      Number of bytes to copy
 * @return 0 on success, negative error code on failure
 *         -EFAULT: Invalid user pointer or access denied
 *
 * IMPORTANT: The kernel source buffer is NOT validated. It is the
 * caller's responsibility to ensure k_src points to valid kernel memory.
 *
 * Example:
 *   struct kernel_response resp = { .status = OK, .data = result };
 *   if (fut_copy_to_user(user_ptr, &resp, sizeof(resp)) != 0) {
 *       return -EFAULT;
 *   }
 */
int fut_copy_to_user(void *u_dst, const void *k_src, size_t n);

/**
 * User space virtual address bounds.
 *
 * These globals define the valid range for user space pointers:
 *   - g_user_lo: Lowest valid user space address (inclusive)
 *   - g_user_hi: Highest valid user space address (exclusive)
 *
 * Any pointer outside [g_user_lo, g_user_hi) is rejected by the
 * access validation functions. These values are architecture-specific
 * and set during early boot.
 *
 * Typical values:
 *   x86_64:  g_user_lo = 0x0, g_user_hi = 0x00007FFFFFFFFFFF
 *   arm64:   g_user_lo = 0x0, g_user_hi = 0x0000FFFFFFFFFFFF
 */
extern uintptr_t g_user_lo;
extern uintptr_t g_user_hi;

/**
 * Restartable copy window state.
 *
 * Tracks the current user memory access in progress, allowing the page
 * fault handler to identify and handle faults during copy operations.
 * This enables restartable copies where a fault partway through can be
 * recovered without losing progress.
 *
 * Fields:
 *   user_ptr - Base address of the current chunk being accessed
 *   length   - Size of the current chunk in bytes
 *   to_user  - Direction flag: non-zero for kernel->user, zero for user->kernel
 *   resume   - Jump target to resume execution after handling a fault
 *
 * This structure is used internally by the copy functions and fault
 * handlers. Most kernel code should not access it directly.
 */
struct fut_uaccess_window {
    const void *user_ptr;    /**< Base address for most recent chunk */
    size_t length;           /**< Length of chunk currently being accessed */
    int to_user;             /**< Non-zero if copy direction is kernel->user */
    void *resume;            /**< Label to resume execution on fault */
};

/**
 * Get the current thread's uaccess window.
 *
 * Returns a pointer to the uaccess window for the currently executing
 * thread. This is used by the page fault handler to determine if a
 * fault occurred during a user memory copy operation.
 *
 * @return Pointer to current thread's uaccess window, or NULL if none active
 */
const struct fut_uaccess_window *fut_uaccess_window_current(void);

/**
 * Signal a fault during user memory access.
 *
 * Called by the page fault handler when a fault occurs during a
 * restartable copy operation. Records the error code and triggers
 * recovery via the window's resume point.
 *
 * @param error  Error code to record (typically -EFAULT)
 *
 * This function does not return normally - it jumps to the resume
 * point set up by the copy function.
 */
void fut_uaccess_window_fault(int error);

/**
 * Get the error from the last uaccess window fault.
 *
 * After a restartable copy returns due to a fault, this function
 * retrieves the error code that was recorded.
 *
 * @return Error code from last fault, or 0 if no fault occurred
 */
int fut_uaccess_window_error(void);
