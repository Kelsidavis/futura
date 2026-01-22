/* posix_syscall.h - POSIX Syscall Dispatch Interface
 *
 * Copyright (c) 2025 Kelsi Davis
 * Licensed under the MPL v2.0 — see LICENSE for details.
 *
 * Public interface for POSIX syscall dispatch subsystem.
 */

#pragma once

#include <stdint.h>

/**
 * Main syscall dispatch function.
 * Called from architecture-specific syscall entry points.
 *
 * @param syscall_num Syscall number
 * @param arg1-arg6   Syscall arguments (up to 6 arguments)
 * @return Syscall return value (or -errno on error)
 */
int64_t posix_syscall_dispatch(uint64_t syscall_num,
                                uint64_t arg1, uint64_t arg2, uint64_t arg3,
                                uint64_t arg4, uint64_t arg5, uint64_t arg6);

/**
 * Initialize POSIX syscall subsystem.
 * Must be called during kernel initialization.
 */
void posix_syscall_init(void);

long syscall_entry_c(uint64_t nr,
                     uint64_t a1, uint64_t a2, uint64_t a3,
                     uint64_t a4, uint64_t a5, uint64_t a6);

/**
 * Propagate socket ownership when duplicating file descriptors.
 * Called by dup/dup2/dup3/fcntl(F_DUPFD) to ensure socket subsystem
 * tracking remains consistent.
 *
 * @param oldfd Original file descriptor
 * @param newfd New file descriptor (after successful dup)
 * @return 0 on success, -errno on error
 */
int propagate_socket_dup(int oldfd, int newfd);

/**
 * Copy a null-terminated string from userspace to kernel buffer.
 * Performs userspace access validation and ensures null termination.
 *
 * @param user_str   User-provided string pointer
 * @param kernel_buf Kernel buffer to copy into
 * @param max_len    Maximum length including null terminator
 * @return 0 on success, -EFAULT if user_str invalid, -ENAMETOOLONG if too long
 */
int copy_user_string(const char *user_str, char *kernel_buf, size_t max_len);
