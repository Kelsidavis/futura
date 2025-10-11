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
