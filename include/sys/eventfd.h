// SPDX-License-Identifier: MPL-2.0
/*
 * sys/eventfd.h - Event notification file descriptor
 *
 * Copyright (c) 2025 Kelsi Davis
 * Licensed under the MPL v2.0 — see LICENSE for details.
 *
 * Provides the eventfd interface for event notification between
 * processes or threads using file descriptor semantics.
 */

#pragma once

#include <stdint.h>

/* ============================================================
 *   eventfd Flags
 * ============================================================ */

#ifndef EFD_SEMAPHORE
#define EFD_SEMAPHORE   0x00000001  /* Provide semaphore-like semantics */
#endif
#ifndef EFD_CLOEXEC
#define EFD_CLOEXEC     02000000    /* Close on exec */
#endif
#ifndef EFD_NONBLOCK
#define EFD_NONBLOCK    00004000    /* Non-blocking mode */
#endif

/* ============================================================
 *   Type Definitions
 * ============================================================ */

/* Type for eventfd counter value */
typedef uint64_t eventfd_t;

/* ============================================================
 *   Function Declarations
 * ============================================================ */

/**
 * eventfd - Create a file descriptor for event notification
 *
 * @initval Initial counter value
 * @flags   EFD_CLOEXEC, EFD_NONBLOCK, EFD_SEMAPHORE
 *
 * Returns file descriptor on success, -1 on error (errno set)
 */
extern int eventfd(unsigned int initval, int flags);

/**
 * eventfd_read - Read event counter
 *
 * @fd    eventfd file descriptor
 * @value Pointer to store counter value
 *
 * For normal eventfd: Returns counter and resets to zero
 * For semaphore mode: Decrements counter by 1 and returns 1
 *
 * Returns 0 on success, -1 on error
 */
extern int eventfd_read(int fd, eventfd_t *value);

/**
 * eventfd_write - Increment event counter
 *
 * @fd    eventfd file descriptor
 * @value Value to add to counter
 *
 * Adds value to the counter. Blocks if would overflow (non-semaphore mode).
 *
 * Returns 0 on success, -1 on error
 */
extern int eventfd_write(int fd, eventfd_t value);

