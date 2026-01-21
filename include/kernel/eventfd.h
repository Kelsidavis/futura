/* include/kernel/eventfd.h - Eventfd integration helpers
 *
 * Copyright (c) 2025 Kelsi Davis
 * Licensed under the MPL v2.0 — see LICENSE for details.
 *
 * Provides kernel-side helpers for eventfd file descriptor management.
 */

#pragma once

#include <stdbool.h>
#include <stdint.h>

struct fut_file;

/**
 * fut_eventfd_poll - Query readiness for an eventfd file descriptor.
 *
 * @param file        Kernel file structure to test.
 * @param requested   Bitmask of EPOLL* events being requested.
 * @param ready_out   Optional pointer that receives the ready mask.
 *
 * @return true if @file refers to an eventfd, false otherwise.
 */
bool fut_eventfd_poll(struct fut_file *file, uint32_t requested, uint32_t *ready_out);
