// SPDX-License-Identifier: MPL-2.0
/*
 * eventfd.h - Kernel helpers for eventfd integration
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
