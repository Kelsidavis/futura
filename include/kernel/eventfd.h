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
struct fut_waitq;

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

/**
 * fut_timerfd_poll - Query readiness for a timerfd file descriptor.
 *
 * @param file        Kernel file structure to test.
 * @param requested   Bitmask of EPOLL* events being requested.
 * @param ready_out   Optional pointer that receives the ready mask.
 *
 * @return true if @file refers to a timerfd, false otherwise.
 */
bool fut_timerfd_poll(struct fut_file *file, uint32_t requested, uint32_t *ready_out);

/**
 * fut_signalfd_poll - Query readiness for a signalfd file descriptor.
 *
 * @param file        Kernel file structure to test.
 * @param requested   Bitmask of EPOLL* events being requested.
 * @param ready_out   Optional pointer that receives the ready mask.
 *
 * @return true if @file refers to a signalfd, false otherwise.
 */
bool fut_signalfd_poll(struct fut_file *file, uint32_t requested, uint32_t *ready_out);

/**
 * fut_pipe_poll - Query readiness for a pipe file descriptor.
 *
 * Checks actual data availability for the read end and space
 * availability for the write end.
 *
 * @param file        Kernel file structure to test.
 * @param requested   Bitmask of EPOLL* events being requested.
 * @param ready_out   Optional pointer that receives the ready mask.
 *
 * @return true if @file refers to a pipe (read or write end), false otherwise.
 */
bool fut_pipe_poll(struct fut_file *file, uint32_t requested, uint32_t *ready_out);

/* ---- fdinfo helpers ---------------------------------------------------- */

/** Return eventfd counter, or -1 if @file is not an eventfd. */
int64_t fut_eventfd_get_count(struct fut_file *file);

/**
 * Fill timerfd metadata.  Returns 0 on success, -1 if not a timerfd.
 * NULL out-pointers are silently ignored.
 */
int fut_timerfd_get_info(struct fut_file *file,
                         int *clockid_out, uint64_t *ticks_out,
                         uint64_t *interval_ms_out);

/** Return signalfd sigmask, or 0 if @file is not a signalfd. */
uint64_t fut_signalfd_get_sigmask(struct fut_file *file);

/**
 * Set the epoll notify waitqueue on a timerfd file.
 * No-op if @file is not a timerfd.
 */
void fut_timerfd_set_epoll_notify(struct fut_file *file, struct fut_waitq *wq);
