/* fut_io_budget.h - Per-process I/O Budget Tracking (Phase 4)
 *
 * Copyright (c) 2025 Kelsi Davis
 * Licensed under the MPL v2.0 — see LICENSE for details.
 *
 * I/O budget tracking to prevent per-process resource exhaustion attacks.
 * Tracks bytes and operations per-second with automatic reset.
 */

#pragma once

#include <stdint.h>
#include <stdbool.h>
#include "fut_task.h"

/* ============================================================
 *   I/O Budget Constants
 * ============================================================ */

/* Default I/O budgets (0 = unlimited) */
#define DEFAULT_IO_BYTES_PER_SEC  0     /* Bytes per second (0 = unlimited) */
#define DEFAULT_IO_OPS_PER_SEC    0     /* Operations per second (0 = unlimited) */

/* Per-operation sizes for budget accounting */
#define SENDTO_OP_SIZE            1     /* One operation per sendto() */
#define CONNECT_OP_SIZE           1     /* One operation per connect() */

/* Large I/O threshold (trigger additional rate limiting checks) */
#define LARGE_IO_THRESHOLD        (1024 * 1024)  /* 1MB */

/* ============================================================
 *   I/O Budget API
 * ============================================================ */

/**
 * Check and enforce per-process I/O byte budget.
 *
 * Resets budget counters if 1+ second has elapsed since last reset.
 * Returns true if operation is allowed, false if rate limit exceeded.
 *
 * @param task       Task to check budget for
 * @param bytes      Number of bytes to account for
 * @param current_ms Current time in milliseconds
 * @return true if budget allows operation, false if rate limited
 */
bool fut_io_budget_check_bytes(fut_task_t *task, uint64_t bytes, uint64_t current_ms);

/**
 * Check and enforce per-process I/O operation budget.
 *
 * Resets budget counters if 1+ second has elapsed since last reset.
 * Returns true if operation is allowed, false if rate limit exceeded.
 *
 * @param task       Task to check budget for
 * @param ops        Number of operations to account for
 * @param current_ms Current time in milliseconds
 * @return true if budget allows operation, false if rate limited
 */
bool fut_io_budget_check_ops(fut_task_t *task, uint64_t ops, uint64_t current_ms);

/**
 * Consume I/O bytes from task's budget.
 *
 * Should only be called after fut_io_budget_check_bytes() returns true.
 * Updates current second's byte counter.
 *
 * @param task  Task to consume budget from
 * @param bytes Number of bytes to consume
 */
void fut_io_budget_consume_bytes(fut_task_t *task, uint64_t bytes);

/**
 * Consume I/O operations from task's budget.
 *
 * Should only be called after fut_io_budget_check_ops() returns true.
 * Updates current second's operation counter.
 *
 * @param task Task to consume budget from
 * @param ops  Number of operations to consume
 */
void fut_io_budget_consume_ops(fut_task_t *task, uint64_t ops);

/**
 * Set per-process I/O byte rate limit.
 *
 * @param task     Task to set limit for
 * @param bytes    Bytes allowed per second (0 = unlimited)
 */
void fut_io_budget_set_byte_limit(fut_task_t *task, uint64_t bytes);

/**
 * Set per-process I/O operation rate limit.
 *
 * @param task Task to set limit for
 * @param ops  Operations allowed per second (0 = unlimited)
 */
void fut_io_budget_set_ops_limit(fut_task_t *task, uint64_t ops);

/**
 * Reset I/O budget counters (for testing/debugging).
 *
 * @param task Task to reset budget for
 */
void fut_io_budget_reset(fut_task_t *task);
