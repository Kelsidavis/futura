/* kernel/io_budget.c - Per-process I/O Budget Tracking (Phase 4)
 *
 * Copyright (c) 2025 Kelsi Davis
 * Licensed under the MPL v2.0 — see LICENSE for details.
 *
 * Implementation of per-process I/O budget tracking to prevent
 * resource exhaustion DoS attacks (sendto flood, connection flood, etc).
 *
 * Design:
 * - Per-task byte and operation counters (reset every 1+ second)
 * - Configurable per-second limits (0 = unlimited)
 * - Fail-fast checks before allocating kernel resources
 * - Automatically resets window when time advances 1+ second
 *
 * Security Model:
 * - Prevents single-process from exhausting system resources
 * - Allows bursty traffic (full budget per second)
 * - Rate limiting kicks in only when limit exceeded in current window
 */

#include <kernel/fut_io_budget.h>
#include <kernel/fut_task.h>
#include <kernel/fut_timer.h>
#include <stdint.h>

#include <kernel/kprintf.h>

/* I/O budget time window in milliseconds (1 second) */
#define IO_BUDGET_WINDOW_MS 1000

/**
 * Check and enforce per-process I/O byte budget.
 *
 * Implements token bucket algorithm:
 * - Each second, budget resets to io_bytes_per_sec
 * - Bytes consumed reduce budget for current second
 * - If current + new_bytes > limit, rate limited (return false)
 */
bool fut_io_budget_check_bytes(fut_task_t *task, uint64_t bytes, uint64_t current_ms) {
    if (!task) {
        return false;
    }

    /* If no limit set (0), allow unlimited bytes */
    if (task->io_bytes_per_sec == 0) {
        return true;
    }

    /* Check if budget window needs reset (1+ second elapsed) */
    uint64_t time_elapsed_ms = current_ms - task->io_budget_reset_time_ms;
    if (time_elapsed_ms >= IO_BUDGET_WINDOW_MS) {
        /* Reset budget counters for new second */
        task->io_bytes_current = 0;
        task->io_ops_current = 0;
        task->io_budget_reset_time_ms = current_ms;
        time_elapsed_ms = 0;
    }

    /* Check if adding these bytes would exceed budget for current second */
    if (task->io_bytes_current + bytes > task->io_bytes_per_sec) {
        fut_printf("[IO_BUDGET] PID %u: Byte budget exhausted in current second "
                   "(current=%llu, requested=%llu, limit=%llu)\n",
                   task->pid, task->io_bytes_current, bytes, task->io_bytes_per_sec);
        return false;
    }

    return true;
}

/**
 * Check and enforce per-process I/O operation budget.
 *
 * Similar to byte budget, but tracks operations instead.
 */
bool fut_io_budget_check_ops(fut_task_t *task, uint64_t ops, uint64_t current_ms) {
    if (!task) {
        return false;
    }

    /* If no limit set (0), allow unlimited operations */
    if (task->io_ops_per_sec == 0) {
        return true;
    }

    /* Check if budget window needs reset (1+ second elapsed) */
    uint64_t time_elapsed_ms = current_ms - task->io_budget_reset_time_ms;
    if (time_elapsed_ms >= IO_BUDGET_WINDOW_MS) {
        /* Reset budget counters for new second */
        task->io_bytes_current = 0;
        task->io_ops_current = 0;
        task->io_budget_reset_time_ms = current_ms;
        time_elapsed_ms = 0;
    }

    /* Check if adding these operations would exceed budget for current second */
    if (task->io_ops_current + ops > task->io_ops_per_sec) {
        fut_printf("[IO_BUDGET] PID %u: Operation budget exhausted in current second "
                   "(current=%llu, requested=%llu, limit=%llu)\n",
                   task->pid, task->io_ops_current, ops, task->io_ops_per_sec);
        return false;
    }

    return true;
}

/**
 * Consume bytes from I/O budget.
 *
 * Should be called after fut_io_budget_check_bytes() returns true
 * to actually charge the bytes against the budget.
 */
void fut_io_budget_consume_bytes(fut_task_t *task, uint64_t bytes) {
    if (!task || task->io_bytes_per_sec == 0) {
        return;  /* No tracking if no limit set */
    }

    task->io_bytes_current += bytes;
}

/**
 * Consume operations from I/O budget.
 *
 * Should be called after fut_io_budget_check_ops() returns true
 * to actually charge the operations against the budget.
 */
void fut_io_budget_consume_ops(fut_task_t *task, uint64_t ops) {
    if (!task || task->io_ops_per_sec == 0) {
        return;  /* No tracking if no limit set */
    }

    task->io_ops_current += ops;
}

/**
 * Set per-process I/O byte rate limit.
 */
void fut_io_budget_set_byte_limit(fut_task_t *task, uint64_t bytes) {
    if (!task) {
        return;
    }

    task->io_bytes_per_sec = bytes;
    /* Reset counters when limit changes */
    task->io_bytes_current = 0;
    task->io_ops_current = 0;
    task->io_budget_reset_time_ms = fut_get_ticks();
}

/**
 * Set per-process I/O operation rate limit.
 */
void fut_io_budget_set_ops_limit(fut_task_t *task, uint64_t ops) {
    if (!task) {
        return;
    }

    task->io_ops_per_sec = ops;
    /* Reset counters when limit changes */
    task->io_bytes_current = 0;
    task->io_ops_current = 0;
    task->io_budget_reset_time_ms = fut_get_ticks();
}

/**
 * Reset I/O budget counters (for testing/debugging).
 */
void fut_io_budget_reset(fut_task_t *task) {
    if (!task) {
        return;
    }

    task->io_bytes_current = 0;
    task->io_ops_current = 0;
    task->io_budget_reset_time_ms = fut_get_ticks();
}

/**
 * Check I/O rate limit and consume one operation (convenience wrapper).
 *
 * This is a convenience function that checks the rate limit and automatically
 * consumes one operation if allowed. Returns standard errno values.
 *
 * @param syscall_name Name of syscall for logging (e.g., "read", "write")
 * @return 0 if operation allowed (and consumed), -EAGAIN if rate limited
 *
 * Usage:
 *   int ret = fut_io_check_and_consume(task, "read");
 *   if (ret < 0) return ret;  // Rate limited
 *   // ... perform I/O operation ...
 */
int fut_io_check_and_consume(fut_task_t *task, const char *syscall_name) {
    if (!task) {
        return 0;  /* No task = no limit (boot/kernel context) */
    }

    uint64_t now_ms = fut_get_ticks();

    /* Check if operation is allowed */
    if (!fut_io_budget_check_ops(task, 1, now_ms)) {
        /* Rate limit exceeded */
        fut_printf("[IO-RATE-LIMIT] %s() rate limit exceeded for pid %llu: "
                   "%llu ops >= %llu limit (Phase 5: DoS prevention)\n",
                   syscall_name, task->pid, task->io_ops_current, task->io_ops_per_sec);
        return -11;  /* -EAGAIN */
    }

    /* Consume the operation */
    fut_io_budget_consume_ops(task, 1);

    return 0;
}
