/* fut_fd_util.h - File Descriptor Utility Functions
 *
 * Copyright (c) 2025 Kelsi Davis
 * Licensed under the MPL v2.0 — see LICENSE for details.
 *
 * Common utility functions for file descriptor operations.
 */

#pragma once

/**
 * Get a human-readable category string for a file descriptor number.
 * Used for debug logging to identify FD usage patterns.
 *
 * @param fd File descriptor number
 * @return Constant string describing the FD category
 */
static inline const char *fut_fd_category(int fd) {
    if (fd <= 2) {
        return "standard (stdin/stdout/stderr)";
    } else if (fd < 10) {
        return "low (common user FDs)";
    } else if (fd < 100) {
        return "typical (normal range)";
    } else if (fd < 1024) {
        return "high (many open files)";
    } else {
        return "very high (unusual)";
    }
}
