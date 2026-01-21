/* fut_fd_util.h - File Descriptor and I/O Utility Functions
 *
 * Copyright (c) 2025 Kelsi Davis
 * Licensed under the MPL v2.0 — see LICENSE for details.
 *
 * Common utility functions for file descriptor and I/O operations.
 * Provides consistent categorization helpers for debug logging.
 */

#pragma once

#include <stddef.h>

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

/**
 * Get a human-readable category string for an I/O buffer size.
 * Used for debug logging to identify I/O request patterns.
 *
 * @param size Buffer size in bytes
 * @return Constant string describing the size category
 */
static inline const char *fut_size_category(size_t size) {
    if (size == 0) {
        return "zero";
    } else if (size <= 16) {
        return "tiny (<=16 bytes)";
    } else if (size <= 512) {
        return "small (<=512 bytes)";
    } else if (size <= 4096) {
        return "typical (<=4 KB)";
    } else if (size <= 65536) {
        return "large (<=64 KB)";
    } else if (size <= 1048576) {
        return "very large (<=1 MB)";
    } else {
        return "excessive (>1 MB)";
    }
}

/**
 * Get a human-readable category string for a file offset.
 * Used for debug logging to identify file position patterns.
 *
 * @param offset File offset in bytes
 * @return Constant string describing the offset category
 */
static inline const char *fut_offset_category(long long offset) {
    if (offset == 0) {
        return "beginning";
    } else if (offset < 4096) {
        return "near start (<4 KB)";
    } else if (offset < 1048576) {
        return "low (<1 MB)";
    } else if (offset < 1073741824LL) {
        return "medium (<1 GB)";
    } else {
        return "high (>=1 GB)";
    }
}
