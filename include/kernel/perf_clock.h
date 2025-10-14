// SPDX-License-Identifier: MPL-2.0
/*
 * perf_clock.h - Lightweight cycle-counter helpers for performance harnesses
 */

#pragma once

#include <stddef.h>
#include <stdint.h>

struct fut_perf_stats {
    uint64_t p50;
    uint64_t p90;
    uint64_t p99;
};

/**
 * Read the timestamp counter with serialization.
 */
uint64_t fut_rdtsc(void);

/**
 * Calibrate and return cycles-per-millisecond. Cached after first call.
 */
uint64_t fut_cycles_per_ms(void);

/**
 * Convert cycles to nanoseconds using the cached calibration.
 */
uint64_t fut_cycles_to_ns(uint64_t cycles);

/**
 * Sort the provided sample buffer in-place (ascending).
 */
void fut_perf_sort(uint64_t *values, size_t count);

/**
 * Populate percentile statistics for the sorted sample buffer.
 */
void fut_perf_compute_stats(const uint64_t *values,
                            size_t count,
                            struct fut_perf_stats *out);
