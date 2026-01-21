// SPDX-License-Identifier: MPL-2.0
/*
 * perf_clock.h - Lightweight cycle-counter helpers for performance harnesses
 *
 * Copyright (c) 2025 Kelsi Davis
 * Licensed under the MPL v2.0 — see LICENSE for details.
 *
 * Provides CPU timestamp counter (TSC) access and calibration for
 * high-precision performance measurements. Used by kernel benchmarks
 * and performance monitoring code.
 *
 * Features:
 *   - Serialized TSC reads (prevents instruction reordering)
 *   - Automatic calibration to convert cycles to nanoseconds
 *   - Percentile statistics computation (p50, p90, p99)
 *   - In-place sorting for sample buffers
 *
 * Usage:
 *   1. Call fut_rdtsc() before and after the code being measured
 *   2. Collect multiple samples into an array
 *   3. Sort with fut_perf_sort() and compute stats with fut_perf_compute_stats()
 *   4. Convert cycle counts to nanoseconds with fut_cycles_to_ns()
 */

#pragma once

#include <stddef.h>
#include <stdint.h>

/**
 * Percentile statistics for performance measurements.
 *
 * Contains median (p50) and tail latencies (p90, p99) which are
 * commonly used for performance analysis. Values are in cycles.
 */
struct fut_perf_stats {
    uint64_t p50;           /**< 50th percentile (median) */
    uint64_t p90;           /**< 90th percentile */
    uint64_t p99;           /**< 99th percentile */
};

/**
 * Read the timestamp counter with serialization.
 *
 * Uses RDTSC preceded by a serializing instruction (CPUID or fence)
 * to prevent instruction reordering and ensure accurate measurements.
 *
 * @return Current CPU cycle count
 */
uint64_t fut_rdtsc(void);

/**
 * Calibrate and return cycles-per-millisecond.
 *
 * Performs one-time calibration using a timer reference, then
 * caches the result for subsequent calls. Thread-safe.
 *
 * @return CPU cycles per millisecond
 */
uint64_t fut_cycles_per_ms(void);

/**
 * Convert cycles to nanoseconds using the cached calibration.
 *
 * Must be called after at least one call to fut_cycles_per_ms()
 * or fut_rdtsc() to ensure calibration has occurred.
 *
 * @param cycles  Cycle count to convert
 * @return Equivalent time in nanoseconds
 */
uint64_t fut_cycles_to_ns(uint64_t cycles);

/**
 * Sort the provided sample buffer in-place (ascending).
 *
 * Uses an efficient sorting algorithm suitable for performance
 * measurement sample sizes (typically hundreds to thousands of samples).
 *
 * @param values  Array of cycle measurements to sort
 * @param count   Number of elements in the array
 */
void fut_perf_sort(uint64_t *values, size_t count);

/**
 * Populate percentile statistics for a sorted sample buffer.
 *
 * Computes p50, p90, and p99 percentiles from a pre-sorted array.
 * The array must be sorted in ascending order (use fut_perf_sort()).
 *
 * @param values  Sorted array of cycle measurements
 * @param count   Number of elements in the array
 * @param out     Output structure to fill with percentile values
 */
void fut_perf_compute_stats(const uint64_t *values,
                            size_t count,
                            struct fut_perf_stats *out);
