// SPDX-License-Identifier: MPL-2.0
/*
 * perf_clock.c - x86_64 cycle counter helpers for performance harnesses
 */

#include <kernel/perf_clock.h>

#include <kernel/fut_timer.h>
#include <kernel/fut_sched.h>

#ifdef __x86_64__

static inline void cpu_relax(void) {
    __asm__ volatile("pause" ::: "memory");
}

uint64_t fut_rdtsc(void) {
    unsigned int lo = 0;
    unsigned int hi = 0;
    unsigned int aux = 0;
    __asm__ volatile("rdtscp" : "=a"(lo), "=d"(hi), "=c"(aux) :: "memory");
    __asm__ volatile("lfence" ::: "memory");
    return ((uint64_t)hi << 32) | lo;
}

uint64_t fut_cycles_per_ms(void) {
    static uint64_t cached = 0;
    static int calibrated = 0;

    if (__atomic_load_n(&calibrated, __ATOMIC_ACQUIRE) && cached != 0) {
        return cached;
    }

    /* Align to tick boundary for consistency. */
    uint64_t start_tick = fut_get_ticks();
    while (fut_get_ticks() == start_tick) {
        cpu_relax();
    }

    start_tick = fut_get_ticks();
    uint64_t start_cycles = fut_rdtsc();

    /* Wait ~50ms to average out jitter. */
    const uint64_t target_tick = start_tick + 50u;
    while (fut_get_ticks() < target_tick) {
        cpu_relax();
    }

    uint64_t end_cycles = fut_rdtsc();
    uint64_t elapsed_ms = fut_get_ticks() - start_tick;
    if (elapsed_ms == 0) {
        elapsed_ms = 1;
    }

    uint64_t cycles = (end_cycles - start_cycles) / elapsed_ms;
    if (cycles == 0) {
        cycles = 1;
    }

    cached = cycles;
    __atomic_store_n(&calibrated, 1, __ATOMIC_RELEASE);
    return cached;
}

uint64_t fut_cycles_to_ns(uint64_t cycles) {
    uint64_t cpm = fut_cycles_per_ms();
    if (cpm == 0) {
        return 0;
    }
#if defined(__SIZEOF_INT128__)
    __uint128_t scaled = (__uint128_t)cycles * 1000000ull;
    return (uint64_t)(scaled / cpm);
#else
    uint64_t quot = cycles / cpm;
    uint64_t rem = cycles % cpm;
    return quot * 1000000ull + (rem * 1000000ull) / cpm;
#endif
}

static void fut_perf_swap(uint64_t *a, uint64_t *b) {
    uint64_t tmp = *a;
    *a = *b;
    *b = tmp;
}

void fut_perf_sort(uint64_t *values, size_t count) {
    if (!values || count < 2) {
        return;
    }

    /* Simple in-place quicksort with manual stack to avoid recursion depth. */
    typedef struct {
        size_t lo;
        size_t hi;
    } range_t;

    range_t stack[64];
    size_t top = 0;
    stack[top++] = (range_t){ .lo = 0, .hi = count - 1 };

    while (top > 0) {
        range_t seg = stack[--top];
        size_t lo = seg.lo;
        size_t hi = seg.hi;
        while (lo < hi) {
            size_t i = lo;
            size_t j = hi;
            uint64_t pivot = values[lo + ((hi - lo) >> 1)];

            while (i <= j) {
                while (values[i] < pivot) {
                    ++i;
                }
                while (values[j] > pivot) {
                    if (j == 0) {
                        break;
                    }
                    --j;
                }
                if (i <= j) {
                    fut_perf_swap(&values[i], &values[j]);
                    ++i;
                    if (j == 0) {
                        break;
                    }
                    --j;
                }
            }

            if (j > lo) {
                if (top < sizeof(stack) / sizeof(stack[0])) {
                    stack[top++] = (range_t){ .lo = lo, .hi = j };
                }
            }
            lo = i;
        }
    }
}

void fut_perf_compute_stats(const uint64_t *values,
                            size_t count,
                            struct fut_perf_stats *out) {
    if (!values || !out || count == 0) {
        if (out) {
            out->p50 = out->p90 = out->p99 = 0;
        }
        return;
    }

    const size_t idx50 = (count - 1u) * 50u / 100u;
    const size_t idx90 = (count - 1u) * 90u / 100u;
    const size_t idx99 = (count - 1u) * 99u / 100u;

    out->p50 = values[idx50];
    out->p90 = values[idx90];
    out->p99 = values[idx99];
}

#else
#error "perf_clock.c only implemented for x86_64"
#endif
