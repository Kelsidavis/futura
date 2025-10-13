/* msr.h - x86_64 MSR and extended control helpers
 *
 * Copyright (c) 2025 Futura OS
 * Licensed under the MPL v2.0 — see LICENSE for details.
 */

#pragma once

#include <stdint.h>

static inline uint64_t rdmsr(uint32_t msr) {
    uint32_t lo, hi;
    __asm__ volatile("rdmsr" : "=a"(lo), "=d"(hi) : "c"(msr));
    return ((uint64_t)hi << 32) | lo;
}

static inline void wrmsr(uint32_t msr, uint64_t val) {
    __asm__ volatile("wrmsr"
                     :
                     : "c"(msr), "a"((uint32_t)val), "d"((uint32_t)(val >> 32)));
}

static inline uint64_t xgetbv(uint32_t index) {
    uint32_t lo, hi;
    __asm__ volatile("xgetbv" : "=a"(lo), "=d"(hi) : "c"(index));
    return ((uint64_t)hi << 32) | lo;
}

static inline void xsetbv(uint32_t index, uint64_t value) {
    uint32_t lo = (uint32_t)value;
    uint32_t hi = (uint32_t)(value >> 32);
    __asm__ volatile("xsetbv" : : "c"(index), "a"(lo), "d"(hi));
}
