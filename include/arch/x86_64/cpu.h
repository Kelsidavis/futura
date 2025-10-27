/* cpu.h - x86_64 CPU feature negotiation helpers
 *
 * Copyright (c) 2025 Futura OS
 * Licensed under the MPL v2.0 — see LICENSE for details.
 */

#pragma once

#include <stdint.h>

typedef struct {
    uint8_t nx;
    uint8_t osxsave;
    uint8_t sse;
    uint8_t avx;
    uint8_t fsgsbase;
    uint8_t pge;
    uint8_t smep;
    uint8_t smap;
} fut_cpu_features_t;

void cpu_features_init(void);
const fut_cpu_features_t *cpu_features_get(void);
