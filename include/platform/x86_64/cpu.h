/* cpu.h - x86_64 CPU feature negotiation helpers
 *
 * Copyright (c) 2025 Futura OS
 * Licensed under the MPL v2.0 — see LICENSE for details.
 */

#pragma once

#include <stdint.h>

typedef struct {
    uint8_t nx;         /* No-Execute bit support (EFER.NXE) */
    uint8_t osxsave;    /* XSAVE/XRESTORE support */
    uint8_t sse;        /* SSE (Streaming SIMD Extensions) */
    uint8_t avx;        /* AVX (Advanced Vector Extensions) */
    uint8_t fsgsbase;   /* RDFSBASE/RDGSBASE instructions */
    uint8_t pge;        /* Page Global Enable (CR4.PGE) */
    uint8_t smep;       /* Supervisor Mode Execution Prevention */
    uint8_t smap;       /* Supervisor Mode Access Prevention */
    /* Huge page support */
    uint8_t pse;        /* Page Size Extension (2MB pages) - CPUID.01H:EDX[bit 3] */
    uint8_t pdpe1gb;    /* 1GB page support - CPUID.80000001H:EDX[bit 26] */
} fut_cpu_features_t;

void cpu_features_init(void);
const fut_cpu_features_t *cpu_features_get(void);
