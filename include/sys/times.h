// SPDX-License-Identifier: MPL-2.0
/*
 * sys/times.h - Process time interface
 *
 * Copyright (c) 2025 Kelsi Davis
 * Licensed under the MPL v2.0 — see LICENSE for details.
 *
 * Provides the times() function and struct tms for process time accounting.
 */

#pragma once

#include <stdint.h>

/* ============================================================
 *   Type Definitions
 * ============================================================ */

/* clock_t: clock tick count (typically long) */
#ifndef _CLOCK_T
#define _CLOCK_T
typedef long clock_t;
#endif

/* ============================================================
 *   Data Structures
 * ============================================================ */

/* tms structure - process times in clock ticks */
#ifndef _STRUCT_TMS
#define _STRUCT_TMS
struct tms {
    clock_t tms_utime;   /* User CPU time */
    clock_t tms_stime;   /* System CPU time */
    clock_t tms_cutime;  /* User CPU time of terminated children */
    clock_t tms_cstime;  /* System CPU time of terminated children */
};
#endif

/* ============================================================
 *   Function Declarations
 * ============================================================ */

/**
 * Get process times.
 *
 * Stores the current process times (in clock ticks) in the tms structure
 * and returns the elapsed time since an arbitrary point in the past.
 *
 * @param buf Pointer to tms structure to receive time values
 * @return Elapsed clock ticks since arbitrary reference, or (clock_t)-1 on error
 */
extern clock_t times(struct tms *buf);
