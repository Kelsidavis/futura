// SPDX-License-Identifier: MPL-2.0
/*
 * sys/sysinfo.h - System information
 *
 * Copyright (c) 2025 Kelsi Davis
 * Licensed under the MPL v2.0 — see LICENSE for details.
 *
 * Provides the sysinfo structure and function for querying
 * system-wide statistics like memory usage and uptime.
 */

#pragma once

#include <stdint.h>

/* ============================================================
 *   sysinfo Structure
 * ============================================================ */

/**
 * struct sysinfo - System information (Linux-compatible)
 *
 * Contains system-wide statistics including memory usage,
 * swap space, load averages, and process count.
 *
 * @uptime      Seconds since boot
 * @loads       Load averages (1, 5, 15 minutes) scaled by SI_LOAD_SHIFT
 * @totalram    Total usable main memory size
 * @freeram     Available memory size
 * @sharedram   Amount of shared memory
 * @bufferram   Memory used by buffers
 * @totalswap   Total swap space size
 * @freeswap    Swap space still available
 * @procs       Number of current processes
 * @totalhigh   Total high memory size (above ~896MB on 32-bit)
 * @freehigh    Available high memory size
 * @mem_unit    Memory unit size in bytes (for scaling)
 *
 * Usage:
 *   struct sysinfo info;
 *   if (sysinfo(&info) == 0) {
 *       printf("Uptime: %ld seconds\n", info.uptime);
 *       printf("Total RAM: %lu bytes\n",
 *              info.totalram * info.mem_unit);
 *       printf("Free RAM: %lu bytes\n",
 *              info.freeram * info.mem_unit);
 *       printf("Processes: %d\n", info.procs);
 *   }
 *
 * Load averages:
 *   Load averages are scaled by (1 << SI_LOAD_SHIFT).
 *   To get the actual load average as a float:
 *     float load = (float)info.loads[0] / (1 << SI_LOAD_SHIFT);
 */
#ifndef _STRUCT_SYSINFO
#define _STRUCT_SYSINFO
struct sysinfo {
    int64_t  uptime;        /* Seconds since boot */
    uint64_t loads[3];      /* 1, 5, and 15 minute load averages */
    uint64_t totalram;      /* Total usable main memory size */
    uint64_t freeram;       /* Available memory size */
    uint64_t sharedram;     /* Amount of shared memory */
    uint64_t bufferram;     /* Memory used by buffers */
    uint64_t totalswap;     /* Total swap space size */
    uint64_t freeswap;      /* Swap space still available */
    uint16_t procs;         /* Number of current processes */
    uint16_t pad;           /* Padding for alignment */
    uint64_t totalhigh;     /* Total high memory size */
    uint64_t freehigh;      /* Available high memory size */
    uint32_t mem_unit;      /* Memory unit size in bytes */
    char     _f[8];         /* Padding to 64 bytes */
};
#endif

/* ============================================================
 *   Load Average Scaling
 * ============================================================ */

/**
 * SI_LOAD_SHIFT - Load average scale factor
 *
 * Load averages in struct sysinfo are scaled by (1 << SI_LOAD_SHIFT).
 * This allows representing fractional load averages as integers.
 *
 * To convert to floating point:
 *   float load = (float)sysinfo.loads[0] / (1 << SI_LOAD_SHIFT);
 */
#ifndef SI_LOAD_SHIFT
#define SI_LOAD_SHIFT   16
#endif

/* ============================================================
 *   Function Declarations
 * ============================================================ */

/**
 * sysinfo - Get system information
 *
 * @info  Pointer to sysinfo structure to fill
 *
 * Fills the structure with system-wide statistics including
 * memory usage, uptime, load averages, and process count.
 *
 * Returns 0 on success, -1 on error (with errno set).
 *
 * Errors:
 *   EFAULT  info is not valid
 */
extern int sysinfo(struct sysinfo *info);

/**
 * get_nprocs - Get number of available processors
 *
 * Returns the number of processors currently available in the system.
 * This may be less than the number of physical processors due to
 * processor affinity masks or cgroups.
 *
 * Returns number of available processors.
 */
extern int get_nprocs(void);

/**
 * get_nprocs_conf - Get number of configured processors
 *
 * Returns the number of processors configured in the system.
 * This is the total number of processors regardless of which
 * are currently available.
 *
 * Returns number of configured processors.
 */
extern int get_nprocs_conf(void);

/**
 * get_phys_pages - Get total number of physical memory pages
 *
 * Returns the total number of pages of physical memory in the system.
 * Multiply by sysconf(_SC_PAGESIZE) to get total bytes.
 *
 * Returns total physical memory pages.
 */
extern long get_phys_pages(void);

/**
 * get_avphys_pages - Get number of available physical memory pages
 *
 * Returns the number of currently available pages of physical memory.
 * This value can change as memory is allocated and freed.
 *
 * Returns available physical memory pages.
 */
extern long get_avphys_pages(void);

