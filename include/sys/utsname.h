// SPDX-License-Identifier: MPL-2.0
/*
 * sys/utsname.h - System identification
 *
 * Copyright (c) 2025 Kelsi Davis
 * Licensed under the MPL v2.0 — see LICENSE for details.
 *
 * Provides the utsname structure and uname() function for
 * retrieving system identification information.
 */

#pragma once

/* ============================================================
 *   Constants
 * ============================================================ */

/* Field size for utsname strings (including null terminator) */
#ifndef _UTSNAME_LENGTH
#define _UTSNAME_LENGTH     65
#endif

/* Alternative name used by some systems */
#ifndef SYS_NMLN
#define SYS_NMLN            _UTSNAME_LENGTH
#endif

/* ============================================================
 *   utsname Structure
 * ============================================================ */

/**
 * struct utsname - System information structure
 *
 * Contains strings identifying the system. Returned by uname().
 * All fields are null-terminated strings.
 *
 * @sysname   Operating system name (e.g., "Futura", "Linux")
 * @nodename  Network hostname (can be changed with sethostname)
 * @release   Operating system release (e.g., "0.1.0")
 * @version   Operating system version/build info
 * @machine   Hardware architecture (e.g., "x86_64", "aarch64")
 *
 * Example output:
 *   sysname  = "Futura"
 *   nodename = "futura"
 *   release  = "0.1.0"
 *   version  = "#1 SMP Jan 21 2026 10:30:00"
 *   machine  = "x86_64"
 */
#ifndef _STRUCT_UTSNAME
#define _STRUCT_UTSNAME
struct utsname {
    char sysname[_UTSNAME_LENGTH];      /* Operating system name */
    char nodename[_UTSNAME_LENGTH];     /* Network node hostname */
    char release[_UTSNAME_LENGTH];      /* Operating system release */
    char version[_UTSNAME_LENGTH];      /* Operating system version */
    char machine[_UTSNAME_LENGTH];      /* Hardware identifier */
#ifdef _GNU_SOURCE
    char domainname[_UTSNAME_LENGTH];   /* NIS/YP domain name (GNU extension) */
#endif
};
#endif

/* ============================================================
 *   Function Declarations
 * ============================================================ */

/**
 * uname - Get system identification
 *
 * @buf  Pointer to utsname structure to fill
 *
 * Fills the structure pointed to by buf with system information.
 *
 * Returns 0 on success, -1 on error (with errno set).
 *
 * Errors:
 *   EFAULT  buf is not valid
 *
 * Usage:
 *   struct utsname info;
 *   if (uname(&info) == 0) {
 *       printf("System: %s %s %s\n",
 *              info.sysname, info.release, info.machine);
 *   }
 */
extern int uname(struct utsname *buf);

