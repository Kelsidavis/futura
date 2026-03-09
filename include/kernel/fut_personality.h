/* include/kernel/fut_personality.h - Process execution domain constants
 *
 * Copyright (c) 2025 Kelsi Davis
 * Licensed under the MPL v2.0 — see LICENSE for details.
 *
 * Defines personality() syscall constants for execution domains and flags.
 */

#pragma once

/* Execution domain personalities (base, low 8 bits) */
#define PER_LINUX       0x0000UL  /* Linux personality (default) */
#define PER_SVR4        0x0001UL  /* SVR4 personality */
#define PER_BSD         0x0006UL  /* BSD personality */
#define PER_LINUX_32BIT 0x0008UL  /* 32-bit Linux */

/* Personality flags (upper bits) */
#define ADDR_NO_RANDOMIZE   0x0040000UL  /* Disable address space randomization */
#define ADDR_COMPAT_LAYOUT  0x0200000UL  /* Compatibility address layout */
#define READ_IMPLIES_EXEC   0x0400000UL  /* READ implies EXEC for mappings */
#define ADDR_LIMIT_32BIT    0x0800000UL  /* Limit address space to 32 bits */
#define SHORT_INODE         0x1000000UL  /* Use 16-bit inode numbers */
#define WHOLE_SECONDS       0x2000000UL  /* Timestamps in whole seconds */
#define STICKY_TIMEOUTS     0x4000000UL  /* Select/poll timeouts sticky */
#define ADDR_LIMIT_3GB      0x8000000UL  /* Limit address space to 3GB */

/* Magic value to query current personality without changing it */
#define PER_QUERY           0xFFFFFFFFUL
