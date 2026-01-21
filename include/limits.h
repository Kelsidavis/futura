// SPDX-License-Identifier: MPL-2.0
/*
 * limits.h - Implementation-defined limits
 *
 * Copyright (c) 2025 Kelsi Davis
 * Licensed under the MPL v2.0 — see LICENSE for details.
 *
 * Provides implementation-defined limits for numeric types,
 * pathname lengths, and other system parameters.
 */

#pragma once

/* ============================================================
 *   Numeric Limits
 * ============================================================ */

/* Signed char */
#ifndef SCHAR_MIN
#define SCHAR_MIN       (-128)
#endif
#ifndef SCHAR_MAX
#define SCHAR_MAX       127
#endif
#ifndef UCHAR_MAX
#define UCHAR_MAX       255
#endif

/* Char (implementation-defined signedness, assume signed) */
#ifndef CHAR_BIT
#define CHAR_BIT        8
#endif
#ifndef CHAR_MIN
#define CHAR_MIN        SCHAR_MIN
#endif
#ifndef CHAR_MAX
#define CHAR_MAX        SCHAR_MAX
#endif

/* Short */
#ifndef SHRT_MIN
#define SHRT_MIN        (-32768)
#endif
#ifndef SHRT_MAX
#define SHRT_MAX        32767
#endif
#ifndef USHRT_MAX
#define USHRT_MAX       65535
#endif

/* Int */
#ifndef INT_MIN
#define INT_MIN         (-2147483647 - 1)
#endif
#ifndef INT_MAX
#define INT_MAX         2147483647
#endif
#ifndef UINT_MAX
#define UINT_MAX        4294967295U
#endif

/* Long (64-bit on LP64 systems) */
#if defined(__LP64__) || defined(__x86_64__) || defined(__aarch64__)
#ifndef LONG_MIN
#define LONG_MIN        (-9223372036854775807L - 1)
#endif
#ifndef LONG_MAX
#define LONG_MAX        9223372036854775807L
#endif
#ifndef ULONG_MAX
#define ULONG_MAX       18446744073709551615UL
#endif
#else /* 32-bit */
#ifndef LONG_MIN
#define LONG_MIN        (-2147483647L - 1)
#endif
#ifndef LONG_MAX
#define LONG_MAX        2147483647L
#endif
#ifndef ULONG_MAX
#define ULONG_MAX       4294967295UL
#endif
#endif

/* Long long */
#ifndef LLONG_MIN
#define LLONG_MIN       (-9223372036854775807LL - 1)
#endif
#ifndef LLONG_MAX
#define LLONG_MAX       9223372036854775807LL
#endif
#ifndef ULLONG_MAX
#define ULLONG_MAX      18446744073709551615ULL
#endif

/* ============================================================
 *   POSIX Limits
 * ============================================================ */

/* Maximum number of bytes in a pathname */
#ifndef PATH_MAX
#define PATH_MAX        4096
#endif

/* Maximum number of bytes in a filename */
#ifndef NAME_MAX
#define NAME_MAX        255
#endif

/* Maximum number of simultaneous processes per user */
#ifndef CHILD_MAX
#define CHILD_MAX       1024
#endif

/* Maximum number of open files per process */
#ifndef OPEN_MAX
#define OPEN_MAX        1024
#endif

/* Maximum number of bytes for command-line arguments */
#ifndef ARG_MAX
#define ARG_MAX         131072  /* 128 KB */
#endif

/* Maximum length of an input line */
#ifndef LINE_MAX
#define LINE_MAX        2048
#endif

/* Maximum number of bytes in a pipe buffer */
#ifndef PIPE_BUF
#define PIPE_BUF        4096
#endif

/* Maximum number of iovec structures for readv/writev */
#ifndef IOV_MAX
#define IOV_MAX         1024
#endif

/* Maximum number of links to a file */
#ifndef LINK_MAX
#define LINK_MAX        65535
#endif

/* Maximum number of symlink traversals */
#ifndef SYMLOOP_MAX
#define SYMLOOP_MAX     40
#endif

/* Maximum length of terminal device name */
#ifndef TTY_NAME_MAX
#define TTY_NAME_MAX    32
#endif

/* Maximum length of a hostname */
#ifndef HOST_NAME_MAX
#define HOST_NAME_MAX   255
#endif

/* Maximum length of a login name */
#ifndef LOGIN_NAME_MAX
#define LOGIN_NAME_MAX  256
#endif

/* ============================================================
 *   Size Limits
 * ============================================================ */

/* Maximum value for size_t */
#ifndef SIZE_MAX
#if defined(__LP64__) || defined(__x86_64__) || defined(__aarch64__)
#define SIZE_MAX        18446744073709551615UL
#else
#define SIZE_MAX        4294967295UL
#endif
#endif

/* Maximum value for ssize_t */
#ifndef SSIZE_MAX
#if defined(__LP64__) || defined(__x86_64__) || defined(__aarch64__)
#define SSIZE_MAX       9223372036854775807L
#else
#define SSIZE_MAX       2147483647L
#endif
#endif

