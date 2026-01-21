// SPDX-License-Identifier: MPL-2.0
/*
 * sys/uio.h - Vectored I/O operations
 *
 * Copyright (c) 2025 Kelsi Davis
 * Licensed under the MPL v2.0 — see LICENSE for details.
 *
 * Provides the iovec structure and related constants for scatter-gather
 * I/O operations (readv, writev, preadv, pwritev).
 */

#pragma once

#include <stddef.h>
#include <stdint.h>

/* ============================================================
 *   Data Structures
 * ============================================================ */

/* I/O vector structure for scatter-gather operations */
#ifndef _STRUCT_IOVEC
#define _STRUCT_IOVEC
struct iovec {
    void   *iov_base;   /* Starting address of buffer */
    size_t  iov_len;    /* Size of buffer in bytes */
};
#endif

/* ============================================================
 *   Constants
 * ============================================================ */

/* Maximum number of iovec structures per call */
#ifndef UIO_MAXIOV
#define UIO_MAXIOV      1024
#endif

/* Alternative name used by some systems */
#ifndef IOV_MAX
#define IOV_MAX         UIO_MAXIOV
#endif

/* ============================================================
 *   ssize_t type (for return values)
 * ============================================================ */

#ifndef ssize_t
#if defined(__LP64__) || defined(__x86_64__) || defined(__aarch64__)
typedef int64_t ssize_t;
#else
typedef int32_t ssize_t;
#endif
#endif

/* ============================================================
 *   Function Declarations
 * ============================================================ */

/* Vectored read operations */
extern ssize_t readv(int fd, const struct iovec *iov, int iovcnt);
extern ssize_t preadv(int fd, const struct iovec *iov, int iovcnt, long offset);
extern ssize_t preadv2(int fd, const struct iovec *iov, int iovcnt,
                       long offset, int flags);

/* Vectored write operations */
extern ssize_t writev(int fd, const struct iovec *iov, int iovcnt);
extern ssize_t pwritev(int fd, const struct iovec *iov, int iovcnt, long offset);
extern ssize_t pwritev2(int fd, const struct iovec *iov, int iovcnt,
                        long offset, int flags);

/* Process memory operations (requires appropriate privileges) */
extern ssize_t process_vm_readv(int pid,
                                const struct iovec *local_iov, unsigned long liovcnt,
                                const struct iovec *remote_iov, unsigned long riovcnt,
                                unsigned long flags);
extern ssize_t process_vm_writev(int pid,
                                 const struct iovec *local_iov, unsigned long liovcnt,
                                 const struct iovec *remote_iov, unsigned long riovcnt,
                                 unsigned long flags);

/* ============================================================
 *   Flags for preadv2/pwritev2
 * ============================================================ */

#ifndef RWF_HIPRI
#define RWF_HIPRI       0x00000001  /* High priority request */
#endif
#ifndef RWF_DSYNC
#define RWF_DSYNC       0x00000002  /* Synchronized I/O data integrity completion */
#endif
#ifndef RWF_SYNC
#define RWF_SYNC        0x00000004  /* Synchronized I/O file integrity completion */
#endif
#ifndef RWF_NOWAIT
#define RWF_NOWAIT      0x00000008  /* Nonblocking I/O */
#endif
#ifndef RWF_APPEND
#define RWF_APPEND      0x00000010  /* Append to file */
#endif

