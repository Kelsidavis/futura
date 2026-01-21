/* include/kernel/errno.h - Kernel error code definitions
 *
 * Copyright (c) 2025 Kelsi Davis
 * Licensed under the MPL v2.0 — see LICENSE for details.
 *
 * Centralizes errno-style constants used across the kernel. Values mirror
 * traditional POSIX assignments so subsystems (VFS, IPC, drivers) can agree
 * on return values. Each definition is guarded to avoid conflicts with legacy
 * headers that provide the same constants.
 *
 * Error codes follow the Linux/POSIX convention where syscalls return negative
 * error numbers (e.g., -EINVAL, -ENOENT) and userspace sees positive errno values.
 */

#pragma once

#ifndef EPERM
#define EPERM       1
#endif

#ifndef ENOENT
#define ENOENT      2
#endif

#ifndef ESRCH
#define ESRCH       3
#endif

#ifndef EINTR
#define EINTR       4
#endif

#ifndef EIO
#define EIO         5
#endif

#ifndef ENXIO
#define ENXIO       6
#endif

#ifndef E2BIG
#define E2BIG       7
#endif

#ifndef EBADF
#define EBADF       9
#endif

#ifndef ENOMEM
#define ENOMEM      12
#endif

#ifndef EACCES
#define EACCES      13
#endif

#ifndef EFAULT
#define EFAULT      14
#endif

#ifndef EAGAIN
#define EAGAIN      11
#endif

#ifndef ECHILD
#define ECHILD      10
#endif

#ifndef EBUSY
#define EBUSY       16
#endif

#ifndef EEXIST
#define EEXIST      17
#endif

#ifndef ENODEV
#define ENODEV      19
#endif

#ifndef ENOTDIR
#define ENOTDIR     20
#endif

#ifndef EISDIR
#define EISDIR      21
#endif

#ifndef EXDEV
#define EXDEV       18
#endif

#ifndef EINVAL
#define EINVAL      22
#endif

#ifndef ENFILE
#define ENFILE      23
#endif

#ifndef EMFILE
#define EMFILE      24
#endif

#ifndef ENOTTY
#define ENOTTY      25
#endif

#ifndef ENOSPC
#define ENOSPC      28
#endif

#ifndef EPIPE
#define EPIPE       32
#endif

#ifndef ERANGE
#define ERANGE      34
#endif

#ifndef ENAMETOOLONG
#define ENAMETOOLONG 36
#endif

#ifndef ESPIPE
#define ESPIPE      29
#endif

#ifndef EROFS
#define EROFS       30
#endif

#ifndef EMLINK
#define EMLINK      31
#endif

#ifndef ENOSYS
#define ENOSYS      38
#endif

#ifndef ENOTEMPTY
#define ENOTEMPTY   39
#endif

#ifndef ELOOP
#define ELOOP       40
#endif

#ifndef EOVERFLOW
#define EOVERFLOW   75
#endif

#ifndef EPROTO
#define EPROTO      71
#endif

#ifndef EMSGSIZE
#define EMSGSIZE    90
#endif

#ifndef ENOPROTOOPT
#define ENOPROTOOPT 92
#endif

#ifndef ENOTSUP
#define ENOTSUP     95
#endif

#ifndef EISCONN
#define EISCONN     106
#endif

#ifndef ENOTCONN
#define ENOTCONN    107
#endif

#ifndef ETIMEDOUT
#define ETIMEDOUT   110
#endif

#ifndef EHOSTUNREACH
#define EHOSTUNREACH 113
#endif

#ifndef phys_addr_t
#include <stdint.h>
typedef uint64_t phys_addr_t;
#endif
