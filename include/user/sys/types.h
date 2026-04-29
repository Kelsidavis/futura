// SPDX-License-Identifier: MPL-2.0
//
// POSIX sys/types.h shim for Futura userland.  Maps the standard C
// type aliases that third-party userland (libffi, libwayland, …)
// expects onto fixed-width types.  Same layout the kernel uses, so
// values cross the syscall boundary unchanged.

#pragma once

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef long             ssize_t;
typedef long             off_t;
typedef int64_t          off64_t;
typedef int64_t          loff_t;

typedef int              pid_t;
typedef int              tid_t;
typedef unsigned int     uid_t;
typedef unsigned int     gid_t;
typedef unsigned int     mode_t;
typedef unsigned int     dev_t;
typedef unsigned long    ino_t;
typedef unsigned long    nlink_t;
typedef long             blksize_t;
typedef long             blkcnt_t;

typedef long             time_t;
typedef long             clock_t;
typedef long             suseconds_t;
typedef unsigned long    useconds_t;

typedef int              key_t;
typedef int              clockid_t;
typedef void *           timer_t;

typedef unsigned long    pthread_t;
typedef unsigned long    pthread_key_t;
typedef int              pthread_once_t;

typedef unsigned int     id_t;
typedef long             intptr_t_compat;

#ifdef __cplusplus
}
#endif
