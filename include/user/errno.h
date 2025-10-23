// SPDX-License-Identifier: MPL-2.0
// Minimal errno shim for Futura OS userland.

#pragma once

#include <kernel/errno.h>

/* Define a core subset of errno values if they have not been declared yet. */
#ifndef EPERM
#define EPERM   1
#define ENOENT  2
#define ESRCH   3
#define EINTR   4
#define EIO     5
#define ENXIO   6
#define E2BIG   7
#define ENOEXEC 8
#define EBADF   9
#define ECHILD  10
#define EAGAIN  11
#define ENOMEM  12
#define EACCES  13
#define EFAULT  14
#define EBUSY   16
#define EEXIST  17
#define EXDEV   18
#define ENODEV  19
#define ENOTDIR 20
#define EISDIR  21
#define EINVAL  22
#define ENFILE  23
#define EMFILE  24
#define ENOTTY  25
#define EFBIG   27
#define ENOSPC  28
#define ESPIPE  29
#define EROFS   30
#define EPIPE   32
#define ENAMETOOLONG 36
#define ERANGE  34
#define EOVERFLOW 75
#define EPROTO  71
#define EOPNOTSUPP 95
#define ENOTSUP EOPNOTSUPP  /* Alias for EOPNOTSUPP */
#endif

#ifdef __cplusplus
extern "C" {
#endif

int *__errno_location(void);

#ifndef errno
#define errno (*__errno_location())
#endif

#ifdef __cplusplus
}
#endif
