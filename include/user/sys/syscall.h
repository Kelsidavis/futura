// SPDX-License-Identifier: MPL-2.0
// Minimal syscall numbers used by vendored libraries.

#pragma once

#ifndef SYS_getpid
#define SYS_getpid      39
#endif
#ifndef SYS_getppid
#define SYS_getppid     110
#endif
#ifndef SYS_getuid
#define SYS_getuid      102
#endif
#ifndef SYS_geteuid
#define SYS_geteuid     107
#endif
#ifndef SYS_getgid
#define SYS_getgid      104
#endif
#ifndef SYS_getegid
#define SYS_getegid     108
#endif
#ifndef SYS_gettid
#define SYS_gettid      186
#endif
#ifndef SYS_getrandom
#define SYS_getrandom   318
#endif
#ifndef SYS_pipe2
#define SYS_pipe2       293
#endif
#ifndef SYS_dup3
#define SYS_dup3        292
#endif
#ifndef SYS_close_range
#define SYS_close_range 436
#endif
#ifndef SYS_openat
#define SYS_openat      257
#endif
#ifndef AT_FDCWD
#define AT_FDCWD        -100
#endif
