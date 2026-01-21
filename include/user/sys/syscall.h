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

/* Capability-based syscalls (Phase 1 - Futura extensions) */
#ifndef SYS_open_cap
#define SYS_open_cap    500  /* Open file with capability handle return */
#endif
#ifndef SYS_read_cap
#define SYS_read_cap    501  /* Read from capability handle */
#endif
#ifndef SYS_write_cap
#define SYS_write_cap   502  /* Write to capability handle */
#endif
#ifndef SYS_close_cap
#define SYS_close_cap   503  /* Close capability handle */
#endif
#ifndef SYS_lseek_cap
#define SYS_lseek_cap   504  /* Seek within capability handle */
#endif
#ifndef SYS_fstat_cap
#define SYS_fstat_cap   505  /* Get file stats from capability handle */
#endif
#ifndef SYS_fsync_cap
#define SYS_fsync_cap   506  /* Sync file data from capability handle */
#endif
#ifndef SYS_mkdirat_cap
#define SYS_mkdirat_cap 507  /* Create directory relative to parent handle */
#endif
#ifndef SYS_unlinkat_cap
#define SYS_unlinkat_cap 508 /* Unlink file relative to parent handle */
#endif
#ifndef SYS_rmdirat_cap
#define SYS_rmdirat_cap 509  /* Remove directory relative to parent handle */
#endif
#ifndef SYS_statat_cap
#define SYS_statat_cap  510  /* Get file stats relative to parent handle */
#endif
