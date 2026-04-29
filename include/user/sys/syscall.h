// SPDX-License-Identifier: MPL-2.0
//
// Linux syscall numbers + raw syscall(2) — vendored third-party
// userland (libwayland, etc.) sometimes calls syscall(SYS_xxx, ...)
// directly when no glibc wrapper exists. Match Linux x86_64
// numbering (which Futura's syscall_table mirrors) so the source
// compiles untouched; libfutura provides the syscall() trampoline.

#pragma once

#ifdef __cplusplus
extern "C" {
#endif

long syscall(long number, ...);

#ifndef SYS_read
#define SYS_read         0
#endif
#ifndef SYS_write
#define SYS_write        1
#endif
#ifndef SYS_open
#define SYS_open         2
#endif
#ifndef SYS_close
#define SYS_close        3
#endif
#ifndef SYS_mmap
#define SYS_mmap         9
#endif
#ifndef SYS_mprotect
#define SYS_mprotect    10
#endif
#ifndef SYS_munmap
#define SYS_munmap      11
#endif
#ifndef SYS_ioctl
#define SYS_ioctl       16
#endif
#ifndef SYS_madvise
#define SYS_madvise     28
#endif
#ifndef SYS_eventfd
#define SYS_eventfd     284
#endif
#ifndef SYS_eventfd2
#define SYS_eventfd2    290
#endif
#ifndef SYS_signalfd
#define SYS_signalfd    282
#endif
#ifndef SYS_signalfd4
#define SYS_signalfd4   289
#endif
#ifndef SYS_timerfd_create
#define SYS_timerfd_create  283
#endif
#ifndef SYS_timerfd_settime
#define SYS_timerfd_settime 286
#endif
#ifndef SYS_epoll_create
#define SYS_epoll_create  213
#endif
#ifndef SYS_epoll_create1
#define SYS_epoll_create1 291
#endif
#ifndef SYS_epoll_ctl
#define SYS_epoll_ctl   233
#endif
#ifndef SYS_epoll_wait
#define SYS_epoll_wait  232
#endif
#ifndef SYS_memfd_create
#define SYS_memfd_create 319
#endif

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

#ifdef __cplusplus
}
#endif
