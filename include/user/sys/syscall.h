// SPDX-License-Identifier: MPL-2.0
//
// Linux syscall numbers + raw syscall(2). Vendored third-party
// userland (libwayland, libffi, …) calls syscall(SYS_xxx, ...) directly
// when no glibc wrapper exists. We pick numbers that match Futura's
// kernel syscall_table at the corresponding arch's native indices,
// so userland doesn't need any compatibility aliasing in the kernel.

#pragma once

#ifdef __cplusplus
extern "C" {
#endif

long syscall(long number, ...);

#if defined(__aarch64__)

/* Linux ARM64 generic numbers (subset libwayland actually uses) */
#ifndef SYS_read
#define SYS_read            63
#endif
#ifndef SYS_write
#define SYS_write           64
#endif
#ifndef SYS_close
#define SYS_close           57
#endif
#ifndef SYS_mmap
#define SYS_mmap            222
#endif
#ifndef SYS_mprotect
#define SYS_mprotect        226
#endif
#ifndef SYS_munmap
#define SYS_munmap          215
#endif
#ifndef SYS_ioctl
#define SYS_ioctl           29
#endif
#ifndef SYS_madvise
#define SYS_madvise         233
#endif
#ifndef SYS_eventfd2
#define SYS_eventfd2        19
#endif
#ifndef SYS_signalfd4
#define SYS_signalfd4       74
#endif
#ifndef SYS_timerfd_create
#define SYS_timerfd_create  85
#endif
#ifndef SYS_timerfd_settime
#define SYS_timerfd_settime 86
#endif
#ifndef SYS_epoll_create1
#define SYS_epoll_create1   20
#endif
#ifndef SYS_epoll_ctl
#define SYS_epoll_ctl       21
#endif
#ifndef SYS_epoll_pwait
#define SYS_epoll_pwait     22
#endif
#ifndef SYS_memfd_create
#define SYS_memfd_create    279
#endif
#ifndef SYS_getpid
#define SYS_getpid          172
#endif
#ifndef SYS_getppid
#define SYS_getppid         173
#endif
#ifndef SYS_getuid
#define SYS_getuid          174
#endif
#ifndef SYS_geteuid
#define SYS_geteuid         175
#endif
#ifndef SYS_getgid
#define SYS_getgid          176
#endif
#ifndef SYS_getegid
#define SYS_getegid         177
#endif
#ifndef SYS_gettid
#define SYS_gettid          178
#endif
#ifndef SYS_getrandom
#define SYS_getrandom       278
#endif
#ifndef SYS_pipe2
#define SYS_pipe2           59
#endif
#ifndef SYS_dup3
#define SYS_dup3            24
#endif
#ifndef SYS_close_range
#define SYS_close_range     436
#endif
#ifndef SYS_openat
#define SYS_openat          56
#endif

/* Deprecated x86_64-style entries kept for source compatibility. The
 * kernel does not register handlers at these sentinel numbers; if any
 * vendored code actually invokes them, fix the call site to use the
 * modern variant. */
#ifndef SYS_open
#define SYS_open            1024
#endif
#ifndef SYS_eventfd
#define SYS_eventfd         1047
#endif
#ifndef SYS_signalfd
#define SYS_signalfd        1049
#endif
#ifndef SYS_epoll_create
#define SYS_epoll_create    1048
#endif
#ifndef SYS_epoll_wait
#define SYS_epoll_wait      22  /* aliased to epoll_pwait — passing NULL sigmask is a no-op */
#endif

#else /* x86_64 */

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

#endif /* arch */

#ifndef AT_FDCWD
#define AT_FDCWD        -100
#endif

/* Capability-based syscalls (Phase 1 - Futura extensions, arch-agnostic) */
#ifndef SYS_open_cap
#define SYS_open_cap    500
#endif
#ifndef SYS_read_cap
#define SYS_read_cap    501
#endif
#ifndef SYS_write_cap
#define SYS_write_cap   502
#endif
#ifndef SYS_close_cap
#define SYS_close_cap   503
#endif
#ifndef SYS_lseek_cap
#define SYS_lseek_cap   504
#endif
#ifndef SYS_fstat_cap
#define SYS_fstat_cap   505
#endif
#ifndef SYS_fsync_cap
#define SYS_fsync_cap   506
#endif
#ifndef SYS_mkdirat_cap
#define SYS_mkdirat_cap 507
#endif
#ifndef SYS_unlinkat_cap
#define SYS_unlinkat_cap 508
#endif
#ifndef SYS_rmdirat_cap
#define SYS_rmdirat_cap 509
#endif
#ifndef SYS_statat_cap
#define SYS_statat_cap  510
#endif

#ifdef __cplusplus
}
#endif
