/* kernel/sys_futimesat.c - Deprecated file timestamp update syscall
 *
 * Copyright (c) 2025 Kelsi Davis
 * Licensed under the MPL v2.0 — see LICENSE for details.
 *
 * Implements futimesat() for changing file timestamps relative to a
 * directory FD. This is the deprecated precursor to utimensat() —
 * uses microsecond-precision struct timeval instead of nanosecond timespec.
 *
 * Linux syscall number: 261 (x86_64), not present on ARM64 (use utimensat)
 */

#include <kernel/fut_task.h>
#include <kernel/errno.h>
#include <kernel/uaccess.h>
#include <shared/fut_timespec.h>
#include <stdint.h>

#ifdef __x86_64__
#include <platform/x86_64/memory/paging.h>
#elif defined(__aarch64__)
#include <platform/arm64/memory/paging.h>
#endif

/* Kernel-pointer bypass helper */
static inline int futimesat_copy_from_user(void *dst, const void *src, size_t n) {
#ifdef KERNEL_VIRTUAL_BASE
    if ((uintptr_t)src >= KERNEL_VIRTUAL_BASE) { __builtin_memcpy(dst, src, n); return 0; }
#endif
    return fut_copy_from_user(dst, src, n);
}

/* struct timeval for futimesat */
struct fut_timeval {
    int64_t tv_sec;
    int64_t tv_usec;
};

/* Forward declaration */
extern long sys_utimensat(int dirfd, const char *pathname,
                          const fut_timespec_t *times, int flags);

/**
 * futimesat() - Change file timestamps (deprecated, microsecond precision)
 *
 * @param dirfd    Directory FD or AT_FDCWD
 * @param pathname Path relative to dirfd
 * @param times    Array of 2 timeval structs [atime, mtime], or NULL for now
 *
 * Returns 0 on success, negative errno on failure.
 *
 * When times is NULL, both timestamps are set to the current time.
 * Otherwise, times[0] is the new access time and times[1] is the new
 * modification time (in seconds + microseconds).
 */
long sys_futimesat(int dirfd, const char *pathname, const struct fut_timeval *times) {
    if (!times) {
        /* NULL times = set both to current time */
        return sys_utimensat(dirfd, pathname, NULL, 0);
    }

    /* Copy timeval pair from user */
    struct fut_timeval tv[2];
    if (futimesat_copy_from_user(tv, times, sizeof(tv)) != 0)
        return -EFAULT;

    /* Validate microseconds range */
    if (tv[0].tv_usec < 0 || tv[0].tv_usec >= 1000000 ||
        tv[1].tv_usec < 0 || tv[1].tv_usec >= 1000000)
        return -EINVAL;

    /* Convert timeval (usec) to timespec (nsec) */
    fut_timespec_t ts[2];
    ts[0].tv_sec = tv[0].tv_sec;
    ts[0].tv_nsec = tv[0].tv_usec * 1000;  /* usec → nsec */
    ts[1].tv_sec = tv[1].tv_sec;
    ts[1].tv_nsec = tv[1].tv_usec * 1000;

    return sys_utimensat(dirfd, pathname, ts, 0);
}

/**
 * utimes() - Change file timestamps (microsecond precision, path-based)
 *
 * @param pathname Path to the file
 * @param times    Array of 2 timeval structs [atime, mtime], or NULL for now
 *
 * Returns 0 on success, negative errno on failure.
 * Equivalent to futimesat(AT_FDCWD, pathname, times).
 */
long sys_utimes(const char *pathname, const struct fut_timeval *times) {
    return sys_futimesat(-100 /* AT_FDCWD */, pathname, times);
}

/**
 * utime() - Change file timestamps (second precision, legacy)
 *
 * @param pathname  Path to the file
 * @param times     struct utimbuf pointer, or NULL for current time
 *
 * struct utimbuf { time_t actime; time_t modtime; }
 * Returns 0 on success, negative errno on failure.
 */
struct fut_utimbuf {
    int64_t actime;   /* access time (seconds) */
    int64_t modtime;  /* modification time (seconds) */
};

long sys_utime(const char *pathname, const struct fut_utimbuf *times) {
    if (!times)
        return sys_utimensat(-100 /* AT_FDCWD */, pathname, NULL, 0);

    struct fut_utimbuf ub;
    if (futimesat_copy_from_user(&ub, times, sizeof(ub)) != 0)
        return -EFAULT;

    fut_timespec_t ts[2];
    ts[0].tv_sec  = ub.actime;
    ts[0].tv_nsec = 0;
    ts[1].tv_sec  = ub.modtime;
    ts[1].tv_nsec = 0;
    return sys_utimensat(-100 /* AT_FDCWD */, pathname, ts, 0);
}
