/* syscall_portable.h - Platform-agnostic syscall wrappers
 *
 * Copyright (c) 2025 Kelsi Davis
 * Licensed under the MPL v2.0 — see LICENSE for details.
 *
 * Provides portable syscall macros and functions that work on both x86-64 and ARM64.
 * Each platform uses its native calling convention and instruction.
 */

#ifndef _SYSCALL_PORTABLE_H
#define _SYSCALL_PORTABLE_H

#include <stdint.h>
#include <stddef.h>

#ifndef __ssize_t_defined
#define __ssize_t_defined 1
typedef long ssize_t;
#endif

/* Platform detection */
#if defined(__x86_64__) || defined(__amd64__)
    #define PLATFORM_X86_64 1
#elif defined(__aarch64__)
    #define PLATFORM_ARM64 1
#else
    #error "Unsupported platform for syscall_portable"
#endif

/* ============================================================
 *   x86-64 Platform (int $0x80)
 * ============================================================ */

#ifdef PLATFORM_X86_64

/* Note: r8 added to clobber list - kernel syscall handler corrupts it */
static inline long syscall0(long nr) {
    long ret;
    __asm__ __volatile__(
        "int $0x80"
        : "=a"(ret)
        : "a"(nr)
        : "rcx", "r8", "r11", "memory"
    );
    return ret;
}

static inline long syscall1(long nr, long arg1) {
    long ret;
    __asm__ __volatile__(
        "int $0x80\n"
        : "=a"(ret)
        : "a"(nr), "D"(arg1)
        : "rcx", "r8", "r11", "memory"
    );
    return ret;
}

static inline long syscall2(long nr, long arg1, long arg2) {
    long ret;
    __asm__ __volatile__(
        "int $0x80\n"
        : "=a"(ret)
        : "a"(nr), "D"(arg1), "S"(arg2)
        : "rcx", "r8", "r11", "memory"
    );
    return ret;
}

static inline long syscall3(long nr, long arg1, long arg2, long arg3) {
    long ret;
    __asm__ __volatile__(
        "int $0x80\n"
        : "=a"(ret)
        : "a"(nr), "D"(arg1), "S"(arg2), "d"(arg3)
        : "rcx", "r8", "r11", "memory"
    );
    return ret;
}

static inline long syscall4(long nr, long arg1, long arg2, long arg3, long arg4) {
    long ret;
    register long r10 __asm__("r10") = arg4;
    __asm__ __volatile__(
        "int $0x80\n"
        : "=a"(ret)
        : "a"(nr), "D"(arg1), "S"(arg2), "d"(arg3), "r"(r10)
        : "rcx", "r8", "r11", "memory"
    );
    return ret;
}

static inline long syscall5(long nr, long arg1, long arg2, long arg3, long arg4, long arg5) {
    long ret;
    register long r10 __asm__("r10") = arg4;
    register long r8  __asm__("r8")  = arg5;
    __asm__ __volatile__(
        "int $0x80\n"
        : "=a"(ret)
        : "a"(nr), "D"(arg1), "S"(arg2), "d"(arg3), "r"(r10), "r"(r8)
        : "rcx", "r11", "memory"
    );
    return ret;
}

static inline long syscall6(long nr, long arg1, long arg2, long arg3, long arg4, long arg5, long arg6) {
    long ret;
    register long r10 __asm__("r10") = arg4;
    register long r8  __asm__("r8")  = arg5;
    register long r9  __asm__("r9")  = arg6;
    __asm__ __volatile__(
        "int $0x80\n"
        : "=a"(ret)
        : "a"(nr), "D"(arg1), "S"(arg2), "d"(arg3), "r"(r10), "r"(r8), "r"(r9)
        : "rcx", "r11", "memory"
    );
    return ret;
}

#endif /* PLATFORM_X86_64 */

/* ============================================================
 *   ARM64 Platform (SVC #0)
 * ============================================================ */

/* ARM64 syscall ABI: x8 = syscall number, x0-x5 = args, x0 = return value.
 * The kernel clears x8 on return (security: prevent syscall number leak).
 * All wrappers must declare x8 as an output so GCC knows it's clobbered
 * and reloads it for each SVC — otherwise consecutive inlined syscalls
 * with the same number get mis-dispatched (e.g., write → read). */
#ifdef PLATFORM_ARM64

static inline long syscall0(long nr) {
    register long x0 __asm__("x0");
    register long x8 __asm__("x8") = nr;
    __asm__ __volatile__(
        "svc #0"
        : "=r"(x0), "+r"(x8)
        :
        : "memory"
    );
    return x0;
}

static inline long syscall1(long nr, long arg1) {
    register long x0 __asm__("x0") = arg1;
    register long x8 __asm__("x8") = nr;
    __asm__ __volatile__(
        "svc #0\n"
        : "+r"(x0), "+r"(x8)
        :
        : "memory"
    );
    return x0;
}

static inline long syscall2(long nr, long arg1, long arg2) {
    register long x0 __asm__("x0") = arg1;
    register long x1 __asm__("x1") = arg2;
    register long x8 __asm__("x8") = nr;
    __asm__ __volatile__(
        "svc #0\n"
        : "+r"(x0), "+r"(x8)
        : "r"(x1)
        : "memory"
    );
    return x0;
}

static inline long syscall3(long nr, long arg1, long arg2, long arg3) {
    register long x0 __asm__("x0") = arg1;
    register long x1 __asm__("x1") = arg2;
    register long x2 __asm__("x2") = arg3;
    register long x8 __asm__("x8") = nr;
    __asm__ __volatile__(
        "svc #0\n"
        : "+r"(x0), "+r"(x8)
        : "r"(x1), "r"(x2)
        : "memory"
    );
    return x0;
}

static inline long syscall4(long nr, long arg1, long arg2, long arg3, long arg4) {
    register long x0 __asm__("x0") = arg1;
    register long x1 __asm__("x1") = arg2;
    register long x2 __asm__("x2") = arg3;
    register long x3 __asm__("x3") = arg4;
    register long x8 __asm__("x8") = nr;
    __asm__ __volatile__(
        "svc #0\n"
        : "+r"(x0), "+r"(x8)
        : "r"(x1), "r"(x2), "r"(x3)
        : "memory"
    );
    return x0;
}

static inline long syscall5(long nr, long arg1, long arg2, long arg3, long arg4, long arg5) {
    register long x0 __asm__("x0") = arg1;
    register long x1 __asm__("x1") = arg2;
    register long x2 __asm__("x2") = arg3;
    register long x3 __asm__("x3") = arg4;
    register long x4 __asm__("x4") = arg5;
    register long x8 __asm__("x8") = nr;
    __asm__ __volatile__(
        "svc #0\n"
        : "+r"(x0), "+r"(x8)
        : "r"(x1), "r"(x2), "r"(x3), "r"(x4)
        : "memory"
    );
    return x0;
}

static inline long syscall6(long nr, long arg1, long arg2, long arg3, long arg4, long arg5, long arg6) {
    register long x0 __asm__("x0") = arg1;
    register long x1 __asm__("x1") = arg2;
    register long x2 __asm__("x2") = arg3;
    register long x3 __asm__("x3") = arg4;
    register long x4 __asm__("x4") = arg5;
    register long x5 __asm__("x5") = arg6;
    register long x8 __asm__("x8") = nr;
    __asm__ __volatile__(
        "svc #0\n"
        : "+r"(x0), "+r"(x8)
        : "r"(x1), "r"(x2), "r"(x3), "r"(x4), "r"(x5)
        : "memory"
    );
    return x0;
}

#endif /* PLATFORM_ARM64 */

/* ============================================================
 *   Common Syscall Definitions
 * ============================================================ */

/* Syscall numbers — arch-conditional. ARM64 uses Linux generic
 * numbering, x86_64 uses historical x86_64 numbering. */
#if defined(__aarch64__)
#define __NR_read           63
#define __NR_write          64
#define __NR_close          57
#define __NR_socket         198
#define __NR_connect        203
#define __NR_bind           200
#define __NR_listen         201
#define __NR_exit           93
#define __NR_fcntl          25
#define __NR_chmod          1042  /* deprecated; prefer fchmodat */
#define __NR_fchmod         52
#define __NR_unlink         1035  /* deprecated; prefer unlinkat */
#define __NR_open           1024  /* deprecated; prefer openat */
#define __NR_openat         56
#define __NR_mkdirat        34
#define __NR_unlinkat       35
#define __NR_fchmodat       53
#define __NR_epoll_ctl      21
#else
#define __NR_read           0
#define __NR_write          1
#define __NR_open           2
#define __NR_close          3
#define __NR_socket         41
#define __NR_connect        53   /* Futura uses 53 (42 is echo in Futura) */
#define __NR_bind           49
#define __NR_listen         50
#define __NR_exit           60
#define __NR_fcntl          72
#define __NR_unlink         87
#define __NR_chmod          90
#define __NR_fchmod         91
#define __NR_openat         257
#define __NR_mkdirat        258
#define __NR_unlinkat       263
#define __NR_fchmodat       268
#define __NR_epoll_ctl      229
#endif

/* Common file flags - only define if not already defined by system headers */
#ifndef O_RDONLY
#define O_RDONLY            0
#define O_WRONLY            1
#define O_RDWR              2
#define O_CREAT             (1 << 6)    /* 0100 */
#define O_TRUNC             (1 << 9)    /* 01000 */
#define O_APPEND            (1 << 10)   /* 02000 */
#define O_TMPFILE           (020000000 | 0200000)  /* Create unnamed temporary file */
#endif

#endif /* _SYSCALL_PORTABLE_H */
