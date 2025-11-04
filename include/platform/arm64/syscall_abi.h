// SPDX-License-Identifier: MPL-2.0
/*
 * syscall_abi.h - ARM64 syscall ABI helpers
 *
 * Copyright (c) 2025 Kelsi Davis
 * Licensed under the MPL v2.0 — see LICENSE for details.
 *
 * ARM64 syscall calling convention (Linux compatible):
 * - Syscall number in X8
 * - Arguments in X0-X6
 * - Return value in X0
 * - Instruction: SVC #0
 */

#pragma once

#include <stdint.h>

/* ============================================================
 *   ARM64 Syscall Invocation
 * ============================================================ */

/**
 * Invoke a syscall with 0-6 arguments.
 * Uses Linux ARM64 syscall convention: syscall number in X8, args in X0-X6.
 */

static inline long syscall_arm64_0(long n) {
    register long x8 __asm__("x8") = n;
    register long x0 __asm__("x0");
    __asm__ volatile("svc #0" : "=r"(x0) : "r"(x8) : "memory");
    return x0;
}

static inline long syscall_arm64_1(long n, long a1) {
    register long x8 __asm__("x8") = n;
    register long x0 __asm__("x0") = a1;
    __asm__ volatile("svc #0" : "+r"(x0) : "r"(x8) : "memory");
    return x0;
}

static inline long syscall_arm64_2(long n, long a1, long a2) {
    register long x8 __asm__("x8") = n;
    register long x0 __asm__("x0") = a1;
    register long x1 __asm__("x1") = a2;
    __asm__ volatile("svc #0" : "+r"(x0) : "r"(x8), "r"(x1) : "memory");
    return x0;
}

static inline long syscall_arm64_3(long n, long a1, long a2, long a3) {
    register long x8 __asm__("x8") = n;
    register long x0 __asm__("x0") = a1;
    register long x1 __asm__("x1") = a2;
    register long x2 __asm__("x2") = a3;
    __asm__ volatile("svc #0" : "+r"(x0) : "r"(x8), "r"(x1), "r"(x2) : "memory");
    return x0;
}

static inline long syscall_arm64_4(long n, long a1, long a2, long a3, long a4) {
    register long x8 __asm__("x8") = n;
    register long x0 __asm__("x0") = a1;
    register long x1 __asm__("x1") = a2;
    register long x2 __asm__("x2") = a3;
    register long x3 __asm__("x3") = a4;
    __asm__ volatile("svc #0" : "+r"(x0) : "r"(x8), "r"(x1), "r"(x2), "r"(x3) : "memory");
    return x0;
}

static inline long syscall_arm64_5(long n, long a1, long a2, long a3, long a4, long a5) {
    register long x8 __asm__("x8") = n;
    register long x0 __asm__("x0") = a1;
    register long x1 __asm__("x1") = a2;
    register long x2 __asm__("x2") = a3;
    register long x3 __asm__("x3") = a4;
    register long x4 __asm__("x4") = a5;
    __asm__ volatile("svc #0" : "+r"(x0) : "r"(x8), "r"(x1), "r"(x2), "r"(x3), "r"(x4) : "memory");
    return x0;
}

static inline long syscall_arm64_6(long n, long a1, long a2, long a3, long a4, long a5, long a6) {
    register long x8 __asm__("x8") = n;
    register long x0 __asm__("x0") = a1;
    register long x1 __asm__("x1") = a2;
    register long x2 __asm__("x2") = a3;
    register long x3 __asm__("x3") = a4;
    register long x4 __asm__("x4") = a5;
    register long x5 __asm__("x5") = a6;
    __asm__ volatile("svc #0" : "+r"(x0) : "r"(x8), "r"(x1), "r"(x2), "r"(x3), "r"(x4), "r"(x5) : "memory");
    return x0;
}

/* ============================================================
 *   Architecture-Agnostic Syscall Macros
 * ============================================================ */

#define __SYSCALL_0(n)                 syscall_arm64_0(n)
#define __SYSCALL_1(n, a1)             syscall_arm64_1(n, (long)(a1))
#define __SYSCALL_2(n, a1, a2)         syscall_arm64_2(n, (long)(a1), (long)(a2))
#define __SYSCALL_3(n, a1, a2, a3)     syscall_arm64_3(n, (long)(a1), (long)(a2), (long)(a3))
#define __SYSCALL_4(n, a1, a2, a3, a4) syscall_arm64_4(n, (long)(a1), (long)(a2), (long)(a3), (long)(a4))
#define __SYSCALL_5(n, a1, a2, a3, a4, a5) \
    syscall_arm64_5(n, (long)(a1), (long)(a2), (long)(a3), (long)(a4), (long)(a5))
#define __SYSCALL_6(n, a1, a2, a3, a4, a5, a6) \
    syscall_arm64_6(n, (long)(a1), (long)(a2), (long)(a3), (long)(a4), (long)(a5), (long)(a6))
