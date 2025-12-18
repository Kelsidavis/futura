// SPDX-License-Identifier: MPL-2.0
/*
 * syscall_abi.h - x86_64 syscall trap ABI helpers
 *
 * Copyright (c) 2025 Kelsi Davis
 * Licensed under the MPL v2.0 — see LICENSE for details.
 *
 * x86_64 syscall calling convention:
 * - Syscall number in RAX
 * - Arguments in RDI, RSI, RDX, R10, R8, R9
 * - Return value in RAX
 * - Instruction: int $0x80 (POSIX compatibility mode)
 */

#pragma once

#include <stdint.h>

#define SYSCALL_INT_VECTOR 0x80u

typedef struct regs64 {
    uint64_t r15, r14, r13, r12, r11, r10, r9, r8;
    uint64_t rdi, rsi, rbp, rdx, rcx, rbx, rax;
    uint64_t rip, cs, rflags, rsp, ss;
} regs64_t;

/* ============================================================
 *   x86_64 Syscall Invocation (int $0x80)
 * ============================================================ */

static inline long syscall_x86_64_0(long n) {
    long ret;
    /* r8 added to clobber list due to kernel syscall handler corruption */
    __asm__ volatile("int $0x80"
                     : "=a"(ret)
                     : "0"(n)
                     : "memory", "rcx", "r8", "r11");
    return ret;
}

static inline long syscall_x86_64_1(long n, long a1) {
    long ret;
    /* r8 added to clobber list due to kernel syscall handler corruption */
    __asm__ volatile("int $0x80"
                     : "=a"(ret)
                     : "0"(n), "D"(a1)
                     : "memory", "rcx", "r8", "r11");
    return ret;
}

static inline long syscall_x86_64_2(long n, long a1, long a2) {
    long ret;
    /* r8 added to clobber list due to kernel syscall handler corruption */
    __asm__ volatile("int $0x80"
                     : "=a"(ret)
                     : "0"(n), "D"(a1), "S"(a2)
                     : "memory", "rcx", "r8", "r11");
    return ret;
}

static inline long syscall_x86_64_3(long n, long a1, long a2, long a3) {
    long ret;
    /* r8 added to clobber list due to kernel syscall handler corruption */
    __asm__ volatile("int $0x80"
                     : "=a"(ret)
                     : "0"(n), "D"(a1), "S"(a2), "d"(a3)
                     : "memory", "rcx", "r8", "r11");
    return ret;
}

static inline long syscall_x86_64_4(long n, long a1, long a2, long a3, long a4) {
    long ret;
    __asm__ volatile(
        "mov %[arg4], %%r10\n\t"
        "int $0x80"
        : "=a"(ret)
        : "0"(n), "D"(a1), "S"(a2), "d"(a3), [arg4] "r"(a4)
        : "memory", "rcx", "r10", "r11");
    return ret;
}

static inline long syscall_x86_64_5(long n, long a1, long a2, long a3, long a4, long a5) {
    long ret;
    __asm__ volatile(
        "mov %[arg4], %%r10\n\t"
        "mov %[arg5], %%r8\n\t"
        "int $0x80"
        : "=a"(ret)
        : "0"(n), "D"(a1), "S"(a2), "d"(a3),
          [arg4] "r"(a4), [arg5] "r"(a5)
        : "memory", "rcx", "r8", "r10", "r11");
    return ret;
}

static inline long syscall_x86_64_6(long n, long a1, long a2, long a3, long a4, long a5, long a6) {
    long ret;
    __asm__ volatile(
        "mov %[arg4], %%r10\n\t"
        "mov %[arg5], %%r8\n\t"
        "mov %[arg6], %%r9\n\t"
        "int $0x80"
        : "=a"(ret)
        : "0"(n), "D"(a1), "S"(a2), "d"(a3),
          [arg4] "r"(a4), [arg5] "r"(a5), [arg6] "r"(a6)
        : "memory", "rcx", "r8", "r9", "r10", "r11");
    return ret;
}

/* ============================================================
 *   Architecture-Agnostic Syscall Macros
 * ============================================================ */

#define __SYSCALL_0(n)                 syscall_x86_64_0(n)
#define __SYSCALL_1(n, a1)             syscall_x86_64_1(n, (long)(a1))
#define __SYSCALL_2(n, a1, a2)         syscall_x86_64_2(n, (long)(a1), (long)(a2))
#define __SYSCALL_3(n, a1, a2, a3)     syscall_x86_64_3(n, (long)(a1), (long)(a2), (long)(a3))
#define __SYSCALL_4(n, a1, a2, a3, a4) syscall_x86_64_4(n, (long)(a1), (long)(a2), (long)(a3), (long)(a4))
#define __SYSCALL_5(n, a1, a2, a3, a4, a5) \
    syscall_x86_64_5(n, (long)(a1), (long)(a2), (long)(a3), (long)(a4), (long)(a5))
#define __SYSCALL_6(n, a1, a2, a3, a4, a5, a6) \
    syscall_x86_64_6(n, (long)(a1), (long)(a2), (long)(a3), (long)(a4), (long)(a5), (long)(a6))
