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
    register long rax __asm__("rax") = n;
    __asm__ volatile("int $0x80" : "+r"(rax) :: "memory");
    return rax;
}

static inline long syscall_x86_64_1(long n, long a1) {
    register long rax __asm__("rax") = n;
    register long rdi __asm__("rdi") = a1;
    __asm__ volatile("int $0x80" : "+r"(rax) : "r"(rdi) : "memory");
    return rax;
}

static inline long syscall_x86_64_2(long n, long a1, long a2) {
    register long rax __asm__("rax") = n;
    register long rdi __asm__("rdi") = a1;
    register long rsi __asm__("rsi") = a2;
    __asm__ volatile("int $0x80" : "+r"(rax) : "r"(rdi), "r"(rsi) : "memory");
    return rax;
}

static inline long syscall_x86_64_3(long n, long a1, long a2, long a3) {
    register long rax __asm__("rax") = n;
    register long rdi __asm__("rdi") = a1;
    register long rsi __asm__("rsi") = a2;
    register long rdx __asm__("rdx") = a3;
    __asm__ volatile("int $0x80" : "+r"(rax) : "r"(rdi), "r"(rsi), "r"(rdx) : "memory");
    return rax;
}

static inline long syscall_x86_64_4(long n, long a1, long a2, long a3, long a4) {
    register long rax __asm__("rax") = n;
    register long rdi __asm__("rdi") = a1;
    register long rsi __asm__("rsi") = a2;
    register long rdx __asm__("rdx") = a3;
    register long r10 __asm__("r10") = a4;
    __asm__ volatile("int $0x80" : "+r"(rax) : "r"(rdi), "r"(rsi), "r"(rdx), "r"(r10) : "memory");
    return rax;
}

static inline long syscall_x86_64_5(long n, long a1, long a2, long a3, long a4, long a5) {
    register long rax __asm__("rax") = n;
    register long rdi __asm__("rdi") = a1;
    register long rsi __asm__("rsi") = a2;
    register long rdx __asm__("rdx") = a3;
    register long r10 __asm__("r10") = a4;
    register long r8 __asm__("r8") = a5;
    __asm__ volatile("int $0x80" : "+r"(rax) : "r"(rdi), "r"(rsi), "r"(rdx), "r"(r10), "r"(r8) : "memory");
    return rax;
}

static inline long syscall_x86_64_6(long n, long a1, long a2, long a3, long a4, long a5, long a6) {
    register long rax __asm__("rax") = n;
    register long rdi __asm__("rdi") = a1;
    register long rsi __asm__("rsi") = a2;
    register long rdx __asm__("rdx") = a3;
    register long r10 __asm__("r10") = a4;
    register long r8 __asm__("r8") = a5;
    register long r9 __asm__("r9") = a6;
    __asm__ volatile("int $0x80" : "+r"(rax) : "r"(rdi), "r"(rsi), "r"(rdx), "r"(r10), "r"(r8), "r"(r9) : "memory");
    return rax;
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
