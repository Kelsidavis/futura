// SPDX-License-Identifier: MPL-2.0
/*
 * syscall_abi.h - x86_64 syscall trap ABI helpers
 */

#pragma once

#include <stdint.h>

#define SYSCALL_INT_VECTOR 0x80u

typedef struct regs64 {
    uint64_t r15, r14, r13, r12, r11, r10, r9, r8;
    uint64_t rdi, rsi, rbp, rdx, rcx, rbx, rax;
    uint64_t rip, cs, rflags, rsp, ss;
} regs64_t;
