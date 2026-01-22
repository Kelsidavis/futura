/* regs.h - Futura OS x86_64 Register Structures
 *
 * Copyright (c) 2025 Kelsi Davis
 * Licensed under the MPL v2.0 — see LICENSE for details.
 *
 * CPU register structures for x86_64 long mode.
 */

#pragma once

#include <stdint.h>

/* Assembly helpers implemented in context_switch.S */
uint64_t fut_get_rsp(void);
uint64_t fut_get_rbp(void);

/* ============================================================
 *   Interrupt Frame Structure
 * ============================================================ */

/**
 * Interrupt frame pushed by CPU and ISR stub.
 * Represents complete CPU state at time of interrupt.
 *
 * Stack layout (grows downward):
 *   [SS]       ← Only if privilege change (ring 3→0)
 *   [RSP]      ← Only if privilege change
 *   RFLAGS
 *   CS
 *   RIP        ← CPU pushes these on interrupt
 *   Error Code ← Some exceptions push this
 *   ---ISR stub pushes below---
 *   RAX, RBX, RCX, RDX
 *   RSI, RDI, RBP
 *   R8-R15
 *   DS, ES, FS, GS
 */
typedef struct fut_interrupt_frame {
    /* Segment registers (pushed first by ISR) */
    uint64_t gs;
    uint64_t fs;
    uint64_t es;
    uint64_t ds;

    /* General purpose registers (pushed by ISR) */
    uint64_t rax;
    uint64_t rbx;
    uint64_t rcx;
    uint64_t rdx;
    uint64_t rsi;
    uint64_t rdi;
    uint64_t rbp;
    uint64_t r8;
    uint64_t r9;
    uint64_t r10;
    uint64_t r11;
    uint64_t r12;
    uint64_t r13;
    uint64_t r14;
    uint64_t r15;

    /* Vector number and error code (pushed by ISR macro/CPU) */
    uint64_t vector;
    uint64_t error_code;

    /* CPU-pushed values (always present) */
    uint64_t rip;
    uint64_t cs;
    uint64_t rflags;

    /* Stack pointer and segment (only if privilege level changed) */
    uint64_t rsp;
    uint64_t ss;
} __attribute__((packed)) fut_interrupt_frame_t;

static_assert(sizeof(fut_interrupt_frame_t) == 208, "Interrupt frame must be 208 bytes");

/* ============================================================
 *   CPU Context Structure (for context switching)
 * ============================================================ */

/**
 * Minimal CPU context for cooperative context switching.
 * Only callee-saved registers need to be preserved.
 */
typedef struct fut_cpu_context {
    /* Callee-saved registers (System V AMD64 ABI) */
    uint64_t r15;
    uint64_t r14;
    uint64_t r13;
    uint64_t r12;
    uint64_t rbx;
    uint64_t rbp;

    /* Control flow state */
    uint64_t rip;
    uint64_t rsp;
    uint64_t rflags;
    uint64_t cs;
    uint64_t ss;

    /* Data segment registers (must be preserved for kernel operations) */
    uint64_t ds;
    uint64_t es;
    uint64_t fs;
    uint64_t gs;

    /* Caller-saved registers captured for bootstrap/debug */
    uint64_t rdi;
    uint64_t rsi;
    uint64_t rdx;
    uint64_t rcx;
    uint64_t rax;

    /* Saved SIMD/FPU state (must be 16-byte aligned for FXSAVE) */
    alignas(16) uint8_t fx_area[512];
} __attribute__((aligned(16))) fut_cpu_context_t;

static_assert(sizeof(fut_cpu_context_t) == 672, "CPU context must be 672 bytes");

/* ============================================================
 *   Register Accessors
 * ============================================================ */

static inline uint64_t fut_read_cr0(void) {
    uint64_t val;
    __asm__ volatile("mov %%cr0, %0" : "=r"(val));
    return val;
}

static inline void fut_write_cr0(uint64_t val) {
    __asm__ volatile("mov %0, %%cr0" :: "r"(val));
}

static inline uint64_t fut_read_cr2(void) {
    uint64_t val;
    __asm__ volatile("mov %%cr2, %0" : "=r"(val));
    return val;
}

static inline uint64_t fut_read_cr3(void) {
    uint64_t val;
    __asm__ volatile("mov %%cr3, %0" : "=r"(val));
    return val;
}

static inline void fut_write_cr3(uint64_t val) {
    __asm__ volatile("mov %0, %%cr3" :: "r"(val) : "memory");
}

static inline uint64_t fut_read_cr4(void) {
    uint64_t val;
    __asm__ volatile("mov %%cr4, %0" : "=r"(val));
    return val;
}

static inline void fut_write_cr4(uint64_t val) {
    __asm__ volatile("mov %0, %%cr4" :: "r"(val));
}

/* ============================================================
 *   MSR Access
 * ============================================================ */

static inline uint64_t fut_read_msr(uint32_t msr) {
    uint32_t low, high;
    __asm__ volatile("rdmsr" : "=a"(low), "=d"(high) : "c"(msr));
    return ((uint64_t)high << 32) | low;
}

static inline void fut_write_msr(uint32_t msr, uint64_t value) {
    uint32_t low = value & 0xFFFFFFFF;
    uint32_t high = value >> 32;
    __asm__ volatile("wrmsr" :: "c"(msr), "a"(low), "d"(high));
}

/* Common MSRs */
#define MSR_EFER        0xC0000080  /* Extended Feature Enable Register */
#define MSR_STAR        0xC0000081  /* System Call Target Address */
#define MSR_LSTAR       0xC0000082  /* Long Mode System Call Target */
#define MSR_CSTAR       0xC0000083  /* Compatibility Mode System Call Target */
#define MSR_SFMASK      0xC0000084  /* System Call Flag Mask */
#define MSR_FS_BASE     0xC0000100  /* FS segment base */
#define MSR_GS_BASE     0xC0000101  /* GS segment base */
#define MSR_KERNEL_GS   0xC0000102  /* Kernel GS base */

/* EFER bits */
#define EFER_SCE        (1 << 0)    /* System Call Extensions */
#define EFER_LME        (1 << 8)    /* Long Mode Enable */
#define EFER_LMA        (1 << 10)   /* Long Mode Active */
#define EFER_NXE        (1 << 11)   /* No-Execute Enable */

/* ============================================================
 *   RFLAGS Definitions
 * ============================================================ */

#define RFLAGS_RESERVED (1 << 1)    /* Reserved bit (must always be 1) */
#define RFLAGS_CF       (1 << 0)    /* Carry Flag */
#define RFLAGS_PF       (1 << 2)    /* Parity Flag */
#define RFLAGS_AF       (1 << 4)    /* Auxiliary Carry Flag */
#define RFLAGS_ZF       (1 << 6)    /* Zero Flag */
#define RFLAGS_SF       (1 << 7)    /* Sign Flag */
#define RFLAGS_TF       (1 << 8)    /* Trap Flag */
#define RFLAGS_IF       (1 << 9)    /* Interrupt Enable Flag */
#define RFLAGS_DF       (1 << 10)   /* Direction Flag */
#define RFLAGS_OF       (1 << 11)   /* Overflow Flag */
#define RFLAGS_IOPL     (3 << 12)   /* I/O Privilege Level */
#define RFLAGS_NT       (1 << 14)   /* Nested Task */
#define RFLAGS_RF       (1 << 16)   /* Resume Flag */
#define RFLAGS_VM       (1 << 17)   /* Virtual 8086 Mode */
#define RFLAGS_AC       (1 << 18)   /* Alignment Check */
#define RFLAGS_VIF      (1 << 19)   /* Virtual Interrupt Flag */
#define RFLAGS_VIP      (1 << 20)   /* Virtual Interrupt Pending */
#define RFLAGS_ID       (1 << 21)   /* ID Flag */

/* Initial RFLAGS for new kernel threads (reserved bit set, interrupts ENABLED)
 * Kernel threads need IF=1 so timer preemption works. If a kernel thread enters
 * a busy-wait loop, it will never be preempted if interrupts are disabled. */
#define RFLAGS_KERNEL_INIT  (RFLAGS_RESERVED | RFLAGS_IF)

/* ============================================================
 *   FPU/SSE State Defaults
 * ============================================================ */

/* MXCSR default value (all exceptions masked, round-to-nearest) */
#define MXCSR_DEFAULT       0x1F80

/* MXCSR field offsets in FXSAVE area */
#define FXSAVE_MXCSR_OFFSET 24

/* ============================================================
 *   CPU Feature Detection
 * ============================================================ */

static inline void fut_cpuid(uint32_t leaf, uint32_t *eax, uint32_t *ebx,
                             uint32_t *ecx, uint32_t *edx) {
    __asm__ volatile("cpuid"
        : "=a"(*eax), "=b"(*ebx), "=c"(*ecx), "=d"(*edx)
        : "a"(leaf));
}

/* ============================================================
 *   Port I/O
 * ============================================================ */

static inline uint8_t fut_inb(uint16_t port) {
    uint8_t value;
    __asm__ volatile("inb %1, %0" : "=a"(value) : "Nd"(port) : "memory");
    return value;
}

static inline void fut_outb(uint16_t port, uint8_t value) {
    __asm__ volatile("outb %0, %1" :: "a"(value), "Nd"(port) : "memory");
}

static inline uint16_t fut_inw(uint16_t port) {
    uint16_t value;
    __asm__ volatile("inw %1, %0" : "=a"(value) : "Nd"(port) : "memory");
    return value;
}

static inline void fut_outw(uint16_t port, uint16_t value) {
    __asm__ volatile("outw %0, %1" :: "a"(value), "Nd"(port) : "memory");
}

static inline uint32_t fut_inl(uint16_t port) {
    uint32_t value;
    __asm__ volatile("inl %1, %0" : "=a"(value) : "Nd"(port) : "memory");
    return value;
}

static inline void fut_outl(uint16_t port, uint32_t value) {
    __asm__ volatile("outl %0, %1" :: "a"(value), "Nd"(port) : "memory");
}

/* ============================================================
 *   Memory Barriers
 * ============================================================ */

static inline void fut_mfence(void) {
    __asm__ volatile("mfence" ::: "memory");
}

static inline void fut_lfence(void) {
    __asm__ volatile("lfence" ::: "memory");
}

static inline void fut_sfence(void) {
    __asm__ volatile("sfence" ::: "memory");
}

/* ============================================================
 *   CPU Control
 * ============================================================ */

static inline void fut_cli(void) {
    __asm__ volatile("cli" ::: "memory");
}

static inline void fut_sti(void) {
    __asm__ volatile("sti" ::: "memory");
}

static inline void fut_hlt(void) {
    __asm__ volatile("hlt");
}

static inline void fut_pause(void) {
    __asm__ volatile("pause");
}

static inline void fut_invlpg(uint64_t addr) {
    __asm__ volatile("invlpg (%0)" :: "r"(addr) : "memory");
}

static inline void fut_wbinvd(void) {
    __asm__ volatile("wbinvd" ::: "memory");
}
