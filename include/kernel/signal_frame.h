/* signal_frame.h - Signal frame structures for userspace signal handlers
 *
 * Copyright (c) 2025 Kelsi Davis
 * Licensed under the MPL v2.0 — see LICENSE for details.
 *
 * Defines the signal frame layout on the user stack when delivering signals
 * to userspace handlers. This allows proper context restoration via sigreturn().
 * Supports both x86-64 and ARM64 architectures.
 */

#ifndef __KERNEL_SIGNAL_FRAME_H__
#define __KERNEL_SIGNAL_FRAME_H__

#include <stdint.h>
#include <kernel/signal.h>

#if defined(__x86_64__)

/* x86-64 general purpose registers in signal context */
struct sigcontext {
    uint64_t r8;
    uint64_t r9;
    uint64_t r10;
    uint64_t r11;
    uint64_t r12;
    uint64_t r13;
    uint64_t r14;
    uint64_t r15;
    uint64_t rdi;
    uint64_t rsi;
    uint64_t rbp;
    uint64_t rbx;
    uint64_t rdx;
    uint64_t rax;
    uint64_t rcx;
    uint64_t rsp;
    uint64_t rip;
    uint64_t eflags;
    uint16_t cs;
    uint16_t gs;
    uint16_t fs;
    uint16_t __pad0;
    uint64_t err;
    uint64_t trapno;
};

#elif defined(__aarch64__)

/* ARM64 general purpose registers and state in signal context
 *
 * Covers all 31 general-purpose registers (x0-x30), program counter (ELR_EL1),
 * processor state (SPSR_EL1), fault address, and NEON SIMD state.
 */
struct sigcontext {
    /* General purpose registers x0-x30 */
    uint64_t x[31];

    /* Stack pointer (SP_EL0) */
    uint64_t sp;

    /* Program counter (ELR_EL1) - instruction to resume at */
    uint64_t pc;

    /* Processor state (SPSR_EL1)
     * Includes condition codes, interrupt masks, exception level, etc. */
    uint64_t pstate;

    /* Fault address (FAR_EL1) - used for memory exceptions */
    uint64_t fault_address;

    /* NEON SIMD registers (v0-v31, each 128-bit) */
    __uint128_t v[32];

    /* Floating-point control registers */
    uint32_t fpsr;        /* Floating-point status register */
    uint32_t fpcr;        /* Floating-point control register */
};

#else
#error "Unsupported architecture for signal frames"
#endif

/* Machine context - registers and flags */
typedef struct {
    struct sigcontext gregs;
} mcontext_t;

/* Stack descriptor */
typedef struct {
    void *ss_sp;
    int ss_flags;
    size_t ss_size;
} stack_t;

/* User context - full context for signal handler */
typedef struct {
    uint64_t uc_flags;
    struct ucontext *uc_link;    /* Link to next context */
    stack_t uc_stack;             /* Alternate signal stack */
    mcontext_t uc_mcontext;       /* Machine context (registers) */
    sigset_t uc_sigmask;          /* Signal mask to restore */
} ucontext_t;

/* Signal info - information about delivered signal */
typedef struct {
    int si_signum;      /* Signal number */
    int si_errno;       /* Error number */
    int si_code;        /* Signal code (SI_USER, SI_QUEUE, etc.) */
    int64_t si_pid;     /* Sending process PID */
    uint32_t si_uid;    /* Sending process UID */
    int si_status;      /* Exit status or signal number */
    void *si_addr;      /* Memory address for SIGSEGV, etc. */
    long si_value;      /* Signal value for rt_sigqueue */
    int si_overrun;     /* Timer overrun count */
    int si_timerid;     /* Timer ID */
} siginfo_t;

/* Real-time signal frame layout on user stack
 *
 * When a signal is delivered, the kernel pushes this entire structure
 * onto the user's stack, then modifies the interrupt context to call
 * the signal handler with this frame as the base reference.
 *
 * Layout (growing downward from high addresses):
 *   [user code that was interrupted]
 *   SP → [rt_sigframe structure below]
 *
 * The signal handler receives (architecture-specific calling convention):
 *   x86-64:
 *     rdi = signal number
 *     rsi = siginfo_t *
 *     rdx = ucontext_t *
 *   ARM64:
 *     x0 = signal number
 *     x1 = siginfo_t *
 *     x2 = ucontext_t *
 */
struct rt_sigframe {
    /* Signal info - passed as second argument to handler */
    siginfo_t info;

    /* User context - passed as third argument to handler
     * Contains all registers and state from interrupted code */
    ucontext_t uc;

    /* Return address (for trampoline code on user stack)
     * When signal handler returns, this points to code that calls sigreturn() */
    void (*return_address)(void);

    /* Padding for alignment (16-byte stack alignment on entry) */
    uint64_t pad;
};

#endif /* __KERNEL_SIGNAL_FRAME_H__ */
