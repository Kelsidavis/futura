/*
 * Futura OS - x86_64 ISR Stubs
 * Copyright (C) 2025 Futura OS Project
 *
 * Interrupt Service Routine stubs with full 64-bit register preservation
 */

.section .text

/* Macro to create exception handler without error code */
.macro ISR_NO_ERROR vector
.global isr\vector
.type isr\vector, @function
isr\vector:
    pushq $0                            /* Dummy error code */
    pushq $\vector                      /* Push vector number */
    jmp isr_common_stub
.size isr\vector, . - isr\vector
.endm

/* Macro to create exception handler with error code */
.macro ISR_ERROR vector
.global isr\vector
.type isr\vector, @function
isr\vector:
    pushq $\vector                      /* Push vector number */
    jmp isr_common_stub
.size isr\vector, . - isr\vector
.endm

/* Macro to create IRQ handler */
.macro IRQ irq, vector
.global irq\irq
.type irq\irq, @function
irq\irq:
    pushq $0                            /* Dummy error code */
    pushq $\vector                      /* Push vector number */
    jmp irq_common_stub
.size irq\irq, . - irq\irq
.endm

/* CPU Exception ISRs (0-31) */
ISR_NO_ERROR 0                          /* Divide by zero */
ISR_NO_ERROR 1                          /* Debug */
ISR_NO_ERROR 2                          /* Non-maskable interrupt */
ISR_NO_ERROR 3                          /* Breakpoint */
ISR_NO_ERROR 4                          /* Overflow */
ISR_NO_ERROR 5                          /* Bound range exceeded */
ISR_NO_ERROR 6                          /* Invalid opcode */
ISR_NO_ERROR 7                          /* Device not available */
ISR_ERROR    8                          /* Double fault */
ISR_NO_ERROR 9                          /* Coprocessor segment overrun */
ISR_ERROR    10                         /* Invalid TSS */
ISR_ERROR    11                         /* Segment not present */
ISR_ERROR    12                         /* Stack segment fault */
ISR_ERROR    13                         /* General protection fault */
ISR_ERROR    14                         /* Page fault */
ISR_NO_ERROR 15                         /* Reserved */
ISR_NO_ERROR 16                         /* x87 floating point exception */
ISR_ERROR    17                         /* Alignment check */
ISR_NO_ERROR 18                         /* Machine check */
ISR_NO_ERROR 19                         /* SIMD floating point exception */
ISR_NO_ERROR 20                         /* Virtualization exception */
ISR_ERROR    21                         /* Control protection exception */
ISR_NO_ERROR 22                         /* Reserved */
ISR_NO_ERROR 23                         /* Reserved */
ISR_NO_ERROR 24                         /* Reserved */
ISR_NO_ERROR 25                         /* Reserved */
ISR_NO_ERROR 26                         /* Reserved */
ISR_NO_ERROR 27                         /* Reserved */
ISR_NO_ERROR 28                         /* Hypervisor injection exception */
ISR_ERROR    29                         /* VMM communication exception */
ISR_ERROR    30                         /* Security exception */
ISR_NO_ERROR 31                         /* Reserved */

/* IRQ handlers (32-47) */
IRQ 0,  32                              /* PIT timer */
IRQ 1,  33                              /* Keyboard */
IRQ 2,  34                              /* Cascade */
IRQ 3,  35                              /* COM2 */
IRQ 4,  36                              /* COM1 */
IRQ 5,  37                              /* LPT2 */
IRQ 6,  38                              /* Floppy */
IRQ 7,  39                              /* LPT1 */
IRQ 8,  40                              /* CMOS RTC */
IRQ 9,  41                              /* Free */
IRQ 10, 42                              /* Free */
IRQ 11, 43                              /* Free */
IRQ 12, 44                              /* PS/2 Mouse */
IRQ 13, 45                              /* FPU */
IRQ 14, 46                              /* Primary ATA */
IRQ 15, 47                              /* Secondary ATA */

/* System call interrupt (128) */
.extern syscall_entry_c
.extern fut_in_interrupt
.extern fut_current_frame
.global isr_syscall_int80_stub
.type isr_syscall_int80_stub, @function
isr_syscall_int80_stub:
    /* ==========================================================================
     * CRITICAL: Use the SAME register layout as isr_common_stub to match
     * fut_interrupt_frame_t structure. This ensures C code accessing the frame
     * (e.g., signal delivery) reads/writes correct register locations.
     *
     * Structure layout (from regs.h fut_interrupt_frame_t):
     *   offset 0:   GS, FS, ES, DS (segments)
     *   offset 32:  RAX, RBX, RCX, RDX, RSI, RDI, RBP (GPRs)
     *   offset 88:  R8, R9, R10, R11, R12, R13, R14, R15
     *   offset 152: vector, error_code
     *   offset 168: RIP, CS, RFLAGS, RSP, SS (CPU-pushed)
     * ========================================================================== */

    /* Push dummy vector (128) and error code (0) to match ISR frame layout */
    pushq $0                  /* Dummy error code */
    pushq $128               /* Vector number (syscall) */

    /* Push all general purpose registers in SAME ORDER as isr_common_stub */
    pushq %r15
    pushq %r14
    pushq %r13
    pushq %r12
    pushq %r11
    pushq %r10
    pushq %r9
    pushq %r8
    pushq %rbp
    pushq %rdi
    pushq %rsi
    pushq %rdx
    pushq %rcx
    pushq %rbx
    pushq %rax               /* RAX contains syscall number */

    /* Push segment registers (zero RAX first to avoid garbage in upper bits) */
    xorq %rax, %rax
    movw %ds, %ax
    pushq %rax
    xorq %rax, %rax
    movw %es, %ax
    pushq %rax
    xorq %rax, %rax
    movw %fs, %ax
    pushq %rax
    xorq %rax, %rax
    movw %gs, %ax
    pushq %rax

    /* Load kernel data segment (but DON'T touch GS or FS - they use MSR base!) */
    movw $0x10, %ax
    movw %ax, %ds
    movw %ax, %es
    /* FS intentionally NOT reloaded - must preserve MSR_FS_BASE for TLS support */
    /* GS intentionally NOT reloaded - must preserve GS_BASE MSR setup */

    /* Now stack layout matches fut_interrupt_frame_t exactly:
     * RSP+0:   GS
     * RSP+8:   FS
     * RSP+16:  ES
     * RSP+24:  DS
     * RSP+32:  RAX (syscall number)
     * RSP+40:  RBX
     * RSP+48:  RCX
     * RSP+56:  RDX
     * RSP+64:  RSI
     * RSP+72:  RDI (syscall arg1)
     * RSP+80:  RBP
     * RSP+88:  R8 (syscall arg5)
     * RSP+96:  R9 (syscall arg6)
     * RSP+104: R10 (syscall arg4)
     * RSP+112: R11
     * RSP+120: R12
     * RSP+128: R13
     * RSP+136: R14
     * RSP+144: R15
     * RSP+152: vector (128)
     * RSP+160: error_code (0)
     * RSP+168: RIP (CPU-pushed)
     * RSP+176: CS
     * RSP+184: RFLAGS
     * RSP+192: RSP
     * RSP+200: SS
     */

    /* Set global fut_current_frame to start of frame for C code access */
    movq %rsp, fut_current_frame(%rip)

    /* Extract syscall arguments from saved registers
     * User syscall convention: RAX=syscall#, RDI=arg1, RSI=arg2, RDX=arg3, R10=arg4, R8=arg5, R9=arg6
     * C calling convention: RDI=param1, RSI=param2, RDX=param3, RCX=param4, R8=param5, R9=param6
     *
     * syscall_entry_c(syscall_nr, arg1, arg2, arg3, arg4, arg5, arg6, frame_ptr)
     */
    movq 32(%rsp), %rdi       /* RDI = syscall number (from saved RAX) */
    movq 72(%rsp), %rsi       /* RSI = arg1 (from saved RDI) */
    movq 64(%rsp), %rdx       /* RDX = arg2 (from saved RSI) */
    movq 56(%rsp), %rcx       /* RCX = arg3 (from saved RDX) */
    movq 104(%rsp), %r8       /* R8 = arg4 (from saved R10) */
    movq 88(%rsp), %r9        /* R9 = arg5 (from saved R8) */
    movq 96(%rsp), %r10       /* R10 = arg6 (from saved R9, will be pushed) */

    /* Push stack arguments for syscall_entry_c */
    movq %rsp, %r11           /* r11 = frame pointer (points to start of fut_interrupt_frame_t) */
    pushq %r11                /* Push frame_ptr (param 8) */
    pushq %r10                /* Push arg6 (param 7) */

    call syscall_entry_c

    /* Save return value */
    movq %rax, %r11           /* Save syscall return value in R11 */

    addq $16, %rsp            /* Remove stack arguments */

    /* Restore registers in reverse order to match push order */
    popq %rax                 /* Discard saved GS value */
    /* GS intentionally NOT restored - must preserve GS_BASE MSR */
    popq %rax                 /* Discard saved FS value */
    /* FS intentionally NOT restored - must preserve MSR_FS_BASE for TLS support */
    popq %rax
    movw %ax, %es             /* Restore user ES */
    popq %rax
    movw %ax, %ds             /* Restore user DS */

    popq %rax                 /* Restore RAX (will be overwritten with return value) */
    popq %rbx
    popq %rcx
    popq %rdx
    popq %rsi
    popq %rdi
    popq %rbp
    popq %r8
    popq %r9
    popq %r10
    addq $8, %rsp             /* Skip R11 - we're using it for return value */
    popq %r12
    popq %r13
    popq %r14
    popq %r15

    /* Remove vector and error_code */
    addq $16, %rsp

    /* Put syscall return value in RAX */
    movq %r11, %rax

    /* NOTE: We do NOT zero XMM registers on syscall return because the userspace
     * syscall wrapper doesn't declare XMM as clobbered. If we zero them here,
     * GCC-generated code that stores pointers in XMM will crash when it finds NULL.
     * XMM registers must be preserved across syscalls per the calling convention. */

    /* CRITICAL: Ensure IF is set in RFLAGS before returning to userspace!
     * RFLAGS is at RSP+16 in the IRETQ frame */
    orq $0x200, 16(%rsp)        /* Set IF (bit 9) in RFLAGS */

    iretq
.size isr_syscall_int80_stub, . - isr_syscall_int80_stub

.global isr128
.set isr128, isr_syscall_int80_stub

/* SYSCALL instruction entry point (x86_64 fast path)
 * On entry:
 *   RAX = syscall number
 *   RDI = arg1, RSI = arg2, RDX = arg3, R10 = arg4, R8 = arg5, R9 = arg6
 *   RIP in RCX, RFLAGS in R11 (saved by hardware)
 *   RSP = user stack pointer
 *
 * CRITICAL: Unlike INT 0x80, SYSCALL does NOT:
 *   - Switch to kernel stack (RSP stays at user value)
 *   - Push an interrupt frame
 * We must:
 * 1. Save user RSP to per-CPU scratch area (via GS)
 * 2. Load kernel RSP from per-CPU data
 * 3. Build interrupt frame manually on kernel stack
 * 4. Call syscall handler
 * 5. Restore user RSP and return via SYSRET
 *
 * CRITICAL: Use the SAME register layout as isr_common_stub to match
 * fut_interrupt_frame_t structure. This ensures C code accessing the frame
 * reads/writes correct register locations.
 *
 * Per-CPU offsets (from fut_percpu.h):
 *   PERCPU_OFFSET_SYSCALL_USER_RSP   = 96
 *   PERCPU_OFFSET_SYSCALL_KERNEL_RSP = 104
 */
.global isr_syscall_fastpath
.type isr_syscall_fastpath, @function
isr_syscall_fastpath:
    /* At entry: RCX=user RIP, R11=user RFLAGS, RSP=user stack, RAX=syscall number */
    /* GS base points to per-CPU data (fut_percpu_t) */

    /* Step 1: Save user RSP to per-CPU scratch area (using GS-relative access) */
    movq %rsp, %gs:96             /* Save user RSP to percpu->syscall_user_rsp */

    /* Step 2: Load kernel RSP from per-CPU data */
    movq %gs:104, %rsp            /* Load percpu->syscall_kernel_rsp */

    /* Step 3: Build interrupt frame on kernel stack matching fut_interrupt_frame_t */
    /* CPU-pushed values (we build manually since SYSCALL doesn't push them) */
    pushq $0x1b                   /* SS = user data segment (0x18|RPL=3) */
    pushq %gs:96                  /* User RSP (from saved scratch) */
    pushq %r11                    /* User RFLAGS (saved by SYSCALL in R11) */
    pushq $0x23                   /* CS = user code segment (0x20|RPL=3) */
    pushq %rcx                    /* User RIP (saved by SYSCALL in RCX) */

    /* Push dummy vector (128) and error code (0) to match ISR frame layout */
    pushq $0                      /* Dummy error code */
    pushq $128                    /* Vector number (syscall) */

    /* Push all general purpose registers in SAME ORDER as isr_common_stub */
    pushq %r15
    pushq %r14
    pushq %r13
    pushq %r12
    pushq %r11                    /* Note: This is user RFLAGS, also saved above */
    pushq %r10
    pushq %r9
    pushq %r8
    pushq %rbp
    pushq %rdi
    pushq %rsi
    pushq %rdx
    pushq %rcx                    /* Note: This is user RIP, also saved above */
    pushq %rbx
    pushq %rax                    /* RAX contains syscall number */

    /* Push segment registers */
    xorq %rax, %rax
    movw %ds, %ax
    pushq %rax
    xorq %rax, %rax
    movw %es, %ax
    pushq %rax
    xorq %rax, %rax
    movw %fs, %ax
    pushq %rax
    xorq %rax, %rax
    movw %gs, %ax
    pushq %rax

    /* Load kernel data segments (but DON'T touch FS or GS - preserve MSR bases!) */
    movw $0x10, %ax
    movw %ax, %ds
    movw %ax, %es
    /* FS intentionally NOT loaded - must preserve MSR_FS_BASE for TLS support */

    /* Stack layout now matches fut_interrupt_frame_t exactly:
     * RSP+0:   GS
     * RSP+8:   FS
     * RSP+16:  ES
     * RSP+24:  DS
     * RSP+32:  RAX (syscall number)
     * RSP+40:  RBX
     * RSP+48:  RCX (user RIP)
     * RSP+56:  RDX
     * RSP+64:  RSI
     * RSP+72:  RDI (syscall arg1)
     * RSP+80:  RBP
     * RSP+88:  R8 (syscall arg5)
     * RSP+96:  R9 (syscall arg6)
     * RSP+104: R10 (syscall arg4)
     * RSP+112: R11 (user RFLAGS)
     * RSP+120: R12
     * RSP+128: R13
     * RSP+136: R14
     * RSP+144: R15
     * RSP+152: vector (128)
     * RSP+160: error_code (0)
     * RSP+168: RIP
     * RSP+176: CS
     * RSP+184: RFLAGS
     * RSP+192: RSP
     * RSP+200: SS
     */

    /* Set global fut_current_frame to start of frame for C code access.
     * CRITICAL: Also set fut_in_interrupt=1 so that if the syscall calls
     * fut_schedule() (e.g., during exit()), the scheduler uses IRETQ-based
     * context switching. Without this, the scheduler uses cooperative switch
     * which loads from thread->context instead of thread->irq_frame, causing
     * state corruption when the next thread was previously preempted. */
    movq %rsp, fut_current_frame(%rip)
    movb $1, fut_in_interrupt(%rip)

    /* Extract syscall arguments from saved registers */
    movq 32(%rsp), %rdi           /* RDI = syscall number (from saved RAX) */
    movq 72(%rsp), %rsi           /* RSI = arg1 (from saved RDI) */
    movq 64(%rsp), %rdx           /* RDX = arg2 (from saved RSI) */
    movq 56(%rsp), %rcx           /* RCX = arg3 (from saved RDX) */
    movq 104(%rsp), %r8           /* R8 = arg4 (from saved R10) */
    movq 88(%rsp), %r9            /* R9 = arg5 (from saved R8) */
    movq 96(%rsp), %r10           /* R10 = arg6 (from saved R9, will be pushed) */

    /* Push stack arguments for syscall_entry_c */
    movq %rsp, %r11               /* r11 = frame pointer */
    pushq %r11                    /* Push frame_ptr (param 8) */
    pushq %r10                    /* Push arg6 (param 7) */

    /* Call the syscall handler */
    call syscall_entry_c

    /* Save return value */
    movq %rax, %r15               /* Save syscall return value in R15 (callee-saved) */

    /* Clear interrupt context flags now that syscall is complete.
     * This must happen before we start restoring registers. */
    movb $0, fut_in_interrupt(%rip)
    movq $0, fut_current_frame(%rip)

    addq $16, %rsp                /* Remove stack arguments */

    /* Restore segment registers (discard GS and FS - must preserve MSR bases!) */
    popq %rax                     /* Discard saved GS */
    popq %rax                     /* Discard saved FS - must preserve MSR_FS_BASE */
    popq %rax
    movw %ax, %es                 /* Restore ES */
    popq %rax
    movw %ax, %ds                 /* Restore DS */

    /* Restore general purpose registers in reverse order */
    popq %rax                     /* Restore RAX (will be overwritten with return value) */
    popq %rbx
    popq %rcx                     /* Restore RCX (was user RIP, needed for SYSRET) */
    popq %rdx
    popq %rsi
    popq %rdi
    popq %rbp
    popq %r8
    popq %r9
    popq %r10
    popq %r11                     /* Restore R11 (user RFLAGS, needed for SYSRET) */
    popq %r12
    popq %r13
    popq %r14
    addq $8, %rsp                 /* Skip R15 - we're using it for return value */

    /* Remove vector and error_code */
    addq $16, %rsp

    /* Now stack has: RIP, CS, RFLAGS, RSP, SS */
    /* But we already have RIP in RCX and RFLAGS in R11 from the pops above */
    /* Skip the CPU-pushed frame */
    addq $40, %rsp                /* Skip RIP, CS, RFLAGS, RSP, SS */

    /* CRITICAL: Ensure IF (bit 9) is set in RFLAGS before returning to userspace!
     * Without this, timer interrupts won't fire for this thread. */
    orq $0x200, %r11

    /* Restore user RSP from per-CPU scratch */
    movq %gs:96, %rsp

    /* Move return value to RAX */
    movq %r15, %rax

    /* Use SYSRET to return to user mode
     * RCX = return address, R11 = RFLAGS, RSP = user stack, RAX = return value
     */
    sysretq
.size isr_syscall_fastpath, . - isr_syscall_fastpath

/* Common ISR stub - saves all registers */
.type isr_common_stub, @function
isr_common_stub:
    /* Push all general purpose registers */
    pushq %r15
    pushq %r14
    pushq %r13
    pushq %r12
    pushq %r11
    pushq %r10
    pushq %r9
    pushq %r8
    pushq %rbp
    pushq %rdi
    pushq %rsi
    pushq %rdx
    pushq %rcx
    pushq %rbx
    pushq %rax

    /* Push segment registers (zero RAX first to avoid garbage in upper bits) */
    xorq %rax, %rax
    movw %ds, %ax
    pushq %rax
    xorq %rax, %rax
    movw %es, %ax
    pushq %rax
    xorq %rax, %rax
    movw %fs, %ax
    pushq %rax
    xorq %rax, %rax
    movw %gs, %ax
    pushq %rax

    /* Load kernel data segment (but DON'T touch GS or FS - they use MSR base!) */
    movw $0x10, %ax
    movw %ax, %ds
    movw %ax, %es
    /* FS intentionally NOT reloaded - must preserve MSR_FS_BASE for TLS support */
    /* GS intentionally NOT reloaded - must preserve GS_BASE MSR setup */

    /* Set interrupt context flag and frame pointer for scheduler.
     * This is critical for exceptions that may terminate threads (e.g., SIGSEGV from
     * page fault). Without this, fut_schedule() uses cooperative switch which doesn't
     * properly handle the exception frame on the stack. */
    movq %rsp, fut_current_frame(%rip)
    movb $1, fut_in_interrupt(%rip)

    /* Align stack to 16 bytes for System V ABI */
    movq %rsp, %rbp
    andq $-16, %rsp

    /* Call C exception handler */
    movq %rbp, %rdi                     /* Pass register state pointer */
    call fut_isr_handler

    /* Clear interrupt context flag and frame pointer */
    movb $0, fut_in_interrupt(%rip)
    movq $0, fut_current_frame(%rip)

    /* Restore stack */
    movq %rbp, %rsp

    /* Pop segment registers (but DON'T restore GS or FS - must preserve MSR bases!) */
    popq %rax            /* Discard saved GS value */
    /* GS intentionally NOT restored - must preserve GS_BASE MSR */
    popq %rax            /* Discard saved FS value */
    /* FS intentionally NOT restored - must preserve MSR_FS_BASE for TLS support */
    popq %rax
    movw %ax, %es
    popq %rax
    movw %ax, %ds

    /* Pop general purpose registers */
    popq %rax
    popq %rbx
    popq %rcx
    popq %rdx
    popq %rsi
    popq %rdi
    popq %rbp
    popq %r8
    popq %r9
    popq %r10
    popq %r11
    popq %r12
    popq %r13
    popq %r14
    popq %r15

    /* Remove error code and vector number */
    addq $16, %rsp

    /* Zero XMM registers before returning to prevent leaking kernel values to userspace.
     * Kernel code (compiled with -O2) may use XMM registers, and per System V ABI they
     * are caller-saved, so we must clean them when returning to userspace. */
    pxor %xmm0, %xmm0
    pxor %xmm1, %xmm1
    pxor %xmm2, %xmm2
    pxor %xmm3, %xmm3
    pxor %xmm4, %xmm4
    pxor %xmm5, %xmm5
    pxor %xmm6, %xmm6
    pxor %xmm7, %xmm7
    pxor %xmm8, %xmm8
    pxor %xmm9, %xmm9
    pxor %xmm10, %xmm10
    pxor %xmm11, %xmm11
    pxor %xmm12, %xmm12
    pxor %xmm13, %xmm13
    pxor %xmm14, %xmm14
    pxor %xmm15, %xmm15

    /* CRITICAL FIX: In 64-bit mode, CPU pushes SS unconditionally, but kernel may
     * run with SS=0 (which works normally but IRETQ may fault when loading it).
     * Fix SS to kernel data segment before IRETQ if returning to kernel mode.
     * Note: CPU-pushed RSP is correct and must NOT be modified. */
    testb $3, 8(%rsp)           /* Test RPL of saved CS (at RIP+8) */
    jnz .isr_common_iretq_user  /* If RPL != 0, returning to user */

    /* Returning to kernel mode - fix up SS only (RSP is correct as pushed by CPU) */
    movq $0x10, 32(%rsp)        /* Store kernel SS (0x10) at SS slot */
    jmp .isr_common_iretq

.isr_common_iretq_user:
    /* Returning to userspace - ensure IF is set so timer can preempt
     * RFLAGS is at RSP+16 in the IRETQ frame */
    orq $0x200, 16(%rsp)        /* Set IF (bit 9) in RFLAGS */

.isr_common_iretq:
    /* Return from interrupt */
    iretq

.size isr_common_stub, . - isr_common_stub

/* Common IRQ stub */
.type irq_common_stub, @function
irq_common_stub:
    /* Push all general purpose registers */
    pushq %r15
    pushq %r14
    pushq %r13
    pushq %r12
    pushq %r11
    pushq %r10
    pushq %r9
    pushq %r8
    pushq %rbp
    pushq %rdi
    pushq %rsi
    pushq %rdx
    pushq %rcx
    pushq %rbx
    pushq %rax

    /* Push segment registers (zero RAX first to avoid garbage in upper bits) */
    xorq %rax, %rax
    movw %ds, %ax
    pushq %rax
    xorq %rax, %rax
    movw %es, %ax
    pushq %rax
    xorq %rax, %rax
    movw %fs, %ax
    pushq %rax
    xorq %rax, %rax
    movw %gs, %ax
    pushq %rax

    /* Load kernel data segment (but DON'T touch GS or FS - they use MSR base!) */
    movw $0x10, %ax
    movw %ax, %ds
    movw %ax, %es
    /* FS intentionally NOT reloaded - must preserve MSR_FS_BASE for TLS support */
    /* GS intentionally NOT reloaded - must preserve GS_BASE MSR setup */

    /* Align stack to 16 bytes for System V ABI */
    movq %rsp, %rbp
    andq $-16, %rsp

    /* Call C IRQ handler */
    movq %rbp, %rdi                     /* Pass register state pointer */
    call fut_irq_handler

    /* Restore stack */
    movq %rbp, %rsp

    /* Pop segment registers (but DON'T restore GS or FS - must preserve MSR bases!) */
    popq %rax            /* Discard saved GS value */
    /* GS intentionally NOT restored - must preserve GS_BASE MSR */
    popq %rax            /* Discard saved FS value */
    /* FS intentionally NOT restored - must preserve MSR_FS_BASE for TLS support */
    popq %rax
    movw %ax, %es
    popq %rax
    movw %ax, %ds

    /* Pop general purpose registers */
    popq %rax
    popq %rbx
    popq %rcx
    popq %rdx
    popq %rsi
    popq %rdi
    popq %rbp
    popq %r8
    popq %r9
    popq %r10
    popq %r11
    popq %r12
    popq %r13
    popq %r14
    popq %r15

    /* Remove error code and vector number */
    addq $16, %rsp

    /* Zero XMM registers before returning to prevent leaking kernel values to userspace.
     * Kernel code (compiled with -O2) may use XMM registers, and per System V ABI they
     * are caller-saved, so we must clean them when returning to userspace. */
    pxor %xmm0, %xmm0
    pxor %xmm1, %xmm1
    pxor %xmm2, %xmm2
    pxor %xmm3, %xmm3
    pxor %xmm4, %xmm4
    pxor %xmm5, %xmm5
    pxor %xmm6, %xmm6
    pxor %xmm7, %xmm7
    pxor %xmm8, %xmm8
    pxor %xmm9, %xmm9
    pxor %xmm10, %xmm10
    pxor %xmm11, %xmm11
    pxor %xmm12, %xmm12
    pxor %xmm13, %xmm13
    pxor %xmm14, %xmm14
    pxor %xmm15, %xmm15

    /* CRITICAL FIX: In 64-bit mode, CPU pushes SS unconditionally, but kernel may
     * run with SS=0 (which works normally but IRETQ may fault when loading it).
     * Fix SS to kernel data segment before IRETQ if returning to kernel mode.
     * Note: CPU-pushed RSP is correct and must NOT be modified. */
    testb $3, 8(%rsp)           /* Test RPL of saved CS (at RIP+8) */
    jnz .irq_common_iretq_user  /* If RPL != 0, returning to user */

    /* Returning to kernel mode - fix up SS only (RSP is correct as pushed by CPU) */
    movq $0x10, 32(%rsp)        /* Store kernel SS (0x10) at SS slot */
    jmp .irq_common_iretq

.irq_common_iretq_user:
    /* Returning to userspace - ensure IF is set so timer can preempt
     * RFLAGS is at RSP+16 in the IRETQ frame */
    orq $0x200, 16(%rsp)        /* Set IF (bit 9) in RFLAGS */

.irq_common_iretq:
    /* Return from interrupt */
    iretq

.size irq_common_stub, . - irq_common_stub

/* Special IRQ0 (timer) handler */
.global irq0_timer
.type irq0_timer, @function
irq0_timer:
    pushq $0                            /* Dummy error code */
    pushq $32                           /* IRQ0 vector */

    /* Push all general purpose registers */
    pushq %r15
    pushq %r14
    pushq %r13
    pushq %r12
    pushq %r11
    pushq %r10
    pushq %r9
    pushq %r8
    pushq %rbp
    pushq %rdi
    pushq %rsi
    pushq %rdx
    pushq %rcx
    pushq %rbx
    pushq %rax

    /* Push segment registers (zero RAX first to avoid garbage in upper bits) */
    xorq %rax, %rax
    movw %ds, %ax
    pushq %rax
    xorq %rax, %rax
    movw %es, %ax
    pushq %rax
    xorq %rax, %rax
    movw %fs, %ax
    pushq %rax
    xorq %rax, %rax
    movw %gs, %ax
    pushq %rax

    /* Load kernel data segment (but DON'T touch GS or FS - they use MSR base!) */
    movw $0x10, %ax
    movw %ax, %ds
    movw %ax, %es
    /* FS intentionally NOT reloaded - must preserve MSR_FS_BASE for TLS support */
    /* GS intentionally NOT reloaded - must preserve GS_BASE MSR setup */

    /* Save interrupt frame pointer before stack alignment */
    movq %rsp, fut_current_frame(%rip)

    /* Align stack to 16 bytes for System V ABI */
    movq %rsp, %rbp
    andq $-16, %rsp

    /* Set interrupt context flag */
    movb $1, fut_in_interrupt(%rip)

    /* Call timer IRQ handler */
    call fut_timer_irq

    /* Clear interrupt context flag */
    movb $0, fut_in_interrupt(%rip)

    /* Clear frame pointer */
    movq $0, fut_current_frame(%rip)

    /* Restore stack */
    movq %rbp, %rsp

    /* Pop segment registers (but DON'T restore GS or FS - must preserve MSR bases!) */
    popq %rax            /* Discard saved GS value */
    /* GS intentionally NOT restored - must preserve GS_BASE MSR */
    popq %rax            /* Discard saved FS value */
    /* FS intentionally NOT restored - must preserve MSR_FS_BASE for TLS support */
    popq %rax
    movw %ax, %es
    popq %rax
    movw %ax, %ds

    /* Pop general purpose registers */
    popq %rax
    popq %rbx
    popq %rcx
    popq %rdx
    popq %rsi
    popq %rdi
    popq %rbp
    popq %r8
    popq %r9
    popq %r10
    popq %r11
    popq %r12
    popq %r13
    popq %r14
    popq %r15

    /* Remove error code and vector number */
    addq $16, %rsp

    /* NOTE: We do NOT zero XMM registers on timer IRQ return!
     * The userspace code may be using XMM registers to hold values (e.g., pointers
     * that GCC moves to XMM temporarily). Zeroing them corrupts user state.
     *
     * For proper security, we should SAVE/RESTORE full FPU/XMM state (FXSAVE/FXRSTOR
     * or XSAVE/XRSTOR) on interrupt entry/exit. For now, rely on the kernel not
     * using XMM registers (compile with -mno-mmx -mno-sse or use kernel_fpu_begin()).
     *
     * Zeroing was causing wl-term crashes where pixels pointer in XMM got zeroed. */

    /* CRITICAL FIX: In 64-bit mode, CPU pushes SS unconditionally, but kernel may
     * run with SS=0 (which works normally but IRETQ may fault when loading it).
     * Fix SS to kernel data segment before IRETQ if returning to kernel mode.
     * Note: CPU-pushed RSP is correct and must NOT be modified. */
    testb $3, 8(%rsp)           /* Test RPL of saved CS (at RIP+8) */
    jnz .irq0_iretq_user        /* If RPL != 0, returning to user */

    /* Returning to kernel mode - fix up SS only (RSP is correct as pushed by CPU) */
    movq $0x10, 32(%rsp)        /* Store kernel SS (0x10) at SS slot */
    jmp .irq0_iretq

.irq0_iretq_user:
    /* Returning to userspace - ensure IF is set so timer can preempt
     * RFLAGS is at RSP+16 in the IRETQ frame */
    orq $0x200, 16(%rsp)        /* Set IF (bit 9) in RFLAGS */

.irq0_iretq:
    /* Return from interrupt */
    iretq

.size irq0_timer, . - irq0_timer

/* Register state structure layout for reference:
 * Offset | Register
 * -------+---------
 * 0      | GS
 * 8      | FS
 * 16     | ES
 * 24     | DS
 * 32     | RAX
 * 40     | RBX
 * 48     | RCX
 * 56     | RDX
 * 64     | RSI
 * 72     | RDI
 * 80     | RBP
 * 88     | R8
 * 96     | R9
 * 104    | R10
 * 112    | R11
 * 120    | R12
 * 128    | R13
 * 136    | R14
 * 144    | R15
 * 152    | Vector number
 * 160    | Error code
 * 168    | RIP
 * 176    | CS
 * 184    | RFLAGS
 * 192    | RSP
 * 200    | SS
 */

/* Mark stack as non-executable */
.section .note.GNU-stack,"",@progbits
