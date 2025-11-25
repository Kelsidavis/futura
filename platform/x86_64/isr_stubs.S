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
    /* Save RAX first (it contains the syscall number) */
    pushq %rax

    /* Now save CR3 to stack (using RAX as temp register is safe now) */
    movq %cr3, %rax           /* Get current CR3 */
    pushq %rax                /* Save CR3 on stack */

    /* Save remaining registers */
    pushq %rbp
    pushq %rbx
    pushq %r12
    pushq %r13
    pushq %r14
    pushq %r15

    pushq %r9
    pushq %r8
    pushq %r10
    pushq %rdx
    pushq %rsi
    pushq %rdi

    /* Save segment registers (zero RAX first to avoid garbage in upper bits) */
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

    /* Load kernel data segment (but DON'T touch GS - it uses MSR base for per-CPU data!) */
    movw $0x10, %ax
    movw %ax, %ds
    movw %ax, %es
    movw %ax, %fs
    /* GS intentionally NOT reloaded - must preserve GS_BASE MSR setup */

    /* Calculate pointer to interrupt frame (for userspace thread state) */
    /* Stack layout from RSP: GS, FS, ES, DS, RDI, RSI, RDX, R10, R8, R9, R15, R14, R13, R12, RBX, RBP, CR3, RAX, RIP, CS, RFLAGS, RSP, SS */
    /* We pushed: 4 segment regs + 6 arg regs + 6 callee-saved + CR3 + RAX = 18 values */
    /* Frame (RIP) is at: RSP + (18 * 8) = RSP + 144 bytes */
    movq %rsp, %r15
    addq $144, %r15           /* r15 = pointer to CPU-pushed frame (RIP onwards) */

    /* Set global fut_current_frame so sys_fork() can access it */
    movq %r15, fut_current_frame(%rip)

    /* Extract syscall arguments from saved registers */
    /* Stack layout (after all pushes): RSP+0=GS, RSP+8=FS, RSP+16=ES, RSP+24=DS,
     * RSP+32=RDI, RSP+40=RSI, RSP+48=RDX, RSP+56=R10, RSP+64=R8, RSP+72=R9,
     * RSP+80=R15, RSP+88=R14, RSP+96=R13, RSP+104=R12, RSP+112=RBX, RSP+120=RBP,
     * RSP+128=CR3, RSP+136=RAX (syscall number), then RIP/CS/RFLAGS/RSP/SS from CPU */

    /* DEBUG: Print register values before extraction to diagnose syscall parameter corruption */
    movq 136(%rsp), %rax      /* Get syscall number for diagnostics */
    movq %rsp, %r11           /* r11 = stack pointer */

    /* Extract syscall arguments from saved registers
     * Stack layout after all pushes (including segment register pushes):
     * RSP+0=GS, RSP+8=FS, RSP+16=ES, RSP+24=DS,
     * RSP+32=RDI (arg1), RSP+40=RSI (arg2), RSP+48=RDX (arg3),
     * RSP+56=R10 (arg4), RSP+64=R8 (arg5), RSP+72=R9 (arg6),
     * RSP+80=R15, RSP+88=R14, RSP+96=R13, RSP+104=R12, RSP+112=RBX, RSP+120=RBP,
     * RSP+128=CR3, RSP+136=RAX (syscall number), then interrupt frame
     *
     * For x86-64 syscall calling convention, syscall_entry_c expects:
     * RDI = syscall number (param 1)
     * RSI = arg1 from RDI (param 2)
     * RDX = arg2 from RSI (param 3)
     * RCX = arg3 from RDX (param 4)
     * R8 = arg4 from R10 (param 5)
     * R9 = arg5 from R8 (param 6)
     * stack = arg6 from R9, frame_ptr (params 7-8)
     */
    movq 136(%rsp), %rdi      /* rdi = syscall number (param 1) */
    movq 32(%rsp), %rsi       /* rsi = arg1 from saved RDI (param 2) */
    movq 40(%rsp), %rdx       /* rdx = arg2 from saved RSI (param 3) */
    movq 48(%rsp), %rcx       /* rcx = arg3 from saved RDX (param 4) */
    movq 56(%rsp), %r8        /* r8 = arg4 from saved R10 (param 5) */
    movq 64(%rsp), %r9        /* r9 = arg5 from saved R8 (param 6) */
    movq 72(%rsp), %r10       /* r10 = arg6 from saved R9 (will be pushed) */

    /* Note: frame_ptr will be passed as 8th parameter on stack */
    pushq %r15                /* push frame pointer (param 8) */
    pushq %r10                /* push arg6 (param 7 on stack) */

    call syscall_entry_c

    /* Save return value before cleaning up stack */
    movq %rax, %r11           /* Save syscall return value in R11 (callee-saved) */

    addq $16, %rsp            /* remove arg6 and arg7 */

    /* Restore registers in reverse order of how we pushed them */
    /* Stack: 0=GS, 8=FS, 16=ES, 24=DS, 32=RDI, 40=RSI, 48=RDX, 56=R10, 64=R8, 72=R9, 80=R15, 88=R14, 96=R13, 104=R12, 112=RBX, 120=RBP, 128=CR3, 136=RAX */
    popq %rax                 /* Discard saved GS value */
    /* GS intentionally NOT restored - must preserve GS_BASE MSR */
    popq %rax
    movw %ax, %fs             /* Restore user FS */
    popq %rax
    movw %ax, %es             /* Restore user ES */
    popq %rax
    movw %ax, %ds             /* Restore user DS */

    popq %rdi                 /* Restore user RDI */
    popq %rsi                 /* Restore user RSI */
    popq %rdx                 /* Restore user RDX */
    popq %r10                 /* Restore user R10 */
    popq %r8                  /* Restore user R8 */
    popq %r9                  /* Restore user R9 */

    popq %r15
    popq %r14
    popq %r13
    popq %r12
    popq %rbx
    popq %rbp

    /* Stack now has: CR3, RAX, RIP, CS, RFLAGS, RSP, SS */
    /* R11 contains syscall return value - DON'T CLOBBER IT! */

    /* Do NOT restore CR3 here! Switching to user page tables while still in kernel
     * mode would unmap the kernel stack, causing a page fault on the next instruction.
     * The kernel page tables map everything (kernel + user), so we keep them active.
     * The CPU automatically uses user page tables when iretq returns to CPL=3. */
    addq $8, %rsp             /* Skip saved CR3 value */

    /* Now stack has: saved_RAX, RIP, CS, RFLAGS, RSP, SS */
    /* Skip saved RAX and restore syscall return value from R11 */
    addq $8, %rsp             /* Skip over saved RAX without clobbering any register */
    movq %r11, %rax           /* Put syscall return value in RAX */

    /* At this point, stack should have: RIP, CS, RFLAGS, RSP, SS */
    /* All user registers are restored except RAX which has the syscall return value */
    /* CR3 remains set to kernel page tables (which map everything) */

    /* NOTE: We do NOT zero XMM registers on syscall return because the userspace
     * syscall wrapper doesn't declare XMM as clobbered. If we zero them here,
     * GCC-generated code that stores pointers in XMM will crash when it finds NULL.
     * XMM registers must be preserved across syscalls per the calling convention. */

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
 * We need to:
 * 1. Save user context (RIP, RFLAGS, RSP)
 * 2. Switch to kernel stack
 * 3. Call syscall handler
 * 4. Return to user mode via SYSRET
 *
 * Key difference from int 0x80:
 * - CPU does NOT push anything for SYSCALL
 * - We must manually construct the frame and manage stacks
 * - SYSRET requires RIP in RCX and RFLAGS in R11
 */
.global isr_syscall_fastpath
.type isr_syscall_fastpath, @function
isr_syscall_fastpath:
    /* At entry: RCX=user RIP, R11=user RFLAGS, RSP=user stack, RAX=syscall number */

    /* Save user RSP and create frame on user stack first */
    /* We'll construct the interrupt frame manually */
    pushq $0                      /* SS placeholder */
    pushq %rsp                    /* User RSP (will be adjusted by +8) */
    movq %r11, -8(%rsp)           /* RFLAGS at RSP-8 */
    subq $8, %rsp
    pushq %rcx                    /* RIP */

    /* Now we have a basic frame. Save syscall number and all regs */
    pushq %rax                    /* Save syscall number */
    movq %cr3, %rax
    pushq %rax                    /* Save CR3 */

    pushq %rbp
    pushq %rbx
    movq %rsp, %r12               /* Save current RSP (user stack pointer) */
    pushq %r12                    /* Save r12 (will be popped as r12 value) */
    pushq %r13
    pushq %r14
    pushq %r15
    pushq %r9
    pushq %r8
    pushq %r10
    pushq %rdx
    pushq %rsi
    pushq %rdi

    /* Now RBP is probably garbage, but we need to set up for C calling convention */
    movq %rsp, %rbp

    /* Set up arguments for syscall_entry_c */
    movq %rsp, %r15
    addq $112, %r15               /* r15 = pointer to interrupt frame */
    movq %r15, fut_current_frame(%rip)

    /* Extract arguments from saved registers */
    movq 104(%rsp), %rdi          /* RDI: syscall number */
    movq 0(%rsp), %rsi            /* RSI: arg1 (original RDI) */
    movq 8(%rsp), %rdx            /* RDX: arg2 (original RSI) */
    movq 16(%rsp), %rcx           /* RCX: arg3 (original RDX) */
    movq 24(%rsp), %r8            /* R8:  arg4 (original R10) */
    movq 32(%rsp), %r9            /* R9:  arg5 (original R8) */
    movq 40(%rsp), %rax           /* RAX: arg6 (original R9) */

    /* Push arguments for syscall_entry_c in reverse order */
    pushq %r15                    /* arg7: interrupt frame pointer */
    pushq %rax                    /* arg6 */

    /* Call the syscall handler */
    call syscall_entry_c

    /* Save return value */
    movq %rax, %r11               /* Save result in R11 for SYSRET */

    /* Restore stack and context */
    addq $16, %rsp                /* Pop arg6 and arg7 */

    /* Restore all registers except RAX (which has return value) */
    popq %rdi
    popq %rsi
    popq %rdx
    popq %r10
    popq %r8
    popq %r9
    popq %r15
    popq %r14
    popq %r13
    popq %r12
    popq %rbx
    popq %rbp

    /* Pop CR3 and restore it */
    popq %rax
    movq %rax, %cr3

    /* Pop saved syscall number (we don't need it anymore) */
    addq $8, %rsp

    /* Now stack has: RIP, RFLAGS, user_rsp+8, SS
     * We need to extract RIP and RFLAGS and original RSP for SYSRET
     */

    /* Restore the syscall return value to RAX */
    movq %r11, %rax

    /* Pop RIP into RCX for SYSRET */
    popq %rcx

    /* Pop RFLAGS into R11 for SYSRET */
    popq %r11

    /* Skip CS placeholder */
    addq $8, %rsp

    /* Pop user RSP (but don't restore it yet - SYSRET will use RSP)*/
    popq %rsp

    /* Skip SS placeholder */
    addq $8, %rsp

    /* Use SYSRET to return to user mode
     * RCX = return address, R11 = RFLAGS, RSP = user stack
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

    /* Load kernel data segment (but DON'T touch GS - it uses MSR base for per-CPU data!) */
    movw $0x10, %ax
    movw %ax, %ds
    movw %ax, %es
    movw %ax, %fs
    /* GS intentionally NOT reloaded - must preserve GS_BASE MSR setup */

    /* Align stack to 16 bytes for System V ABI */
    movq %rsp, %rbp
    andq $-16, %rsp

    /* Call C exception handler */
    movq %rbp, %rdi                     /* Pass register state pointer */
    call fut_isr_handler

    /* Restore stack */
    movq %rbp, %rsp

    /* Pop segment registers (but DON'T restore GS - must preserve per-CPU setup!) */
    popq %rax            /* Discard saved GS value */
    /* GS intentionally NOT restored - must preserve GS_BASE MSR */
    popq %rax
    movw %ax, %fs
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
    jnz .isr_common_iretq       /* If RPL != 0, returning to user - SS is valid */

    /* Returning to kernel mode - fix up SS only (RSP is correct as pushed by CPU) */
    movq $0x10, 32(%rsp)        /* Store kernel SS (0x10) at SS slot */

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

    /* Load kernel data segment (but DON'T touch GS - it uses MSR base for per-CPU data!) */
    movw $0x10, %ax
    movw %ax, %ds
    movw %ax, %es
    movw %ax, %fs
    /* GS intentionally NOT reloaded - must preserve GS_BASE MSR setup */

    /* Align stack to 16 bytes for System V ABI */
    movq %rsp, %rbp
    andq $-16, %rsp

    /* Call C IRQ handler */
    movq %rbp, %rdi                     /* Pass register state pointer */
    call fut_irq_handler

    /* Restore stack */
    movq %rbp, %rsp

    /* Pop segment registers (but DON'T restore GS - must preserve per-CPU setup!) */
    popq %rax            /* Discard saved GS value */
    /* GS intentionally NOT restored - must preserve GS_BASE MSR */
    popq %rax
    movw %ax, %fs
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
    jnz .irq_common_iretq       /* If RPL != 0, returning to user - SS is valid */

    /* Returning to kernel mode - fix up SS only (RSP is correct as pushed by CPU) */
    movq $0x10, 32(%rsp)        /* Store kernel SS (0x10) at SS slot */

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

    /* Load kernel data segment (but DON'T touch GS - it uses MSR base for per-CPU data!) */
    movw $0x10, %ax
    movw %ax, %ds
    movw %ax, %es
    movw %ax, %fs
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

    /* Pop segment registers (but DON'T restore GS - must preserve per-CPU setup!) */
    popq %rax            /* Discard saved GS value */
    /* GS intentionally NOT restored - must preserve GS_BASE MSR */
    popq %rax
    movw %ax, %fs
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
    jnz .irq0_iretq             /* If RPL != 0, returning to user - SS is valid */

    /* Returning to kernel mode - fix up SS only (RSP is correct as pushed by CPU) */
    movq $0x10, 32(%rsp)        /* Store kernel SS (0x10) at SS slot */

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
