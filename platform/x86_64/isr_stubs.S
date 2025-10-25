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

    /* Calculate pointer to interrupt frame (for userspace thread state) */
    /* Stack layout from RSP: RDI, RSI, RDX, R10, R8, R9, R15, R14, R13, R12, RBX, RBP, CR3, RAX, RIP, CS, RFLAGS, RSP, SS */
    /* We pushed: 6 arg regs + 6 callee-saved + CR3 + RAX = 14 values */
    /* Frame (RIP) is at: RSP + (14 * 8) = RSP + 112 bytes */
    movq %rsp, %r15
    addq $112, %r15           /* r15 = pointer to interrupt frame (RIP) */

    /* Extract syscall arguments from saved registers */
    /* Stack: 0=RDI, 8=RSI, 16=RDX, 24=R10, 32=R8, 40=R9, 48=R15, 56=R14, 64=R13, 72=R12, 80=RBX, 88=RBP, 96=CR3, 104=RAX, 112=RIP... */
    movq 104(%rsp), %rdi      /* syscall number from saved RAX */
    movq 0(%rsp), %rsi        /* arg1 from RDI */
    movq 8(%rsp), %rdx        /* arg2 from RSI */
    movq 16(%rsp), %rcx       /* arg3 from RDX */
    movq 24(%rsp), %r8        /* arg4 from R10 */
    movq 32(%rsp), %r9        /* arg5 from R8 */
    movq 40(%rsp), %r11       /* arg6 from R9 */
    pushq %r15                /* arg7: interrupt frame pointer (push FIRST) */
    pushq %r11                /* arg6 (push SECOND, closer to RSP) */

    call syscall_entry_c

    /* Save return value before cleaning up stack */
    movq %rax, %r11           /* Save syscall return value in R11 (callee-saved) */

    addq $16, %rsp            /* remove arg6 and arg7 */

    /* Restore registers in reverse order of how we pushed them */
    /* Stack: 0=RDI, 8=RSI, 16=RDX, 24=R10, 32=R8, 40=R9, 48=R15, 56=R14, 64=R13, 72=R12, 80=RBX, 88=RBP, 96=CR3, 104=RAX */
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

    /* Restore CR3 - use RAX as scratch since we'll overwrite it anyway */
    /* Writing the same CR3 value is harmless (CPU optimizes it) */
    popq %rax                 /* Load saved CR3 into RAX (temp) */
    movq %rax, %cr3           /* Restore user CR3 (TLB flush if value changed) */

    /* Now stack has: saved_RAX, RIP, CS, RFLAGS, RSP, SS */
    /* Skip saved RAX and restore syscall return value from R11 */
    addq $8, %rsp             /* Skip over saved RAX without clobbering any register */
    movq %r11, %rax           /* Put syscall return value in RAX */

    /* At this point, stack should have: RIP, CS, RFLAGS, RSP, SS */
    /* All user registers are restored except RAX which has the syscall return value */
    /* CR3 is restored to user page tables */

    /* Zero XMM registers before returning to userspace.
     * The kernel (compiled with -O2) may have used XMM registers during the syscall,
     * leaving garbage values that userspace code might interpret as pointers.
     * Per System V ABI, XMM registers are caller-saved, so we must clean them. */
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

    iretq
.size isr_syscall_int80_stub, . - isr_syscall_int80_stub

.global isr128
.set isr128, isr_syscall_int80_stub

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

    /* Push segment registers */
    movw %ds, %ax
    pushq %rax
    movw %es, %ax
    pushq %rax
    movw %fs, %ax
    pushq %rax
    movw %gs, %ax
    pushq %rax

    /* Load kernel data segment */
    movw $0x10, %ax
    movw %ax, %ds
    movw %ax, %es
    movw %ax, %fs
    movw %ax, %gs

    /* Align stack to 16 bytes for System V ABI */
    movq %rsp, %rbp
    andq $-16, %rsp

    /* Call C exception handler */
    movq %rbp, %rdi                     /* Pass register state pointer */
    call fut_isr_handler

    /* Restore stack */
    movq %rbp, %rsp

    /* Pop segment registers */
    popq %rax
    movw %ax, %gs
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

    /* Push segment registers */
    movw %ds, %ax
    pushq %rax
    movw %es, %ax
    pushq %rax
    movw %fs, %ax
    pushq %rax
    movw %gs, %ax
    pushq %rax

    /* Load kernel data segment */
    movw $0x10, %ax
    movw %ax, %ds
    movw %ax, %es
    movw %ax, %fs
    movw %ax, %gs

    /* Align stack to 16 bytes for System V ABI */
    movq %rsp, %rbp
    andq $-16, %rsp

    /* Call C IRQ handler */
    movq %rbp, %rdi                     /* Pass register state pointer */
    call fut_irq_handler

    /* Restore stack */
    movq %rbp, %rsp

    /* Pop segment registers */
    popq %rax
    movw %ax, %gs
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

    /* Push segment registers */
    movw %ds, %ax
    pushq %rax
    movw %es, %ax
    pushq %rax
    movw %fs, %ax
    pushq %rax
    movw %gs, %ax
    pushq %rax

    /* Load kernel data segment */
    movw $0x10, %ax
    movw %ax, %ds
    movw %ax, %es
    movw %ax, %fs
    movw %ax, %gs

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

    /* Pop segment registers */
    popq %rax
    movw %ax, %gs
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
