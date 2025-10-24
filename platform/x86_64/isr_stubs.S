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
.global isr_syscall_int80_stub
.type isr_syscall_int80_stub, @function
isr_syscall_int80_stub:
    /* Save all registers that might contain syscall arguments */
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
    pushq %rax

    /* Extract syscall arguments from saved registers */
    movq 0(%rsp), %rdi        /* syscall number from RAX */
    movq 8(%rsp), %rsi        /* arg1 from RDI */
    movq 16(%rsp), %rdx       /* arg2 from RSI */
    movq 24(%rsp), %rcx       /* arg3 from RDX */
    movq 32(%rsp), %r8        /* arg4 from R10 */
    movq 40(%rsp), %r9        /* arg5 from R8 */
    movq 48(%rsp), %r11       /* arg6 from R9 */
    pushq %r11

    call syscall_entry_c

    addq $8, %rsp             /* remove arg6 */
    addq $56, %rsp            /* remove saved argument registers */

    popq %r15
    popq %r14
    popq %r13
    popq %r12
    popq %rbx
    popq %rbp

    /* At this point, stack should have: RIP, CS, RFLAGS, RSP, SS */
    /* Verify CS selector is userspace (0x1B for user code in GDT) */
    movq 8(%rsp), %rax        /* Load CS from stack */
    cmpq $0x1B, %rax          /* Check if it's user CS */
    je 1f                      /* If correct, continue */

    /* CS is wrong - this is a bug, halt for debugging */
    cli
    hlt
1:
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

    /* Align stack to 16 bytes for System V ABI */
    movq %rsp, %rbp
    andq $-16, %rsp

    /* Set interrupt context flag */
    movb $1, fut_in_interrupt(%rip)

    /* Call timer IRQ handler */
    call fut_timer_irq

    /* Clear interrupt context flag */
    movb $0, fut_in_interrupt(%rip)

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
