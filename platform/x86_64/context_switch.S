/*
 * Futura OS - x86_64 Context Switching
 * Copyright (C) 2025 Futura OS Project
 *
 * 64-bit context switching with callee-saved register preservation
 */

.section .text

/* Context structure offsets (matching fut_cpu_context_t in regs.h) */
/* struct fut_cpu_context {
 *     uint64_t rbx, rbp, r12, r13, r14, r15;
 *     uint64_t rsp, rip, rflags, cs, ss;
 *     void *fpu_state;
 * } */
.equ CTX_RBX,     0
.equ CTX_RBP,     8
.equ CTX_R12,     16
.equ CTX_R13,     24
.equ CTX_R14,     32
.equ CTX_R15,     40
.equ CTX_RSP,     48
.equ CTX_RIP,     56
.equ CTX_RFLAGS,  64
.equ CTX_CS,      72
.equ CTX_SS,      80
.equ CTX_FXSAVE,  88

/*
 * fut_switch_context - Switch from current context to next context
 *
 * System V AMD64 ABI calling convention:
 * RDI = pointer to current context (fut_cpu_context_t *current)
 * RSI = pointer to next context (fut_cpu_context_t *next)
 *
 * Preserves: RBX, RSP, RBP, R12-R15 (callee-saved)
 */
.global fut_switch_context
.type fut_switch_context, @function
fut_switch_context:
    /* Check if current context is NULL (first time) */
    testq %rdi, %rdi
    jz restore_only

    /* Save current context (pointed to by RDI) */

    /* Save callee-saved general purpose registers */
    movq %rbx, CTX_RBX(%rdi)
    movq %rbp, CTX_RBP(%rdi)
    movq %r12, CTX_R12(%rdi)
    movq %r13, CTX_R13(%rdi)
    movq %r14, CTX_R14(%rdi)
    movq %r15, CTX_R15(%rdi)

    /* Save return address as RIP */
    movq (%rsp), %rax                   /* Get return address from stack */
    movq %rax, CTX_RIP(%rdi)

    /* Save stack pointer (after return address is popped) */
    leaq 8(%rsp), %rax                  /* RSP after return */
    movq %rax, CTX_RSP(%rdi)

    /* Save RFLAGS */
    pushfq
    popq %rax
    movq %rax, CTX_RFLAGS(%rdi)

    /* Save segment registers */
    movq $0x08, %rax                    /* Kernel code segment */
    movq %rax, CTX_CS(%rdi)
    movq $0x10, %rax                    /* Kernel data segment */
    movq %rax, CTX_SS(%rdi)

    /* Save FPU/SSE state (if fpu_state pointer is valid) */
    movq CTX_FXSAVE(%rdi), %rax
    testq %rax, %rax
    jz restore_only
    fxsave64 (%rax)

restore_only:
    /* Restore next context (pointed to by RSI) */

    /* Restore FPU/SSE state (if fpu_state pointer is valid) */
    movq CTX_FXSAVE(%rsi), %rax
    testq %rax, %rax
    jz skip_fxrstor
    fxrstor64 (%rax)

skip_fxrstor:
    /* Restore RFLAGS */
    movq CTX_RFLAGS(%rsi), %rax
    pushq %rax
    popfq

    /* Restore stack pointer */
    movq CTX_RSP(%rsi), %rsp

    /* Restore callee-saved general purpose registers */
    movq CTX_RBX(%rsi), %rbx
    movq CTX_RBP(%rsi), %rbp
    movq CTX_R12(%rsi), %r12
    movq CTX_R13(%rsi), %r13
    movq CTX_R14(%rsi), %r14
    movq CTX_R15(%rsi), %r15

    /* Push return address and return to it */
    pushq CTX_RIP(%rsi)
    ret

.size fut_switch_context, . - fut_switch_context

/*
 * fut_switch_context_irq - IRQ-safe context switch using IRET
 *
 * System V AMD64 ABI:
 * RDI = pointer to previous thread (fut_thread_t *prev)
 * RSI = pointer to next thread (fut_thread_t *next)
 * RDX = pointer to interrupt frame (fut_interrupt_frame_t *frame)
 *
 * This function modifies the interrupt frame to return to the next thread
 * and never returns directly - execution continues via IRET in the ISR.
 */
.global fut_switch_context_irq
.type fut_switch_context_irq, @function
fut_switch_context_irq:
    /* Phase 1: Stub implementation */
    /* Future: Implement IRQ-safe context switching via IRET frame manipulation */
    /* For now, just return and let the IRQ handler continue normally */
    ret

.size fut_switch_context_irq, . - fut_switch_context_irq

/*
 * fut_init_context - Initialize a new task context
 *
 * System V AMD64 ABI:
 * RDI = pointer to context (fut_cpu_context_t *ctx)
 * RSI = stack pointer (void *stack_top)
 * RDX = entry point (void (*entry)(void *))
 * RCX = argument to pass (void *arg)
 */
.global fut_init_context
.type fut_init_context, @function
fut_init_context:
    /* Clear callee-saved registers */
    movq $0, CTX_RBX(%rdi)
    movq $0, CTX_RBP(%rdi)
    movq $0, CTX_R12(%rdi)
    movq $0, CTX_R13(%rdi)
    movq $0, CTX_R14(%rdi)
    movq $0, CTX_R15(%rdi)

    /* Set up stack pointer (16-byte aligned) */
    movq %rsi, %rax
    andq $-16, %rax                     /* Align to 16 bytes */
    movq %rax, CTX_RSP(%rdi)

    /* Set up entry point as RIP */
    movq %rdx, CTX_RIP(%rdi)

    /* Set up RFLAGS with interrupts enabled */
    movq $0x200, CTX_RFLAGS(%rdi)       /* IF flag set */

    /* Set up code segment */
    movq $0x08, CTX_CS(%rdi)            /* Kernel code segment */

    /* Set up stack segment */
    movq $0x10, CTX_SS(%rdi)            /* Kernel data segment */

    /* Store argument in a register that will be preserved */
    /* We'll use R12 to pass the argument to the entry point */
    movq %rcx, CTX_R12(%rdi)

    /* FPU state pointer is initialized to NULL by default */
    movq $0, CTX_FXSAVE(%rdi)

    ret

.size fut_init_context, . - fut_init_context

/*
 * Thread entry trampoline - receives argument in R12
 * This is needed because context switch restores R12, allowing us to pass an argument
 */
.global fut_thread_entry_trampoline
.type fut_thread_entry_trampoline, @function
fut_thread_entry_trampoline:
    /* Move argument from R12 to RDI (first parameter) */
    movq %r12, %rdi

    /* Call the actual entry point stored in R13 */
    callq *%r13

    /* If entry point returns, terminate thread */
    /* Future: Call thread_exit() or similar */
1:
    cli
    hlt
    jmp 1b

.size fut_thread_entry_trampoline, . - fut_thread_entry_trampoline

/*
 * fut_get_rsp - Get current stack pointer
 *
 * Returns: Current RSP value in RAX
 */
.global fut_get_rsp
.type fut_get_rsp, @function
fut_get_rsp:
    movq %rsp, %rax
    ret

.size fut_get_rsp, . - fut_get_rsp

/*
 * fut_get_rbp - Get current base pointer
 *
 * Returns: Current RBP value in RAX
 */
.global fut_get_rbp
.type fut_get_rbp, @function
fut_get_rbp:
    movq %rbp, %rax
    ret

.size fut_get_rbp, . - fut_get_rbp

/*
 * fut_set_kernel_stack - Set kernel stack for interrupt handling
 *
 * System V AMD64 ABI:
 * RDI = new kernel stack pointer
 */
.global fut_set_kernel_stack
.type fut_set_kernel_stack, @function
fut_set_kernel_stack:
    /* This would update TSS RSP0 in a full implementation */
    /* For now, just update RSP directly */
    movq %rdi, %rsp
    ret

.size fut_set_kernel_stack, . - fut_set_kernel_stack

/*
 * fut_idle - Halt CPU until next interrupt
 */
.global fut_idle
.type fut_idle, @function
fut_idle:
    hlt
    ret

.size fut_idle, . - fut_idle

/*
 * fut_enter_usermode - Enter user mode (ring 3)
 *
 * System V AMD64 ABI:
 * RDI = user entry point
 * RSI = user stack pointer
 */
.global fut_enter_usermode
.type fut_enter_usermode, @function
fut_enter_usermode:
    /* Disable interrupts during transition */
    cli

    /* Set up IRET frame for user mode */
    pushq $0x20 | 3                     /* User data segment (SS) with RPL=3 */
    pushq %rsi                          /* User stack pointer (RSP) */
    pushq $0x200                        /* RFLAGS (IF=1) */
    pushq $0x18 | 3                     /* User code segment (CS) with RPL=3 */
    pushq %rdi                          /* User entry point (RIP) */

    /* Clear all registers for security */
    xorq %rax, %rax
    xorq %rbx, %rbx
    xorq %rcx, %rcx
    xorq %rdx, %rdx
    xorq %rsi, %rsi
    xorq %rdi, %rdi
    xorq %rbp, %rbp
    xorq %r8, %r8
    xorq %r9, %r9
    xorq %r10, %r10
    xorq %r11, %r11
    xorq %r12, %r12
    xorq %r13, %r13
    xorq %r14, %r14
    xorq %r15, %r15

    /* Set user data segments */
    movw $(0x20 | 3), %ax
    movw %ax, %ds
    movw %ax, %es
    movw %ax, %fs
    movw %ax, %gs

    /* Execute IRET to enter user mode */
    iretq

.size fut_enter_usermode, . - fut_enter_usermode

/*
 * fut_context_size - Return size of context structure
 *
 * Returns: Size in RAX
 */
.global fut_context_size
.type fut_context_size, @function
fut_context_size:
    movq $96, %rax                      /* sizeof(fut_cpu_context_t) */
    ret

.size fut_context_size, . - fut_context_size

/* Mark stack as non-executable */
.section .note.GNU-stack,"",@progbits
