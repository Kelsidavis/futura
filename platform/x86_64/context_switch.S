/*
 * Futura OS - x86_64 Context Switching
 * Preserves full kernel thread state including SIMD context.
 */

.section .text

/* struct fut_cpu_context layout (see include/arch/x86_64/regs.h)
 *
 *  uint64_t r15, r14, r13, r12, rbx, rbp;
 *  uint64_t rip, rsp, rflags, cs, ss;
 *  uint64_t rdi, rsi, rdx, rcx, rax;
 *  uint8_t  fx_area[512];
 */
.equ CTX_R15,     0
.equ CTX_R14,     8
.equ CTX_R13,     16
.equ CTX_R12,     24
.equ CTX_RBX,     32
.equ CTX_RBP,     40
.equ CTX_RIP,     48
.equ CTX_RSP,     56
.equ CTX_RFLAGS,  64
.equ CTX_CS,      72
.equ CTX_SS,      80
.equ CTX_RDI,     88
.equ CTX_RSI,     96
.equ CTX_RDX,     104
.equ CTX_RCX,     112
.equ CTX_RAX,     120
.equ CTX_FX,      128

/*
 * fut_switch_context
 *   RDI = previous context pointer (nullable)
 *   RSI = next context pointer (non-null)
 */
.global fut_switch_context
.type fut_switch_context, @function
fut_switch_context:
    /* Stash next context pointer in %r11 (scratch) */
    movq %rsi, %r11

    /* Save current context if present */
    testq %rdi, %rdi
    jz 1f

    movq %r15, CTX_R15(%rdi)
    movq %r14, CTX_R14(%rdi)
    movq %r13, CTX_R13(%rdi)
    movq %r12, CTX_R12(%rdi)
    movq %rbx, CTX_RBX(%rdi)
    movq %rbp, CTX_RBP(%rdi)

    movq (%rsp), %rax
    movq %rax, CTX_RIP(%rdi)
    leaq 8(%rsp), %rax
    movq %rax, CTX_RSP(%rdi)

    pushfq
    popq %rax
    movq %rax, CTX_RFLAGS(%rdi)

    movq $0x08, %rax
    movq %rax, CTX_CS(%rdi)
    movq $0x10, %rax
    movq %rax, CTX_SS(%rdi)

    leaq CTX_FX(%rdi), %rax
    fxsave64 (%rax)

1:
    /* Restore next context (pointer in %r11) */
    leaq CTX_FX(%r11), %rax
    fxrstor64 (%rax)

    movq CTX_RFLAGS(%r11), %rax
    pushq %rax
    popfq

    movq CTX_RSP(%r11), %rsp

    movq CTX_R15(%r11), %r15
    movq CTX_R14(%r11), %r14
    movq CTX_R13(%r11), %r13
    movq CTX_R12(%r11), %r12
    movq CTX_RBX(%r11), %rbx
    movq CTX_RBP(%r11), %rbp

    movq CTX_RDI(%r11), %rdi
    movq CTX_RSI(%r11), %rsi
    movq CTX_RDX(%r11), %rdx
    movq CTX_RCX(%r11), %rcx
    movq CTX_RAX(%r11), %rax

    movq CTX_RIP(%r11), %r10
    pushq %r10
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
    movq $640, %rax                     /* sizeof(fut_cpu_context_t) */
    ret

.size fut_context_size, . - fut_context_size

/* Mark stack as non-executable */
.section .note.GNU-stack,"",@progbits
