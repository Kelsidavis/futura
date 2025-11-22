/*
 * Futura OS - x86_64 Context Switching
 * Preserves full kernel thread state including SIMD context.
 */

.section .text

/* struct fut_cpu_context layout (see include/arch/x86_64/regs.h)
 *
 *  uint64_t r15, r14, r13, r12, rbx, rbp;
 *  uint64_t rip, rsp, rflags, cs, ss;
 *  uint64_t ds, es, fs, gs;
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
.equ CTX_DS,      88
.equ CTX_ES,      96
.equ CTX_FS,      104
.equ CTX_GS,      112
.equ CTX_RDI,     120
.equ CTX_RSI,     128
.equ CTX_RDX,     136
.equ CTX_RCX,     144
.equ CTX_RAX,     152
.equ CTX_FX,      160

/*
 * fut_switch_context
 *   RDI = previous context pointer (nullable)
 *   RSI = next context pointer (non-null)
 */
.global fut_switch_context
.type fut_switch_context, @function
fut_switch_context:
    /* Debug: Write 'C' to serial port (0x3F8) */
    pushq %rax
    pushq %rdx
    movw $0x3F8, %dx
    movb $'C', %al
    outb %al, %dx
    popq %rdx
    popq %rax

    /* Stash next context pointer in %r11 (scratch) */
    movq %rsi, %r11

    /* Save current context if present */
    testq %rdi, %rdi
    jz 1f

    /* Debug: Write 'S' (saving context) */
    pushq %rax
    pushq %rdx
    movw $0x3F8, %dx
    movb $'S', %al
    outb %al, %dx
    popq %rdx
    popq %rax

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

    /* Note: We don't save segment registers from kernel context
     * They're always kernel segments (0x10) for kernel code, and we
     * restore them explicitly below rather than from saved context
     */

    /* Debug: Write 'F' (before fxsave) */
    pushq %rax
    pushq %rdx
    movw $0x3F8, %dx
    movb $'F', %al
    outb %al, %dx
    popq %rdx
    popq %rax

    leaq CTX_FX(%rdi), %rax
    fxsave64 (%rax)

    /* Debug: Write 'X' (after fxsave) */
    pushq %rax
    pushq %rdx
    movw $0x3F8, %dx
    movb $'X', %al
    outb %al, %dx
    popq %rdx
    popq %rax

1:
    /* Debug: Write 'R' (before fxrstor) */
    pushq %rax
    pushq %rdx
    movw $0x3F8, %dx
    movb $'R', %al
    outb %al, %dx
    popq %rdx
    popq %rax

    /* Restore next context (pointer in %r11) */
    leaq CTX_FX(%r11), %rax
    fxrstor64 (%rax)

    /* Debug: Write 'T' (after fxrstor) */
    pushq %rax
    pushq %rdx
    movw $0x3F8, %dx
    movb $'T', %al
    outb %al, %dx
    popq %rdx
    popq %rax

    movq CTX_RFLAGS(%r11), %rax
    pushq %rax
    popfq

    movq CTX_RSP(%r11), %rsp

    movq CTX_R15(%r11), %r15
    movq CTX_R14(%r11), %r14
    movq CTX_R13(%r11), %r13
    movq CTX_R12(%r11), %r12

    /* For kernel threads, segment registers are always kernel data segment (0x10).
     * In 64-bit mode, these don't affect addressing, but we set them for consistency.
     * Skip explicit restore - they're already set correctly from boot/previous switch.
     */

    /* Restore rbx and rbp */
    movq CTX_RBX(%r11), %rbx
    movq CTX_RBP(%r11), %rbp

    movq CTX_RDI(%r11), %rdi
    movq CTX_RSI(%r11), %rsi
    movq CTX_RDX(%r11), %rdx
    movq CTX_RCX(%r11), %rcx
    movq CTX_RAX(%r11), %rax

    /* Jump to saved RIP using ret for proper stack alignment */
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
 *
 * Thread structure offsets (see include/kernel/fut_thread.h):
 *   +0:   tid (8 bytes)
 *   +8:   task (8 bytes)
 *   +16:  stack_base (8 bytes)
 *   +24:  stack_size (8 bytes)
 *   +32:  alloc_base (8 bytes)
 *   +40:  _padding (8 bytes)
 *   +48:  context (672 bytes)
 *   +720: irq_frame (8 bytes pointer)
 */
.global fut_switch_context_irq
.type fut_switch_context_irq, @function
fut_switch_context_irq:
    /* Save callee-saved registers */
    pushq %rbx
    pushq %r12
    pushq %r13
    pushq %r14
    pushq %r15

    /* Save arguments */
    movq %rdi, %r12         /* r12 = prev */
    movq %rsi, %r13         /* r13 = next */
    movq %rdx, %r14         /* r14 = frame */

    /* Step 1: Save/allocate interrupt frame for prev thread */
    testq %r12, %r12
    jz 1f                   /* Skip if prev is NULL */

    /* Check if prev->irq_frame is NULL (needs allocation) */
    movq 720(%r12), %r15
    testq %r15, %r15
    jnz .save_frame         /* Already allocated, just save */

    /* Allocate frame storage (208 bytes) - call fut_malloc */
    /* Save frame pointer first */
    pushq %r14
    movq $208, %rdi
    call fut_malloc
    popq %r14
    movq %rax, %r15         /* r15 = allocated frame */

    /* Check allocation success */
    testq %r15, %r15
    jz 1f                   /* Skip if allocation failed */

    /* Save pointer */
    movq %r15, 720(%r12)    /* prev->irq_frame = allocated_frame */

.save_frame:
    /* Copy current frame to prev->irq_frame */
    movq %r15, %rdi         /* dest = prev->irq_frame */
    movq %r14, %rsi         /* src = current frame on stack */
    movq $26, %rcx          /* 208 bytes / 8 = 26 qwords */
    cld
    rep movsq

1:
    /* Step 2: Get next thread's saved frame pointer */
    movq 720(%r13), %r11

    /* If next->irq_frame is NULL, construct frame from context */
    testq %r11, %r11
    jnz .restore_saved_frame

    /* Construct interrupt frame from thread context */
    /* Thread structure: context starts at offset 48 */
    /* Context layout: r15(0), r14(8), r13(16), r12(24), rbx(32), rbp(40),
     *                 rip(48), rsp(56), rflags(64), cs(72), ss(80),
     *                 ds(88), es(96), fs(104), gs(112),
     *                 rdi(120), rsi(128), rdx(136), rcx(144), rax(152) */

    leaq 48(%r13), %rsi     /* rsi = &next->context */
    movq %r14, %rdi         /* rdi = interrupt frame on stack */

    /* Copy segment registers (gs, fs, es, ds) */
    movq 112(%rsi), %rax    /* context.gs */
    movq %rax, 0(%rdi)      /* frame->gs */
    movq 104(%rsi), %rax    /* context.fs */
    movq %rax, 8(%rdi)      /* frame->fs */
    movq 96(%rsi), %rax     /* context.es */
    movq %rax, 16(%rdi)     /* frame->es */
    movq 88(%rsi), %rax     /* context.ds */
    movq %rax, 24(%rdi)     /* frame->ds */

    /* Copy general purpose registers */
    movq 152(%rsi), %rax    /* context.rax */
    movq %rax, 32(%rdi)     /* frame->rax */
    movq 32(%rsi), %rax     /* context.rbx */
    movq %rax, 40(%rdi)     /* frame->rbx */
    movq 144(%rsi), %rax    /* context.rcx */
    movq %rax, 48(%rdi)     /* frame->rcx */
    movq 136(%rsi), %rax    /* context.rdx */
    movq %rax, 56(%rdi)     /* frame->rdx */
    movq 128(%rsi), %rax    /* context.rsi */
    movq %rax, 64(%rdi)     /* frame->rsi */
    movq 120(%rsi), %rax    /* context.rdi */
    movq %rax, 72(%rdi)     /* frame->rdi */
    movq 40(%rsi), %rax     /* context.rbp */
    movq %rax, 80(%rdi)     /* frame->rbp */

    /* Copy r8-r15 (set to context values) */
    movq $0, 88(%rdi)       /* frame->r8 = 0 */
    movq $0, 96(%rdi)       /* frame->r9 = 0 */
    movq $0, 104(%rdi)      /* frame->r10 = 0 */
    movq $0, 112(%rdi)      /* frame->r11 = 0 */
    movq 24(%rsi), %rax     /* context.r12 */
    movq %rax, 120(%rdi)    /* frame->r12 */
    movq 16(%rsi), %rax     /* context.r13 */
    movq %rax, 128(%rdi)    /* frame->r13 */
    movq 8(%rsi), %rax      /* context.r14 */
    movq %rax, 136(%rdi)    /* frame->r14 */
    movq 0(%rsi), %rax      /* context.r15 */
    movq %rax, 144(%rdi)    /* frame->r15 */

    /* Set vector and error_code */
    movq $32, 152(%rdi)     /* frame->vector = 32 (IRQ0) */
    movq $0, 160(%rdi)      /* frame->error_code = 0 */

    /* Copy control registers (CPU-pushed values) */
    movq 48(%rsi), %rax     /* context.rip */
    movq %rax, 168(%rdi)    /* frame->rip */
    movq 72(%rsi), %rax     /* context.cs */
    movq %rax, 176(%rdi)    /* frame->cs */
    movq 64(%rsi), %rax     /* context.rflags */
    movq %rax, 184(%rdi)    /* frame->rflags */
    movq 56(%rsi), %rax     /* context.rsp */
    movq %rax, 192(%rdi)    /* frame->rsp */
    movq 80(%rsi), %rax     /* context.ss */
    movq %rax, 200(%rdi)    /* frame->ss */

    jmp 2f

.restore_saved_frame:
    /* Step 3: Copy saved frame to current interrupt frame location */
    movq %r14, %rdi         /* dest = current frame on stack */
    movq %r11, %rsi         /* src = next->irq_frame */
    movq $26, %rcx          /* 208 bytes / 8 = 26 qwords */
    cld
    rep movsq

2:
    /* Step 4: Restore FPU state from next thread's context */
    /* context is at offset 48, fx_area is at offset 160 within context */
    /* So fx_area is at 48 + 160 = 208 */
    leaq 208(%r13), %rax    /* rax = &next->context.fx_area */
    fxrstor64 (%rax)

    /* Restore callee-saved registers */
    popq %r15
    popq %r14
    popq %r13
    popq %r12
    popq %rbx

    /* Step 5: Return - IRET will restore from modified frame */
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

    /* Zero XMM registers before entering userspace to prevent leaking kernel values.
     * GCC -O2 uses XMM registers to store pointers, and garbage values cause crashes. */
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
    movq $672, %rax                     /* sizeof(fut_cpu_context_t) */
    ret

.size fut_context_size, . - fut_context_size

/* Mark stack as non-executable */
.section .note.GNU-stack,"",@progbits
