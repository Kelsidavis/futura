/* SPDX-License-Identifier: MPL-2.0 */
/*
 * user_iretq.S - Pure assembly IRETQ to userspace
 *
 * This is in a separate assembly file to avoid compiler code generation issues.
 */

.section .text

/*
 * void fut_do_user_iretq(uint64_t entry, uint64_t stack, uint64_t argc, uint64_t argv);
 *
 * Arguments (System V ABI):
 *   rdi = entry point (RIP)
 *   rsi = user stack (RSP)
 *   rdx = argc
 *   rcx = argv
 *
 * CRITICAL: This function must execute atomically without interruption.
 * We disable interrupts IMMEDIATELY and keep them disabled until IRETQ.
 * If a timer interrupt fires while we're loading user segments, it could
 * corrupt the segment register state and cause crashes.
 */
.global fut_do_user_iretq
.type fut_do_user_iretq, @function
fut_do_user_iretq:
    /* CRITICAL: Disable interrupts FIRST, before touching anything!
     * This must be the very first instruction to prevent timer interrupts
     * from firing while we're in a transitional state. */
    cli

    /* Move arguments to temporary registers */
    movq %rdi, %r11                     /* r11 = entry (RIP) */
    movq %rsi, %r10                     /* r10 = user stack (RSP) */
    movq %rdx, %rdi                     /* rdi = argc (first user arg) */
    movq %rcx, %rsi                     /* rsi = argv (second user arg) */

    /* Build IRETQ frame on stack
     * Stack layout (growing down):
     *   [SS]     = 0x23 (user data selector)
     *   [RSP]    = user stack pointer
     *   [RFLAGS] = 0x202 (IF | reserved bit 1)
     *   [CS]     = 0x1b (user code selector)
     *   [RIP]    = entry point
     */
    pushq $0x23                         /* SS = USER_DATA_SELECTOR (0x20|3) */
    pushq %r10                          /* RSP = user stack */
    pushq $0x202                        /* RFLAGS = IF set, reserved bit 1 */
    pushq $0x1b                         /* CS = USER_CODE_SELECTOR (0x18|3) */
    pushq %r11                          /* RIP = entry point */

    /* Debug: Write 'Z' just before IRETQ */
    pushq %rax
    pushq %rdx
    movw $0x3F8, %dx
    movb $'Z', %al
    outb %al, %dx
    popq %rdx
    popq %rax

    /* Zero unused registers for clean userspace entry */
    xorq %rax, %rax
    xorq %rbx, %rbx
    xorq %rcx, %rcx
    xorq %rdx, %rdx
    xorq %r8, %r8
    xorq %r9, %r9
    xorq %r10, %r10
    xorq %r11, %r11
    xorq %r12, %r12
    xorq %r13, %r13
    xorq %r14, %r14
    xorq %r15, %r15
    xorq %rbp, %rbp

    /* Zero XMM/SSE registers to prevent uninitialized pointer usage
     * The shell is compiled with -O2 which uses XMM registers for optimization.
     * If these aren't zeroed, the compiler-generated code may use them as pointers
     * and dereference garbage/NULL values, causing page faults. */
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

    /* Debug: Write '!' just before IRETQ - but rax/rdx are now zero!
     * Load them again after zeroing */
    movw $0x3F8, %dx
    movb $'!', %al
    outb %al, %dx

    /* Debug: Check SS before loading segments */
    movb $'S', %al
    outb %al, %dx
    movw %ss, %ax
    movb %ah, %al
    outb %al, %dx
    movw %ss, %ax
    /* AL already has low byte */
    outb %al, %dx

    /* Set user data segments for ring transition
     * IRETQ will validate that all segment registers have DPL >= CPL
     * User code has CPL=3, so we need user data selectors with DPL=3 (0x23)
     * Without this, IRETQ will cause a General Protection Fault #13 */
    movw $0x23, %ax             /* User data selector (0x20|3) */
    movw %ax, %ds
    movw %ax, %es
    movw %ax, %fs
    /* DON'T load GS - it uses MSR for per-CPU data! */

    /* Debug: Check SS after loading segments */
    movw $0x3F8, %dx
    movb $'T', %al
    outb %al, %dx
    movw %ss, %ax
    movb %ah, %al
    outb %al, %dx
    movw %ss, %ax
    /* AL already has low byte */
    outb %al, %dx

    /* Return to userspace - this never returns */
    iretq

    /* Should NEVER reach here - if we do, write '@' to serial */
    movw $0x3F8, %dx
    movb $'@', %al
    outb %al, %dx

    /* Illegal instruction to halt */
    ud2
