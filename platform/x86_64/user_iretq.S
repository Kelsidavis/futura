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
 */
.global fut_do_user_iretq
.type fut_do_user_iretq, @function
fut_do_user_iretq:
    /* Disable interrupts before building IRETQ frame */
    cli

    /* Build IRETQ frame on stack
     * Arguments (System V ABI):
     *   rdi = entry point (RIP)
     *   rsi = user stack (RSP)
     *   rdx = argc
     *   rcx = argv
     */

    /* Move arguments to temporary registers */
    movq %rdi, %r11                     /* r11 = entry (RIP) */
    movq %rsi, %r10                     /* r10 = user stack (RSP) */
    movq %rdx, %rdi                     /* rdi = argc (first user arg) */
    movq %rcx, %rsi                     /* rsi = argv (second user arg) */

    /* Build IRETQ frame */
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

    /* Debug: Write '!' just before IRETQ - but rax/rdx are now zero!
     * Load them again after zeroing */
    movw $0x3F8, %dx
    movb $'!', %al
    outb %al, %dx

    /* Return to userspace - this never returns */
    iretq

    /* Should NEVER reach here - if we do, write '@' to serial */
    movw $0x3F8, %dx
    movb $'@', %al
    outb %al, %dx

    /* Illegal instruction to halt */
    ud2
