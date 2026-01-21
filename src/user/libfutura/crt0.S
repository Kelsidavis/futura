/* crt0.S - C Runtime Startup for Futura OS Userland (x86-64)
 *
 * Copyright (c) 2025 Kelsi Davis
 * Licensed under the MPL v2.0 — see LICENSE for details.
 *
 * This is the entry point for all userland programs.
 * Sets up the execution environment and calls main().
 */

.section .text
.global _start

_start:
    /* Clear frame pointer for stack unwinding */
    xor %rbp, %rbp

    /* Stack layout when we start:
     * rsp+0:  argc
     * rsp+8:  argv[0]
     * rsp+16: argv[1]
     * ...
     * NULL
     * envp[0]
     * envp[1]
     * ...
     * NULL
     */

    /* Pop argc into %rdi (first argument) */
    pop %rdi

    /* argv is now at %rsp, put it in %rsi (second argument) */
    mov %rsp, %rsi

    /* Save argc in a callee-saved register (rbx) for use after __libc_init_environ */
    mov %rdi, %rbx

    /* Find envp (skip past argv array until we hit NULL) */
    mov %rsi, %rdx          /* Start with argv */
    mov %rdi, %rcx          /* argc counter */
    inc %rcx                /* +1 for the NULL terminator */
    shl $3, %rcx            /* multiply by 8 (pointer size) */
    add %rcx, %rdx          /* rdx now points to envp */

    /* Align stack to 16 bytes (required by x86-64 ABI) */
    and $-16, %rsp

    /* Call __libc_init_environ(envp) to initialize the environ global */
    /* envp is in %rdx, so move it to %rdi (first argument) */
    mov %rdx, %rdi
    call __libc_init_environ

    /* Restore argc from rbx and argv from rsi for main call */
    mov %rbx, %rdi          /* argc back in rdi */
    /* argv is still in rsi */

    /* Call main(argc, argv) */
    call main

    /* main() returned, %rax contains exit code */
    mov %rax, %rdi
    call exit

    /* Should never reach here */
    ud2

/* exit() system call wrapper */
.global exit
exit:
    /* Phase 3: Would send EXIT message to posixd via FIPC
     * For now, just halt
     */
    mov $60, %rax           /* exit syscall (fallback) */
    int $0x80               /* Use int 0x80, not syscall instruction */
    ud2                     /* unreachable */

/* Mark stack as non-executable to silence linker warnings */
.section .note.GNU-stack, "", @progbits
