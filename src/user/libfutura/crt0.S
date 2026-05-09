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

    /* Compute envp = &argv[argc + 1] and stash it in r12 (callee-
     * saved). r13 holds argv across the call to __libc_init_environ;
     * r12 keeps envp safe so we can pass it as main's third argument
     * without re-reading caller-saved %rdx after the call. */
    mov %rsi, %r13          /* r13 = argv (callee-saved) */
    lea 8(%rsi, %rbx, 8), %r12  /* r12 = argv + (argc + 1) * 8 = envp */

    /* Align stack to 16 bytes (required by x86-64 ABI) */
    and $-16, %rsp

    /* Call __libc_init_environ(envp). r12/r13 stay valid across it. */
    mov %r12, %rdi
    call __libc_init_environ

    /* Set up argc, argv, envp for main call */
    mov %rbx, %rdi          /* argc */
    mov %r13, %rsi          /* argv */
    mov %r12, %rdx          /* envp (preserved across call) */

    /* Call main(argc, argv, envp) */
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

