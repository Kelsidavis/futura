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

    /* Find envp (skip past argv array until we hit NULL) */
    mov %rsi, %rdx          /* Start with argv */
    mov %rdi, %rcx          /* argc counter */
    inc %rcx                /* +1 for the NULL terminator */
    shl $3, %rcx            /* multiply by 8 (pointer size) */
    add %rcx, %rdx          /* rdx now points to envp */

    /* Align stack to 16 bytes (required by x86-64 ABI) */
    and $-16, %rsp

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
    syscall
    ud2                     /* unreachable */
