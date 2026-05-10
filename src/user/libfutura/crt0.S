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

    /* Earliest possible user-mode probe for Gemini Lake bring-up:
     * raw write(1, "[U-START]\\n", 10) via int $0x80 before main(),
     * libc env setup, or allocator usage. */
    mov $1, %rax                  /* SYS_write */
    mov $1, %rdi                  /* fd=stdout */
    lea user_early_msg(%rip), %rsi
    mov $10, %rdx
    int $0x80

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

    /* Gemini Lake bring-up differential test:
     * skip __libc_init_environ() for one build so we can tell whether the
     * first failure happens in early malloc/brk during env setup or later
     * on the explicit init syscalls. main() in /sbin/init does not depend
     * on inherited environment today, so this is safe for diagnosis. */
    /* mov %r12, %rdi */
    /* call __libc_init_environ */

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

.section .rodata
user_early_msg:
    .ascii "[U-START]\n"

/* Mark stack as non-executable to silence linker warnings */
.section .note.GNU-stack, "", @progbits
