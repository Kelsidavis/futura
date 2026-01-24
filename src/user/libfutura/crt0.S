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
    /* EARLY DEBUG: Write marker to fd=1 to confirm _start reached (userspace)
     * Uses int 0x80 syscall - this is the earliest possible userspace output.
     * This should appear after BCDE markers in kernel logs if syscalls work. */
    mov $1, %rax            /* SYS_write = 1 */
    mov $1, %rdi            /* fd = stdout */
    lea crt0_early_msg(%rip), %rsi  /* buf = message */
    mov $crt0_early_msg_len, %rdx   /* count */
    int $0x80

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

    /* Debug: emit marker if argv[0] matches /sbin/futura-wayland */
    mov %rsi, %r12          /* Save argv pointer */
    mov (%r12), %rdi        /* argv[0] */
    test %rdi, %rdi
    je 1f
    lea fw_path(%rip), %rsi
0:
    movzbq (%rdi), %rcx
    movzbq (%rsi), %rdx
    cmp %rcx, %rdx
    jne 1f
    test %rcx, %rcx
    je 2f
    inc %rdi
    inc %rsi
    jmp 0b
2:
    mov $1, %rax            /* SYS_write */
    mov $1, %rdi            /* fd=stdout */
    lea fw_msg(%rip), %rsi
    mov $fw_msg_len, %rdx
    int $0x80
1:
    mov %r12, %rsi          /* Restore argv pointer */

    /* Find envp (skip past argv array until we hit NULL) */
    mov %rsi, %rdx          /* Start with argv */
    mov %rbx, %rcx          /* argc counter (rbx has saved argc from line 45) */
    inc %rcx                /* +1 for the NULL terminator */
    shl $3, %rcx            /* multiply by 8 (pointer size) */
    add %rcx, %rdx          /* rdx now points to envp */

    /* Align stack to 16 bytes (required by x86-64 ABI) */
    and $-16, %rsp

    /* Save argv to a callee-saved register before calling __libc_init_environ */
    mov %rsi, %r13          /* r13 = argv (callee-saved, preserved across calls) */

    /* Call __libc_init_environ(envp) to initialize the environ global */
    /* envp is in %rdx, so move it to %rdi (first argument) */
    mov %rdx, %rdi
    call __libc_init_environ

    /* Restore argc and argv for main call */
    mov %rbx, %rdi          /* argc (from rbx, saved earlier) */
    mov %r13, %rsi          /* argv (from r13, saved above) */

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

/* Debug strings */
.section .rodata
crt0_early_msg:
    .asciz "[CRT0] _start reached\n"
    .equ crt0_early_msg_len, . - crt0_early_msg - 1
fw_path:
    .asciz "/sbin/futura-wayland"
fw_msg:
    .asciz "[COMPOSITOR-BOOT] _start reached\n"
    .equ fw_msg_len, . - fw_msg - 1
