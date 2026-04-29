/* crt0_arm64.S - C Runtime Startup for Futura OS Userland (ARM64)
 *
 * Copyright (c) 2025 Kelsi Davis
 * Licensed under the MPL v2.0 — see LICENSE for details.
 *
 * This is the entry point for all userland programs on ARM64.
 * Sets up the execution environment and calls main().
 */

.section .text
.global _start

_start:
    /* Clear frame pointer for stack unwinding */
    mov x29, #0

    /* Stack layout when we start (from kernel/exec/elf64.c:1366):
     * sp+0:  argc
     * sp+8:  argv[0]
     * sp+16: argv[1]
     * ...
     * NULL
     * envp[0]
     * envp[1]
     * ...
     * NULL
     */

    /* Load argc from stack into x19 (callee-saved register) */
    ldr x19, [sp]

    /* Calculate argv pointer (sp + 8) and save to x20 (callee-saved) */
    add x20, sp, #8

    /* Find envp (skip past argv array until we hit NULL)
     * x1 = argv pointer
     * x2 = argc counter
     * x3 = temporary for envp calculation
     */
    mov x1, x20                 /* x1 = argv */
    mov x2, x19                 /* x2 = argc */
    add x2, x2, #1              /* +1 for the NULL terminator */
    lsl x3, x2, #3              /* multiply by 8 (pointer size) */
    add x3, x1, x3              /* x3 now points to envp */

    /* Stack is already 16-byte aligned by kernel (elf64.c:1305) */

    /* Call __libc_init_environ(envp) to initialize the environ global
     * envp is in x3, move it to x0 (first argument)
     */
    mov x0, x3
    bl __libc_init_environ

    /* Restore argc, argv, and envp for main call */
    mov x0, x19                 /* argc in x0 */
    mov x1, x20                 /* argv in x1 */
    mov x2, x3                  /* envp in x2 (calculated above) */

    /* Call main(argc, argv, envp) */
    bl main

    /* main() returned, x0 contains exit code */
    bl exit

    /* Should never reach here */
    .inst 0xd4200000            /* brk #0 (illegal instruction trap) */

/* exit() system call wrapper.
 *
 * Uses ARM64 Linux generic syscall #93 = exit. The kernel's
 * arm64 syscall table registers sys_exit_wrapper at slot 93,
 * matching Linux. (Earlier versions of this file used #60 from
 * the x86_64 historical numbering, which collided with fchown
 * in the ARM64 generic ABI and caused exit to silently fail —
 * that compat path is gone now.)
 *
 * SVC immediate is informational on AArch64 and our exception
 * handler ignores it, but #0 is the standard Linux convention. */
.global exit
exit:
    mov x8, #93                 /* SYS_exit (Linux ARM64 generic) */
    svc #0                      /* Trap to EL1 */
    .inst 0xd4200000            /* unreachable */

/* Mark stack as non-executable to silence linker warnings */
.section .note.GNU-stack, "", %progbits
