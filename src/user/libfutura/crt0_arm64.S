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

    /* Compute envp = &argv[argc + 1] and stash it in x21 (callee-
     * saved). x3 used to hold this, but `bl __libc_init_environ`
     * clobbers caller-saved registers including x3 — the subsequent
     * `mov x2, x3` then passed garbage to main as envp, and main()
     * dereferenced it on the first envp[0] load (typically 0x11 or
     * similar small junk). Keeping envp in x21 across the call
     * fixes the user-mode segfault that masked the shell at boot. */
    mov x1, x20                 /* x1 = argv */
    mov x2, x19                 /* x2 = argc */
    add x2, x2, #1              /* +1 for the NULL terminator */
    lsl x21, x2, #3             /* x21 = (argc + 1) * 8 */
    add x21, x1, x21            /* x21 = envp (callee-saved) */

    /* Stack is already 16-byte aligned by kernel (elf64.c:1305) */

    /* Call __libc_init_environ(envp). x21 stays valid across the bl. */
    mov x0, x21
    bl __libc_init_environ

    /* Set up argc, argv, envp for main call */
    mov x0, x19                 /* argc in x0 */
    mov x1, x20                 /* argv in x1 */
    mov x2, x21                 /* envp in x2 (preserved across call) */

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
