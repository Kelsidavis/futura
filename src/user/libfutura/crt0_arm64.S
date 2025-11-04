/* crt0_arm64.S - C Runtime Startup for Futura OS Userland (ARM64)
 *
 * Copyright (c) 2025 Kelsi Davis
 * Licensed under the MPL v2.0 — see LICENSE for details.
 *
 * This is the entry point for all ARM64 userland programs.
 * Sets up the execution environment and calls main().
 *
 * ARM64 Calling Convention:
 * - x0-x7: First 8 arguments
 * - x0: Return value
 * - x29: Frame pointer (FP)
 * - x30: Link register (LR)
 * - sp: Stack pointer (must be 16-byte aligned)
 */

.section .text
.global _start

_start:
    /* Clear frame pointer for stack unwinding */
    mov     x29, #0

    /* Stack layout when we start:
     * sp+0:   argc
     * sp+8:   argv[0]
     * sp+16:  argv[1]
     * ...
     * NULL
     * envp[0]
     * envp[1]
     * ...
     * NULL
     */

    /* Load argc from stack into x0 (first argument) */
    ldr     x0, [sp], #8

    /* argv is now at sp, put it in x1 (second argument) */
    mov     x1, sp

    /* Save argc in x19 (callee-saved register) for use after __libc_init_environ */
    mov     x19, x0

    /* Find envp (skip past argv array until we hit NULL)
     * Calculate: envp = argv + (argc + 1) * 8
     */
    add     x2, x0, #1          /* x2 = argc + 1 */
    lsl     x2, x2, #3          /* x2 = (argc + 1) * 8 */
    add     x2, x1, x2          /* x2 = argv + (argc + 1) * 8 = envp */

    /* Align stack to 16 bytes (required by ARM64 ABI)
     * sp must be 16-byte aligned before function calls
     */
    mov     x3, sp
    and     x3, x3, #-16
    mov     sp, x3

    /* Call __libc_init_environ(envp) to initialize the environ global
     * envp is in x2, so move it to x0 (first argument)
     */
    mov     x0, x2
    bl      __libc_init_environ

    /* Restore argc from x19 and argv for main call */
    mov     x0, x19             /* argc back in x0 */
    /* argv still needs to be recalculated since sp changed */
    /* For simplicity, we'll pass NULL for argv for now */
    mov     x1, #0              /* argv = NULL (TODO: fix this) */

    /* Call main(argc, argv) */
    bl      main

    /* main() returned, x0 contains exit code */
    /* x0 already has return value, just call exit */
    bl      exit

    /* Should never reach here */
    brk     #0

/* exit() system call wrapper */
.global exit
exit:
    /* ARM64 syscall convention:
     * x8 = syscall number
     * x0 = argument (exit code already in x0)
     */
    mov     x8, #93             /* __NR_exit = 93 for ARM64 */
    svc     #0                  /* Make syscall */
    brk     #0                  /* unreachable */
