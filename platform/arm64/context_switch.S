/*
 * Futura OS - ARM64 Context Switching
 * Copyright (C) 2025 Futura OS Project
 *
 * Low-level context switching routines for ARM64 architecture.
 */

.section .text

/*
 * fut_context_switch - Switch from one thread context to another
 *
 * Arguments:
 *   x0 = prev thread (struct fut_thread *)
 *   x1 = next thread (struct fut_thread *)
 *
 * Saves the context of the current thread and loads the context of the next thread.
 */
.global fut_context_switch
.type fut_context_switch, @function
fut_context_switch:
    /* Save prev thread context */
    /* Offset to context field in fut_thread structure (adjust based on actual layout) */
    /* For now, assume context is at offset 64 */

    /* Save callee-saved registers */
    stp     x19, x20, [x0, #64]       /* Save x19, x20 */
    stp     x21, x22, [x0, #80]       /* Save x21, x22 */
    stp     x23, x24, [x0, #96]       /* Save x23, x24 */
    stp     x25, x26, [x0, #112]      /* Save x25, x26 */
    stp     x27, x28, [x0, #128]      /* Save x27, x28 */
    stp     x29, x30, [x0, #144]      /* Save FP (x29), LR (x30) */

    /* Save stack pointer */
    mov     x2, sp
    str     x2, [x0, #160]            /* Save SP */

    /* Save return address (PC) */
    adr     x2, 1f                    /* Get address of resume point */
    str     x2, [x0, #168]            /* Save PC */

    /* Restore next thread context */
    ldp     x19, x20, [x1, #64]       /* Restore x19, x20 */
    ldp     x21, x22, [x1, #80]       /* Restore x21, x22 */
    ldp     x23, x24, [x1, #96]       /* Restore x23, x24 */
    ldp     x25, x26, [x1, #112]      /* Restore x25, x26 */
    ldp     x27, x28, [x1, #128]      /* Restore x27, x28 */
    ldp     x29, x30, [x1, #144]      /* Restore FP (x29), LR (x30) */

    /* Restore stack pointer */
    ldr     x2, [x1, #160]            /* Restore SP */
    mov     sp, x2

    /* Restore PC (return address) */
    ldr     x2, [x1, #168]            /* Restore PC */
    br      x2                        /* Jump to next thread */

1:  /* Resume point for prev thread */
    ret

.size fut_context_switch, . - fut_context_switch

/*
 * fut_context_init - Initialize a new thread's context
 *
 * Arguments:
 *   x0 = thread (struct fut_thread *)
 *   x1 = entry point (void (*)(void *))
 *   x2 = argument (void *)
 *   x3 = stack_base (void *)
 *   x4 = stack_size (size_t)
 *
 * Sets up the initial context for a new thread.
 */
.global fut_context_init
.type fut_context_init, @function
fut_context_init:
    /* Calculate stack top (stack grows downward) */
    add     x5, x3, x4                /* x5 = stack_base + stack_size */

    /* Align stack to 16 bytes (ARM64 ABI requirement) */
    and     x5, x5, #~15

    /* Set up initial context */
    /* x0 already contains thread pointer */

    /* Clear callee-saved registers */
    stp     xzr, xzr, [x0, #64]       /* x19, x20 = 0 */
    stp     xzr, xzr, [x0, #80]       /* x21, x22 = 0 */
    stp     xzr, xzr, [x0, #96]       /* x23, x24 = 0 */
    stp     xzr, xzr, [x0, #112]      /* x25, x26 = 0 */
    stp     xzr, xzr, [x0, #128]      /* x27, x28 = 0 */

    /* x19 will hold the argument for the entry function */
    str     x2, [x0, #64]             /* x19 = arg */

    /* Set up FP and LR */
    str     xzr, [x0, #144]           /* x29 (FP) = 0 */
    adr     x6, fut_thread_entry_stub
    str     x6, [x0, #152]            /* x30 (LR) = thread entry stub */

    /* Set initial stack pointer */
    str     x5, [x0, #160]            /* SP = stack top */

    /* Set initial PC to entry function */
    str     x1, [x0, #168]            /* PC = entry function */

    /* Set initial PSTATE (EL1h, interrupts enabled) */
    mov     x6, #(PSTATE_MODE_EL1h | PSTATE_F_BIT)
    str     x6, [x0, #176]            /* PSTATE */

    ret

.size fut_context_init, . - fut_context_init

/*
 * fut_thread_entry_stub - Entry point wrapper for new threads
 *
 * This stub is called when a new thread first runs.
 * It calls the thread entry function with the saved argument.
 */
.type fut_thread_entry_stub, @function
fut_thread_entry_stub:
    /* x19 contains the argument (set by context_init) */
    /* PC contains the entry function (restored during context switch) */

    /* Get entry function from saved context */
    /* For now, assume entry function is in x1 (passed during init) */
    /* This is a simplified stub - full implementation would retrieve from context */

    /* Call entry function with argument */
    mov     x0, x19                   /* x0 = arg (from x19) */
    /* Entry function address should be in LR or PC */

    /* After entry function returns, exit thread */
    bl      fut_thread_exit

    /* Should never reach here */
1:  wfi
    b       1b

.size fut_thread_entry_stub, . - fut_thread_entry_stub

/*
 * Constants for PSTATE
 */
.set PSTATE_MODE_EL0t, 0x00
.set PSTATE_MODE_EL1t, 0x04
.set PSTATE_MODE_EL1h, 0x05
.set PSTATE_F_BIT, (1 << 6)
.set PSTATE_I_BIT, (1 << 7)
.set PSTATE_A_BIT, (1 << 8)
