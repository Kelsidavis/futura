/*
 * Futura OS - ARM64 Context Switching
 * Copyright (C) 2025 Futura OS Project
 *
 * Low-level context switching routines for ARM64 architecture.
 */

.section .text

/*
 * fut_switch_context - Cooperative context switch (called by scheduler)
 *
 * Arguments:
 *   x0 = old context (fut_cpu_context_t *) - may be NULL for first switch
 *   x1 = new context (fut_cpu_context_t *)
 *
 * Saves current CPU state to old context and restores from new context.
 */
.global fut_switch_context
.type fut_switch_context, @function
fut_switch_context:
    /* Check if old context is NULL (first thread switch) */
    cbz     x0, .Lrestore_only

    /* Save current context to old */
    stp     x19, x20, [x0, #0]        /* Save x19, x20 */
    stp     x21, x22, [x0, #16]       /* Save x21, x22 */
    stp     x23, x24, [x0, #32]       /* Save x23, x24 */
    stp     x25, x26, [x0, #48]       /* Save x25, x26 */
    stp     x27, x28, [x0, #64]       /* Save x27, x28 */
    stp     x29, x30, [x0, #80]       /* Save FP (x29), LR (x30) */

    /* Save stack pointer */
    mov     x2, sp
    str     x2, [x0, #96]             /* Save SP */

    /* Save return address as PC */
    adr     x2, .Lresume_point        /* Get address of resume point */
    str     x2, [x0, #104]            /* Save PC */

.Lrestore_only:
    /* Restore new context */
    ldp     x19, x20, [x1, #0]        /* Restore x19, x20 */
    ldp     x21, x22, [x1, #16]       /* Restore x21, x22 */
    ldp     x23, x24, [x1, #32]       /* Restore x23, x24 */
    ldp     x25, x26, [x1, #48]       /* Restore x25, x26 */
    ldp     x27, x28, [x1, #64]       /* Restore x27, x28 */
    ldp     x29, x30, [x1, #80]       /* Restore FP (x29), LR (x30) */

    /* Restore stack pointer */
    ldr     x2, [x1, #96]             /* Restore SP */
    mov     sp, x2

    /* Jump to saved PC */
    ldr     x2, [x1, #104]            /* Load PC */
    br      x2                        /* Jump to new thread */

.Lresume_point:
    /* Resume point when this thread is switched back to */
    ret

.size fut_switch_context, . - fut_switch_context

/*
 * fut_switch_context_irq - Context switch from interrupt handler
 *
 * Arguments:
 *   x0 = prev thread (struct fut_thread *) - may be NULL
 *   x1 = next thread (struct fut_thread *)
 *   x2 = prev_frame (struct fut_interrupt_frame *) - currently unused
 *
 * Context is stored at offset 48 in fut_thread structure.
 */
.global fut_switch_context_irq
.type fut_switch_context_irq, @function
fut_switch_context_irq:
    /* Save x2 (prev_frame) - not used in basic implementation */
    /* We can use it later for saving interrupt context */

    /* Check if prev thread is NULL */
    cbz     x0, .Lirq_restore_only

    /* Get pointer to prev thread's context (offset 48) */
    add     x0, x0, #48

.Lirq_restore_only:
    /* Get pointer to next thread's context (offset 48) */
    add     x1, x1, #48

    /* Call the main context switch function */
    b       fut_switch_context

.size fut_switch_context_irq, . - fut_switch_context_irq

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
    /* Offset to context field in fut_thread structure is 48 bytes */

    /* Save callee-saved registers */
    stp     x19, x20, [x0, #48]       /* Save x19, x20 */
    stp     x21, x22, [x0, #64]       /* Save x21, x22 */
    stp     x23, x24, [x0, #80]       /* Save x23, x24 */
    stp     x25, x26, [x0, #96]       /* Save x25, x26 */
    stp     x27, x28, [x0, #112]      /* Save x27, x28 */
    stp     x29, x30, [x0, #128]      /* Save FP (x29), LR (x30) */

    /* Save stack pointer */
    mov     x2, sp
    str     x2, [x0, #144]            /* Save SP */

    /* Save return address (PC) */
    adr     x2, 1f                    /* Get address of resume point */
    str     x2, [x0, #152]            /* Save PC */

    /* Restore next thread context */
    ldp     x19, x20, [x1, #48]       /* Restore x19, x20 */
    ldp     x21, x22, [x1, #64]       /* Restore x21, x22 */
    ldp     x23, x24, [x1, #80]       /* Restore x23, x24 */
    ldp     x25, x26, [x1, #96]       /* Restore x25, x26 */
    ldp     x27, x28, [x1, #112]      /* Restore x27, x28 */
    ldp     x29, x30, [x1, #128]      /* Restore FP (x29), LR (x30) */

    /* Restore stack pointer */
    ldr     x2, [x1, #144]            /* Restore SP */
    mov     sp, x2

    /* Restore PC (return address) */
    ldr     x2, [x1, #152]            /* Restore PC */
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
    /* x0 already contains thread pointer, context starts at offset 48 */

    /* Clear callee-saved registers */
    stp     xzr, xzr, [x0, #48]       /* x19, x20 = 0 */
    stp     xzr, xzr, [x0, #64]       /* x21, x22 = 0 */
    stp     xzr, xzr, [x0, #80]       /* x23, x24 = 0 */
    stp     xzr, xzr, [x0, #96]       /* x25, x26 = 0 */
    stp     xzr, xzr, [x0, #112]      /* x27, x28 = 0 */

    /* x19 will hold the argument for the entry function */
    str     x2, [x0, #48]             /* x19 = arg */

    /* Set up FP and LR */
    str     xzr, [x0, #128]           /* x29 (FP) = 0 */
    adr     x6, fut_thread_entry_stub
    str     x6, [x0, #136]            /* x30 (LR) = thread entry stub */

    /* Set initial stack pointer */
    str     x5, [x0, #144]            /* SP = stack top */

    /* Set initial PC to entry function */
    str     x1, [x0, #152]            /* PC = entry function */

    /* Set initial PSTATE (EL1h, interrupts enabled) */
    mov     x6, #(PSTATE_MODE_EL1h | PSTATE_F_BIT)
    str     x6, [x0, #160]            /* PSTATE */

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
 * fut_restore_context - Restore context and transition to target exception level
 *
 * Arguments:
 *   x0 = context (fut_cpu_context_t *)
 *
 * Restores CPU state from context and uses eret to transition to the target EL.
 * This function handles both EL1→EL1 and EL1→EL0 transitions.
 *
 * Context structure offsets:
 *   0: x0, 8: x19, 16: x20, 24: x21, 32: x22, 40: x23, 48: x24, 56: x25
 *   64: x26, 72: x27, 80: x28, 88: x29_fp, 96: x30_lr, 104: sp, 112: pc, 120: pstate
 */
.global fut_restore_context
.type fut_restore_context, @function
fut_restore_context:
    /* Save x0 temporarily (we'll need it until the end) */
    mov     x2, x0

    /* Load PC and PSTATE into exception return registers */
    ldr     x1, [x2, #112]            /* Load PC */
    msr     elr_el1, x1               /* ELR_EL1 = target PC */

    ldr     x1, [x2, #120]            /* Load PSTATE */
    msr     spsr_el1, x1              /* SPSR_EL1 = target PSTATE */

    /* Restore stack pointer
     * Check if target is EL0 (PSTATE & 0xF == 0) and set SP_EL0
     * Otherwise set SP_EL1
     */
    ldr     x1, [x2, #104]            /* Load SP */
    ldr     x3, [x2, #120]            /* Load PSTATE again */
    and     x3, x3, #0xF              /* Extract mode bits */
    cbnz    x3, 1f                    /* If not EL0, skip to setting SP_EL1 */

    /* Target is EL0 - set SP_EL0 */
    msr     sp_el0, x1
    b       2f

1:  /* Target is EL1 - set SP_EL1 */
    mov     sp, x1

2:  /* Continue with register restore */
    /* Restore callee-saved registers x19-x28 */
    ldr     x19, [x2, #8]
    ldr     x20, [x2, #16]
    ldr     x21, [x2, #24]
    ldr     x22, [x2, #32]
    ldr     x23, [x2, #40]
    ldr     x24, [x2, #48]
    ldr     x25, [x2, #56]
    ldr     x26, [x2, #64]
    ldr     x27, [x2, #72]
    ldr     x28, [x2, #80]

    /* Restore frame pointer and link register */
    ldr     x29, [x2, #88]            /* Restore FP */
    ldr     x30, [x2, #96]            /* Restore LR */

    /* Restore x0 last (return value / first argument) */
    ldr     x0, [x2, #0]

    /* Use eret to transition to target EL with restored PC and PSTATE */
    eret

.size fut_restore_context, . - fut_restore_context

/*
 * fut_save_context - Save current context
 *
 * Arguments:
 *   x0 = context (fut_cpu_context_t *)
 *
 * Saves the current CPU state into the context structure.
 */
.global fut_save_context
.type fut_save_context, @function
fut_save_context:
    /* Save x0 (usually return value) */
    str     x0, [x0, #0]

    /* Save callee-saved registers x19-x28 */
    str     x19, [x0, #8]
    str     x20, [x0, #16]
    str     x21, [x0, #24]
    str     x22, [x0, #32]
    str     x23, [x0, #40]
    str     x24, [x0, #48]
    str     x25, [x0, #56]
    str     x26, [x0, #64]
    str     x27, [x0, #72]
    str     x28, [x0, #80]

    /* Save frame pointer and link register */
    str     x29, [x0, #88]            /* Save FP */
    str     x30, [x0, #96]            /* Save LR */

    /* Save stack pointer */
    mov     x1, sp
    str     x1, [x0, #104]

    /* Save return address as PC */
    adr     x1, 1f
    str     x1, [x0, #112]

    /* Save current PSTATE (using SPSR_EL1 if available, or construct from CurrentEL) */
    mrs     x1, spsr_el1
    str     x1, [x0, #120]

    ret

1:  /* Resume point */
    ret

.size fut_save_context, . - fut_save_context

/*
 * Constants for PSTATE
 */
.set PSTATE_MODE_EL0t, 0x00
.set PSTATE_MODE_EL1t, 0x04
.set PSTATE_MODE_EL1h, 0x05
.set PSTATE_F_BIT, (1 << 6)
.set PSTATE_I_BIT, (1 << 7)
.set PSTATE_A_BIT, (1 << 8)
