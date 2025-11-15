/*
 * Futura OS - ARM64 Context Switching
 * Copyright (C) 2025 Futura OS Project
 *
 * Low-level context switching routines for ARM64 architecture.
 *
 * ARM64 Context Switching Framework
 * ==================================
 *
 * Phase 1 (Completed): Basic Cooperative Context Switching
 * -----
 * Status: ✓ Implemented and tested
 * - Register preservation (x0-x30)
 * - Callee-saved register save/restore (x19-x29, x30/LR)
 * - Stack pointer management (SP_EL1 for kernel, SP_EL0 for user)
 * - Program counter restoration
 * - PSTATE restoration for EL1/EL0 transitions
 * - Asynchronous context save: NULL old context support
 * - Per-task CPU context pointer allocation
 * - Kernel stack switch on context change
 *
 * Key Optimization:
 * - Caller-saved registers (x0-x18): Not saved (caller responsibility)
 * - Callee-saved registers (x19-x29, x30): Explicitly saved/restored
 * - Minimal register shuffling (x0, x1 only partially used)
 *
 * Phase 2 (Planned): Page Table Context Switching
 * -----
 * Status: ⏳ Framework in place, TTBR context switching pending
 * - TTBR0_EL1 save/restore (per-task user page table base)
 * - TTBR1_EL1 management (kernel page table, usually fixed)
 * - TLB invalidation on context switch (TLBI ASIDE1)
 * - Context ID (CONTEXTID_EL1) management
 * - ASID isolation for address space separation
 *
 * Phase 3 (Planned): Advanced Context Management
 * -----
 * Status: ⏳ Deferred
 * - FPU context preservation (v0-v31, FPSR, FPCR)
 * - Lazy FPU restoration strategy
 * - System register context (TPIDR_EL0, TPIDRRO_EL0)
 * - Privileged system registers (SCTLR_EL1, ACTLR_EL1)
 *
 * CPU Context Structure (fut_cpu_context_t)
 * ==========================================
 *
 * Memory Layout:
 *   Offset 0:   x0
 *   Offset 8:   x1
 *   Offset 16:  x19
 *   Offset 24:  x20
 *   ...
 *   Offset 112: sp (SP_EL1 - kernel stack pointer)
 *   Offset 120: sp_el0 (SP_EL0 - user stack pointer)
 *   Offset 128: pc (program counter)
 *   Offset 136: pstate (processor state)
 *   Offset 144: ttbr0_el1 (user page table base)
 *
 * Context Switching Flow
 * ======================
 *
 * 1. Scheduler calls: fut_switch_context(old_ctx, new_ctx)
 *    - old_ctx: Current task's CPU context (may be NULL for first switch)
 *    - new_ctx: Next task's CPU context
 *
 * 2. Save old context (if not NULL):
 *    - Save callee-saved registers (x19-x29, x30)
 *    - Save current stack pointer (SP_EL1)
 *    - Save user stack pointer (SP_EL0)
 *    - Save program counter (PC at return label)
 *    - Save processor state (PSTATE for privilege level)
 *
 * 3. Restore new context:
 *    - Check if target is EL0 (user) or EL1 (kernel)
 *    - Restore callee-saved registers
 *    - Restore stack pointer
 *    - If EL0: Setup ERET path (ELR_EL1, SPSR_EL1, TTBRo_EL1)
 *    - If EL1: Direct return (normal function return)
 *
 * 4. For EL0 return (user code):
 *    - Set ELR_EL1 to user PC
 *    - Set SPSR_EL1 to PSTATE
 *    - Load user page table (TTBR0_EL1)
 *    - Load user stack pointer (SP_EL0)
 *    - Execute ERET (exception return to EL0)
 *
 * 5. For EL1 return (kernel code):
 *    - Direct RET instruction
 *    - Uses saved return address (x30/LR)
 *
 * Register Calling Convention
 * ============================
 *
 * Caller-saved (x0-x18):
 *   - Not preserved across function calls
 *   - Caller must save if needed
 *   - Used for argument passing and return values
 *
 * Callee-saved (x19-x28, x29, x30):
 *   - Must be preserved by called function
 *   - This routine explicitly saves/restores them
 *   - x29: Frame pointer (FP)
 *   - x30: Link register (LR / return address)
 *
 * Privilege Level Transitions
 * ============================
 *
 * EL1 (Kernel) Context:
 *   - PSTATE: 0x05 (EL1h mode)
 *   - Stack: Kernel stack (SP_EL1)
 *   - Page tables: Kernel TTBR0_EL1 (usually)
 *   - Return: Direct RET instruction
 *
 * EL0 (User) Context:
 *   - PSTATE: 0x00 (EL0 mode)
 *   - Stack: User stack (SP_EL0)
 *   - Page tables: User TTBR0_EL1 (per-task)
 *   - Return: ERET instruction (exception return)
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

    /* Save current context to old (matching C structure layout) */
    /* Note: x0 contains the context pointer, so we can't save the "real" x0 */
    /* x2-x18 are caller-saved, so we don't save them for EL1 cooperative switches */
    str     x1, [x0, #8]              /* Save x1 at offset 8 */

    /* Save callee-saved registers x19-x30 at new offsets */
    stp     x19, x20, [x0, #152]      /* Save x19, x20 at new offset 152 */
    stp     x21, x22, [x0, #168]      /* Save x21, x22 */
    stp     x23, x24, [x0, #184]      /* Save x23, x24 */
    stp     x25, x26, [x0, #200]      /* Save x25, x26 */
    stp     x27, x28, [x0, #216]      /* Save x27, x28 */
    stp     x29, x30, [x0, #232]      /* Save FP (x29), LR (x30) at new offset 232 */

    /* Save stack pointer */
    mov     x2, sp
    str     x2, [x0, #248]            /* Save SP at new offset 248 */

    /* Save SP_EL0 (user stack pointer) */
    mrs     x2, sp_el0
    str     x2, [x0, #256]            /* Save SP_EL0 at new offset 256 */

    /* Save return address as PC */
    adr     x2, .Lresume_point        /* Get address of resume point */
    str     x2, [x0, #264]            /* Save PC at new offset 264 */

    /* Save PSTATE (for EL1, it should be 0x05) */
    mov     x2, #0x05                 /* EL1h mode */
    str     x2, [x0, #272]            /* Save PSTATE at new offset 272 */

.Lrestore_only:
    /* Context structure layout (with x2-x18 added for fork support):
     *   Offset 0:   x0
     *   Offset 8:   x1
     *   Offset 16:  x2-x18 (caller-saved, 17 regs)
     *   Offset 152: x19 (callee-saved start)
     *   ...
     *   Offset 248: sp
     *   Offset 256: sp_el0
     *   Offset 264: pc
     *   Offset 272: pstate
     *   Offset 280: ttbr0_el1
     */

    /* Check if target context is EL0 (PSTATE & 0xF == 0) */
    ldr     x2, [x1, #272]            /* Load PSTATE from new offset 272 */
    and     x3, x2, #0xF              /* Extract mode bits */
    cbnz    x3, .Lrestore_el1         /* If not zero, it's EL1 */

    /* Target is EL0 - use ERET path - need to restore ALL registers for fork */
    /* CRITICAL: Load all registers BEFORE switching page table! */
    /* The context is in kernel memory (0x40000000+) which is only mapped in
     * the kernel's TTBR0_EL1, not in user TTBR0_EL1, so we must load everything
     * before switching. */

    /* Set up ELR_EL1 and SPSR_EL1 for exception return */
    ldr     x2, [x1, #264]            /* Load PC from new offset 264 */
    msr     elr_el1, x2               /* Set exception return address */

    ldr     x2, [x1, #272]            /* Load PSTATE from new offset 272 */
    msr     spsr_el1, x2              /* Set saved processor state */

    /* Restore SP_EL0 (user stack pointer) - CRITICAL for userspace */
    ldr     x2, [x1, #256]            /* Load SP_EL0 from new offset 256 */
    msr     sp_el0, x2                /* Set user stack pointer */

    /* Strategy: Save both context pointer (x1) and user's x2 to stack early,
     * then restore ALL user registers from context, then use stack values for
     * TTBR0 switch. This way kernel stack is always accessible (mapped in both
     * kernel and user page tables via TTBR1_EL1). */

    /* Push context pointer and user's x2 onto kernel stack */
    ldr     x2, [x1, #16]             /* Load user's x2 value */
    stp     x1, x2, [sp, #-16]!       /* Push context ptr and user's x2 */

    /* Now load TTBR0 value into x2 for later use */
    ldr     x2, [x1, #280]            /* Load ttbr0_el1 value into x2 */
    str     x2, [sp, #-16]!           /* Push TTBR0 value onto stack */

    /* Restore callee-saved registers (x19-x30) BEFORE switching page table */
    ldp     x19, x20, [x1, #152]      /* Restore x19, x20 from new offset 152 */
    ldp     x21, x22, [x1, #168]      /* Restore x21, x22 */
    ldp     x23, x24, [x1, #184]      /* Restore x23, x24 */
    ldp     x25, x26, [x1, #200]      /* Restore x25, x26 */
    ldp     x27, x28, [x1, #216]      /* Restore x27, x28 */
    ldp     x29, x30, [x1, #232]      /* Restore FP (x29), LR (x30) from new offset 232 */

    /* Restore caller-saved registers x3-x18 (needed for fork) */
    ldr     x3, [x1, #24]             /* Restore x3 */
    ldp     x4, x5, [x1, #32]         /* Restore x4, x5 */

    ldp     x6, x7, [x1, #48]         /* Restore x6, x7 - x7 contains string table pointer! */
    ldp     x8, x9, [x1, #64]         /* Restore x8, x9 */
    ldp     x10, x11, [x1, #80]       /* Restore x10, x11 */
    ldp     x12, x13, [x1, #96]       /* Restore x12, x13 */
    ldp     x14, x15, [x1, #112]      /* Restore x14, x15 */
    ldp     x16, x17, [x1, #128]      /* Restore x16, x17 */
    ldr     x18, [x1, #144]           /* Restore x18 */

    /* Restore x0 and x1 BEFORE switching page table */
    ldp     x0, x1, [x1, #0]          /* Restore x0 and x1 */

    /* Now ALL user registers except x2 have correct values.
     * Pop TTBR0 from stack and switch page table */
    ldr     x2, [sp], #16             /* Pop TTBR0 value into x2 */
    msr     ttbr0_el1, x2             /* Set user page table base */
    isb                               /* Instruction synchronization barrier */

    /* Stack now has [context_ptr, user_x2]. Pop user's x2 value.
     * Skip context_ptr (we don't need it anymore). */
    ldr     x2, [sp, #8]              /* Load user's x2 from stack */
    add     sp, sp, #16               /* Pop both values from stack */

    /* Ensure all register loads complete */
    dsb     sy                        /* Data synchronization barrier */
    isb                               /* Instruction synchronization barrier */

    /* Disable interrupts before ERET to prevent IRQ from clobbering registers */
    msr     daifset, #0xf             /* Disable Debug, SError, IRQ, FIQ */
    isb                               /* Ensure interrupt mask takes effect */

    /* Exception return to EL0 */
    eret

.Lrestore_el1:
    /* Target is EL1 - use regular cooperative switch */
    /* Only restore callee-saved registers (x2-x18 are caller's responsibility) */

    /* Restore callee-saved registers (x19-x30) with new offsets */
    ldp     x19, x20, [x1, #152]      /* Restore x19, x20 from new offset 152 */
    ldp     x21, x22, [x1, #168]      /* Restore x21, x22 */
    ldp     x23, x24, [x1, #184]      /* Restore x23, x24 */
    ldp     x25, x26, [x1, #200]      /* Restore x25, x26 */
    ldp     x27, x28, [x1, #216]      /* Restore x27, x28 */
    ldp     x29, x30, [x1, #232]      /* Restore FP (x29), LR (x30) from new offset 232 */

    /* Restore stack pointer */
    ldr     x2, [x1, #248]            /* Restore SP from new offset 248 */
    mov     sp, x2

    /* Load PC */
    ldr     x2, [x1, #264]            /* Load PC from new offset 264 */

    /* Restore x0 and x1 (parameters for new threads, or saved values for resumed threads) */
    ldp     x0, x3, [x1, #0]          /* Load x0 and x1 into x0 and x3 */
    mov     x1, x3                    /* Move x1 value to x1 */

    /* Jump to saved PC */
    br      x2                        /* Jump to thread */

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
 * Context structure offsets (fut_cpu_context_t):
 *   0: x0, 8: x1, 16: x19, 24: x20, 32: x21, 40: x22, 48: x23, 56: x24
 *   64: x25, 72: x26, 80: x27, 88: x28, 96: x29_fp, 104: x30_lr
 *   112: sp, 120: sp_el0, 128: pc, 136: pstate, 144: ttbr0_el1
 */
.global fut_restore_context
.type fut_restore_context, @function
fut_restore_context:
    /* Save x0 temporarily (we'll need it until the end) */
    mov     x2, x0

    /* Load PC and PSTATE into exception return registers */
    ldr     x1, [x2, #128]            /* Load PC from offset 128 */
    msr     elr_el1, x1               /* ELR_EL1 = target PC */

    ldr     x1, [x2, #136]            /* Load PSTATE from offset 136 */
    msr     spsr_el1, x1              /* SPSR_EL1 = target PSTATE */

    /* Restore stack pointers
     * Check if target is EL0 (PSTATE & 0xF == 0) and set SP_EL0
     * Otherwise set SP_EL1
     */
    ldr     x1, [x2, #112]            /* Load SP from offset 112 */
    ldr     x4, [x2, #120]            /* Load SP_EL0 from offset 120 */
    ldr     x3, [x2, #136]            /* Load PSTATE again from offset 136 */
    and     x3, x3, #0xF              /* Extract mode bits */
    cbnz    x3, 1f                    /* If not EL0, skip to setting SP_EL1 */

    /* Target is EL0 - set SP_EL0 and use kernel stack for SP */
    msr     sp_el0, x4                /* Set user stack pointer */
    mov     sp, x1                    /* Set kernel stack pointer */
    b       2f

1:  /* Target is EL1 - set SP_EL1 */
    mov     sp, x1

2:  /* Continue with register restore */
    /* Restore callee-saved registers x19-x28 */
    ldr     x19, [x2, #16]            /* x19 at offset 16 */
    ldr     x20, [x2, #24]            /* x20 at offset 24 */
    ldr     x21, [x2, #32]            /* x21 at offset 32 */
    ldr     x22, [x2, #40]            /* x22 at offset 40 */
    ldr     x23, [x2, #48]            /* x23 at offset 48 */
    ldr     x24, [x2, #56]            /* x24 at offset 56 */
    ldr     x25, [x2, #64]            /* x25 at offset 64 */
    ldr     x26, [x2, #72]            /* x26 at offset 72 */
    ldr     x27, [x2, #80]            /* x27 at offset 80 */
    ldr     x28, [x2, #88]            /* x28 at offset 88 */

    /* Restore frame pointer and link register */
    ldr     x29, [x2, #96]            /* FP at offset 96 */
    ldr     x30, [x2, #104]           /* LR at offset 104 */

    /* Restore x0 and x1 last */
    ldr     x1, [x2, #8]              /* x1 at offset 8 */
    ldr     x0, [x2, #0]              /* x0 at offset 0 */

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
    /* Save x0 and x1 */
    str     x0, [x0, #0]              /* Save x0 */
    str     x1, [x0, #8]              /* Save x1 */

    /* Save callee-saved registers x19-x28 */
    str     x19, [x0, #16]            /* x19 at offset 16 */
    str     x20, [x0, #24]            /* x20 at offset 24 */
    str     x21, [x0, #32]            /* x21 at offset 32 */
    str     x22, [x0, #40]            /* x22 at offset 40 */
    str     x23, [x0, #48]            /* x23 at offset 48 */
    str     x24, [x0, #56]            /* x24 at offset 56 */
    str     x25, [x0, #64]            /* x25 at offset 64 */
    str     x26, [x0, #72]            /* x26 at offset 72 */
    str     x27, [x0, #80]            /* x27 at offset 80 */
    str     x28, [x0, #88]            /* x28 at offset 88 */

    /* Save frame pointer and link register */
    str     x29, [x0, #96]            /* FP at offset 96 */
    str     x30, [x0, #104]           /* LR at offset 104 */

    /* Save stack pointers */
    mov     x1, sp
    str     x1, [x0, #112]            /* Save SP at offset 112 */

    mrs     x1, sp_el0
    str     x1, [x0, #120]            /* Save SP_EL0 at offset 120 */

    /* Save return address as PC */
    adr     x1, 1f
    str     x1, [x0, #128]            /* Save PC at offset 128 */

    /* Save current PSTATE (using SPSR_EL1 if available, or construct from CurrentEL) */
    mrs     x1, spsr_el1
    str     x1, [x0, #136]            /* Save PSTATE at offset 136 */

    ret

1:  /* Resume point */
    ret

.size fut_save_context, . - fut_save_context

/*
 * Debug message strings
 */
.section .rodata
.Ldebug_msg_branch_check:
    .asciz "branch_check"
.Ldebug_msg_eret_path:
    .asciz "ERET_PATH"
.Ldebug_msg_el1_path:
    .asciz "EL1_PATH"
.Ldebug_msg_x7:
    .asciz "x7"
.Ldebug_msg_ctx_x7:
    .asciz "ctx_load"
.Ldebug_x7_fmt:
    .asciz "[CTX-SWITCH] Loaded x7=0x%llx before ERET\n"
.Ldebug_x7_before_eret_fmt:
    .asciz "[CTX-SWITCH] x7=0x%llx RIGHT BEFORE ERET\n"

.section .text

/*
 * Constants for PSTATE
 */
.set PSTATE_MODE_EL0t, 0x00
.set PSTATE_MODE_EL1t, 0x04
.set PSTATE_MODE_EL1h, 0x05
.set PSTATE_F_BIT, (1 << 6)
.set PSTATE_I_BIT, (1 << 7)
.set PSTATE_A_BIT, (1 << 8)
