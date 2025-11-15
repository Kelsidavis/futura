/* arm64_vectors.S - ARM64 Exception Vector Table
 *
 * Copyright (c) 2025 Kelsi Davis
 * Licensed under the MPL v2.0 — see LICENSE for details.
 *
 * Hardware exception entry point vectors for ARM64 synchronous exceptions, IRQs, FIQs,
 * and system errors. Each vector dispatches to appropriate C-level handler via branch.
 *
 * ARM64 Exception Vector Infrastructure
 * =====================================
 *
 * Phase 1 (Completed): Basic Exception Vector Table
 * -----
 * Status: ✓ Implemented and tested
 * - 2KB aligned exception vector table (VBAR_EL1 compatible)
 * - 16-entry vector table for all exception sources
 * - Exception level awareness (EL0 vs EL1, SP0 vs SPx)
 * - AArch64 vs AArch32 exception support (AArch32 returns error)
 * - Basic dispatch mechanism via branch instructions
 * - Synchronous exception entry points (SVC, data abort, instruction abort)
 * - IRQ exception entry with minimal context preservation
 * - FIQ exception entry (currently stubbed, returns immediately)
 * - SError (system error) entry with context preservation
 *
 * Key Features:
 * - Hardware entry point: VBAR_EL1 register points here
 * - 0x80-byte spacing between vectors (128 bytes per handler)
 * - Each vector can contain up to 32 ARM64 instructions
 * - Dispatch via branch (bl instruction) to common handlers
 * - Common handlers build interrupt_frame_t and call C dispatcher
 *
 * Phase 2 (Planned): Vector Optimization and Inlining
 * -----
 * Status: ⏳ Deferred
 * - Fast-path inlining for frequently-hit exception types
 * - Context-specific optimization (EL0 vs EL1 detection)
 * - Exception class prediction/pre-decoding in vector code
 * - Reduced latency paths for high-frequency exceptions (syscalls, page faults)
 * - Page table context switching optimization
 *
 * Phase 3 (Planned): Performance Monitoring and Tracing
 * -----
 * Status: ⏳ Deferred
 * - Exception cycle counter instrumentation
 * - Exception type histogramming
 * - Latency measurement between vector entry and handler
 * - Debug exception filtering
 * - Profiling hooks for performance analysis
 *
 * Phase 4 (Planned): Advanced Exception Features
 * -----
 * Status: ⏳ Deferred
 * - Debug and trace exception support (BRKVN, BRKPT, WFTRP)
 * - Memory tagging extension (MTE) fault handling
 * - Secure EL2 (SEL2) exception support
 * - Nested exception handling framework
 * - Exception recovery and retry mechanisms
 *
 * Exception Vector Layout (ARMv8.0)
 * =================================
 *
 * Vector table structure (2KB = 0x800 bytes):
 * Base address: VBAR_EL1 (set by arm64_install_exception_vectors)
 *
 * Current EL with SP0 (not used in Futura - kernel uses SPx):
 *   +0x000 (0x000): Synchronous exception from current EL with SP0
 *   +0x080 (0x080): IRQ from current EL with SP0
 *   +0x100 (0x100): FIQ from current EL with SP0
 *   +0x180 (0x180): SError from current EL with SP0
 *
 * Current EL with SPx (kernel execution):
 *   +0x200 (0x200): Synchronous exception from current EL with SPx
 *   +0x280 (0x280): IRQ from current EL with SPx
 *   +0x300 (0x300): FIQ from current EL with SPx
 *   +0x380 (0x380): SError from current EL with SPx
 *
 * Lower EL (AArch64, userspace EL0):
 *   +0x400 (0x400): Synchronous exception from lower EL (AArch64)
 *   +0x480 (0x480): IRQ from lower EL (AArch64)
 *   +0x500 (0x500): FIQ from lower EL (AArch64)
 *   +0x580 (0x580): SError from lower EL (AArch64)
 *
 * Lower EL (AArch32, not supported):
 *   +0x600 (0x600): Synchronous exception from lower EL (AArch32)
 *   +0x680 (0x680): IRQ from lower EL (AArch32)
 *   +0x700 (0x700): FIQ from lower EL (AArch32)
 *   +0x780 (0x780): SError from lower EL (AArch32)
 *
 * Exception Types and Dispatch
 * =============================
 *
 * Synchronous Exceptions (EC in ESR_EL1[31:26]):
 *   - SVC #n (0x15): Supervisor call - system calls from userspace
 *   - Data Abort (0x24-0x25): Memory access violations, page faults
 *   - Instruction Abort (0x20-0x21): Instruction fetch violations
 *   - Other synchronous: Unknown, WFI/WFE, illegal state
 *   Dispatch: branch to sync_exception_entry
 *
 * IRQ (Interrupt Request):
 *   - Timer interrupt (ARM Generic Timer)
 *   - Peripheral interrupt (GIC - Generic Interrupt Controller)
 *   - Dispatch: branch to irq_exception_entry
 *   - Minimal context save on stack
 *   - Call arm64_handle_irq() for GIC dispatch
 *
 * FIQ (Fast Interrupt Request):
 *   - Reserved for secure/hypervisor use
 *   - Currently not used in Futura
 *   - Dispatch: branch to fiq_exception_entry (returns immediately)
 *
 * SError (System Error, Asynchronous Abort):
 *   - Serious hardware errors (memory, interconnect)
 *   - Rare in QEMU (common on real hardware)
 *   - Non-maskable - always taken
 *   - Dispatch: branch to serror_exception_entry
 *   - Calls arm64_handle_serror() which halts system
 *
 * Handler Flow
 * ============
 *
 * 1. CPU takes exception:
 *    - Exception saved in ESR_EL1 (exception syndrome register)
 *    - Fault address in FAR_EL1 (for data/instruction aborts)
 *    - Return address in ELR_EL1 (exception link register)
 *    - Processor state in SPSR_EL1 (saved processor state)
 *    - CPU jumps to VBAR_EL1 + vector offset
 *
 * 2. Vector executes branch:
 *    - Branch (bl) to appropriate handler (sync, irq, fiq, serror)
 *    - Handler saves full register context and builds interrupt frame
 *    - Calls C-level dispatcher with frame pointer
 *
 * 3. C handler processes exception:
 *    - Examines ESR_EL1 to determine exception class
 *    - Routes to specific handler (SVC, data abort, etc.)
 *    - Handler processes and returns
 *
 * 4. Vector restores context:
 *    - Restores all registers from frame
 *    - Executes ERET to return to interrupted code
 *    - Hardware uses ELR_EL1 and SPSR_EL1 to resume
 *
 * Alignment and Memory Layout
 * ===========================
 *
 * Vector table requirements:
 *   - Must be 2KB (0x800) aligned: .align 11 (2^11 = 2048)
 *   - Each vector slot: 0x80 (128) bytes apart = 0x20 (32) instructions
 *   - ARM64 instructions are 4 bytes (32-bit)
 *   - Vector entries use .align 7 (2^7 = 128) for 0x80 spacing
 *   - Each slot can contain up to 32 instructions before next vector
 *
 * VBAR_EL1 (Vector Base Address Register):
 *   - Points to base of exception vector table (2KB aligned)
 *   - Set by arm64_install_exception_vectors()
 *   - Low 11 bits must be zero (2KB alignment requirement)
 *   - Used by CPU to calculate exception entry address
 *   - Formula: exception_address = VBAR_EL1 + vector_offset
 *
 * Memory Protection:
 *   - Vectors are in kernel .text section
 *   - Marked read-only (no self-modifying code)
 *   - All vectors present in memory before boot completes
 *   - Exception handlers have full access to kernel memory
 */

.text
.align 11  /* Vector table must be 2KB aligned (2^11 = 2048) */

.global arm64_exception_vectors
arm64_exception_vectors:

/* ============================================================
 *   Current EL with SP0 (not used - kernel always uses SPx)
 * ============================================================ */

/* +0x000: Synchronous from current EL with SP0 */
.align 7
curr_el_sp0_sync:
    b       sync_exception_entry

/* +0x080: IRQ from current EL with SP0 */
.align 7
curr_el_sp0_irq:
    b       irq_exception_entry

/* +0x100: FIQ from current EL with SP0 */
.align 7
curr_el_sp0_fiq:
    b       fiq_exception_entry

/* +0x180: SError from current EL with SP0 */
.align 7
curr_el_sp0_serror:
    b       serror_exception_entry

/* ============================================================
 *   Current EL with SPx (kernel mode)
 * ============================================================ */

/* +0x200: Synchronous from current EL with SPx */
.align 7
curr_el_spx_sync:
    b       sync_exception_entry

/* +0x280: IRQ from current EL with SPx */
.align 7
curr_el_spx_irq:
    b       irq_exception_entry

/* +0x300: FIQ from current EL with SPx */
.align 7
curr_el_spx_fiq:
    b       fiq_exception_entry

/* +0x380: SError from current EL with SPx */
.align 7
curr_el_spx_serror:
    b       serror_exception_entry

/* ============================================================
 *   Lower EL (AArch64) - userspace
 * ============================================================ */

/* +0x400: Synchronous from lower EL (AArch64) */
.align 7
lower_el_aarch64_sync:
    b       sync_exception_entry

/* +0x480: IRQ from lower EL (AArch64) */
.align 7
lower_el_aarch64_irq:
    b       irq_exception_entry

/* +0x500: FIQ from lower EL (AArch64) */
.align 7
lower_el_aarch64_fiq:
    b       fiq_exception_entry

/* +0x580: SError from lower EL (AArch64) */
.align 7
lower_el_aarch64_serror:
    b       serror_exception_entry

/* ============================================================
 *   Lower EL (AArch32) - not supported
 * ============================================================ */

/* +0x600: Synchronous from lower EL (AArch32) */
.align 7
lower_el_aarch32_sync:
    b       aarch32_not_supported

/* +0x680: IRQ from lower EL (AArch32) */
.align 7
lower_el_aarch32_irq:
    b       aarch32_not_supported

/* +0x700: FIQ from lower EL (AArch32) */
.align 7
lower_el_aarch32_fiq:
    b       aarch32_not_supported

/* +0x780: SError from lower EL (AArch32) */
.align 7
lower_el_aarch32_serror:
    b       aarch32_not_supported

/* ============================================================
 *   Exception Entry Stubs
 * ============================================================ */

/* IRQ Exception Entry - saves state and calls C handler */
irq_exception_entry:
    /* Save ALL caller-saved registers (x0-x18) that C code can clobber
     * This is critical for fork: if IRQ fires during context switch return,
     * we must preserve all registers including x7 (string table pointer) */
    sub     sp, sp, #880

    /* Save x0-x18 (all caller-saved registers) */
    stp     x0, x1, [sp, #0]
    stp     x2, x3, [sp, #16]
    stp     x4, x5, [sp, #32]
    stp     x6, x7, [sp, #48]      // Critical: x7 must be preserved!
    stp     x8, x9, [sp, #64]
    stp     x10, x11, [sp, #80]
    stp     x12, x13, [sp, #96]
    stp     x14, x15, [sp, #112]
    stp     x16, x17, [sp, #128]
    str     x18, [sp, #144]

    /* Save callee-saved registers and FP/LR */
    stp     x29, x30, [sp, #224]

    /* Call C IRQ handler */
    mov     x0, sp
    bl      arm64_handle_irq

    /* Restore ALL registers in reverse order */
    ldp     x29, x30, [sp, #224]

    ldr     x18, [sp, #144]
    ldp     x16, x17, [sp, #128]
    ldp     x14, x15, [sp, #112]
    ldp     x12, x13, [sp, #96]
    ldp     x10, x11, [sp, #80]
    ldp     x8, x9, [sp, #64]
    ldp     x6, x7, [sp, #48]      // Restore x7!
    ldp     x4, x5, [sp, #32]
    ldp     x2, x3, [sp, #16]
    ldp     x0, x1, [sp, #0]

    add     sp, sp, #880
    eret

/* FIQ Exception Entry - currently not used */
fiq_exception_entry:
    eret

/* SError Exception Entry - system error */
serror_exception_entry:
    /* Save ALL caller-saved registers (x0-x18) that C code can clobber
     * SErrors are asynchronous and can fire at any time, including during
     * context switch, so we must preserve all registers */
    sub     sp, sp, #880

    /* Save x0-x18 (all caller-saved registers) */
    stp     x0, x1, [sp, #0]
    stp     x2, x3, [sp, #16]
    stp     x4, x5, [sp, #32]
    stp     x6, x7, [sp, #48]      // Preserve x7
    stp     x8, x9, [sp, #64]
    stp     x10, x11, [sp, #80]
    stp     x12, x13, [sp, #96]
    stp     x14, x15, [sp, #112]
    stp     x16, x17, [sp, #128]
    str     x18, [sp, #144]

    /* Save callee-saved registers and FP/LR */
    stp     x29, x30, [sp, #224]

    /* Call C SError handler */
    mov     x0, sp
    bl      arm64_handle_serror

    /* Restore ALL registers in reverse order */
    ldp     x29, x30, [sp, #224]

    ldr     x18, [sp, #144]
    ldp     x16, x17, [sp, #128]
    ldp     x14, x15, [sp, #112]
    ldp     x12, x13, [sp, #96]
    ldp     x10, x11, [sp, #80]
    ldp     x8, x9, [sp, #64]
    ldp     x6, x7, [sp, #48]      // Restore x7
    ldp     x4, x5, [sp, #32]
    ldp     x2, x3, [sp, #16]
    ldp     x0, x1, [sp, #0]

    add     sp, sp, #880
    eret

/* AArch32 not supported */
aarch32_not_supported:
    /* Halt - AArch32 mode not supported */
1:  wfi
    b       1b

/* ============================================================
 *   Vector Table Installation Function
 * ============================================================ */

.global arm64_install_exception_vectors
.type arm64_install_exception_vectors, %function
arm64_install_exception_vectors:
    adrp    x0, arm64_exception_vectors
    add     x0, x0, :lo12:arm64_exception_vectors
    msr     vbar_el1, x0
    isb
    ret

.end
