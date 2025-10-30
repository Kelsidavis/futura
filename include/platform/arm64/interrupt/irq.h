/* irq.h - ARM64 Interrupt and Exception Handling
 *
 * Copyright (c) 2025 Kelsi Davis
 * Licensed under the MPL v2.0 — see LICENSE for details.
 *
 * ARM64 (AArch64) interrupt controller abstraction and IRQ routing.
 */

#pragma once

#include <platform/arm64/regs.h>
#include <stdint.h>
#include <stdbool.h>

/* ============================================================
 *   IRQ Handler Types
 * ============================================================ */

/**
 * IRQ handler function type.
 * @param irq_num IRQ number that triggered
 * @param frame Exception frame with full CPU state
 */
typedef void (*fut_irq_handler_t)(int irq_num, fut_interrupt_frame_t *frame);

/* ============================================================
 *   IRQ Numbers and Sources
 * ============================================================ */

#define FUT_IRQ_TIMER           30      /* ARM Generic Timer IRQ (SPI) */
#define FUT_IRQ_UART            33      /* PL011 UART IRQ (typical) */
#define FUT_IRQ_VIRTIO          40      /* VirtIO devices base IRQ */

#define FUT_MAX_IRQS            256     /* Maximum IRQ handlers */

/* ============================================================
 *   Interrupt Control Register Accessors
 * ============================================================ */

/**
 * Read Interrupt Mask Bits (DAIF).
 * Returns the current interrupt mask state.
 * @return DAIF register value
 */
static inline uint64_t fut_read_daif(void) {
    uint64_t daif;
    __asm__ volatile("mrs %0, daif" : "=r"(daif));
    return daif;
}

/**
 * Write Interrupt Mask Bits (DAIF).
 * Sets the interrupt mask state.
 * @param daif Value to write to DAIF
 */
static inline void fut_write_daif(uint64_t daif) {
    __asm__ volatile("msr daif, %0" :: "r"(daif) : "memory");
}

/**
 * Disable IRQs specifically (set DAIF.I bit).
 */
static inline void fut_disable_irqs(void) {
    __asm__ volatile("msr daifset, #0x2" ::: "memory");  /* Set I bit */
}

/**
 * Enable IRQs specifically (clear DAIF.I bit).
 */
static inline void fut_enable_irqs(void) {
    __asm__ volatile("msr daifclr, #0x2" ::: "memory");  /* Clear I bit */
}

/**
 * Check if interrupts are enabled.
 * @return true if IRQs are enabled, false if masked
 */
static inline bool fut_interrupts_enabled(void) {
    uint64_t daif = fut_read_daif();
    return (daif & PSTATE_I_BIT) == 0;
}

/* ============================================================
 *   Exception Syndrome Register (ESR) Utilities
 * ============================================================ */

/**
 * Get exception class from ESR.
 * @param esr Exception Syndrome Register value
 * @return Exception class (EC field)
 */
static inline uint32_t fut_esr_get_ec(uint64_t esr) {
    return (esr >> 26) & 0x3F;
}

/**
 * Get instruction length from ESR (for data/instruction aborts).
 * @param esr Exception Syndrome Register value
 * @return Instruction length (0=16-bit, 1=32-bit)
 */
static inline int fut_esr_get_il(uint64_t esr) {
    return (esr >> 25) & 0x1;
}

/**
 * Get fault status code from ESR (for page faults).
 * @param esr Exception Syndrome Register value
 * @return Fault status code
 */
static inline uint32_t fut_esr_get_fsc(uint64_t esr) {
    return esr & 0x3F;
}

/* ============================================================
 *   ARM Generic Interrupt Controller (GICv2) Interface
 * ============================================================ */

/**
 * Initialize GICv2 (Generic Interrupt Controller).
 * Sets up the GIC for the kernel's use.
 */
void fut_gic_init(void);

/**
 * Register an IRQ handler.
 * @param irq IRQ number to handle
 * @param handler Handler function
 * @return 0 on success, negative on error
 */
int fut_register_irq_handler(int irq, fut_irq_handler_t handler);

/**
 * Unregister an IRQ handler.
 * @param irq IRQ number to unregister
 * @return 0 on success, negative on error
 */
int fut_unregister_irq_handler(int irq);

/**
 * Acknowledge interrupt from GIC.
 * Reads the interrupt acknowledge register to get IRQ number.
 * @return IRQ number, or -1 if spurious/invalid
 */
int fut_irq_acknowledge(void);

/**
 * Send end-of-interrupt signal to GIC.
 * @param irq IRQ number to acknowledge
 */
void fut_irq_send_eoi(uint8_t irq);

/**
 * Get current GIC interrupt priority.
 * @return Priority value
 */
uint32_t fut_irq_get_priority(int irq);

/**
 * Set GIC interrupt priority.
 * Lower values = higher priority (0 is highest).
 * @param irq IRQ number
 * @param priority Priority value (0-255)
 */
void fut_irq_set_priority(int irq, uint32_t priority);

/**
 * Enable a specific IRQ.
 * @param irq IRQ number to enable
 */
void fut_irq_enable(uint8_t irq);

/**
 * Disable a specific IRQ.
 * @param irq IRQ number to disable
 */
void fut_irq_disable(uint8_t irq);

/**
 * Check if IRQ is enabled.
 * @param irq IRQ number to check
 * @return true if enabled, false if disabled
 */
bool fut_irq_is_enabled(int irq);

/* ============================================================
 *   ARM Generic Timer Interface
 * ============================================================ */

/**
 * Initialize ARM Generic Timer.
 * Sets up the system timer for periodic interrupts.
 * @param frequency Timer frequency in Hz
 */
void fut_timer_init(uint32_t frequency);

/**
 * Get current timer count.
 * @return Current value of CNTPCT_EL0 (physical counter)
 */
static inline uint64_t fut_timer_read_count(void) {
    uint64_t cnt;
    __asm__ volatile("mrs %0, cntpct_el0" : "=r"(cnt));
    return cnt;
}

/**
 * Get timer frequency (ticks per second).
 * @return Frequency in Hz
 */
uint32_t fut_timer_get_frequency(void);

/**
 * Set timer interrupt timeout (relative to now).
 * @param ticks Number of timer ticks from now
 */
void fut_timer_set_timeout(uint64_t ticks);

/**
 * Handle timer interrupt.
 * Called from IRQ handler when timer fires.
 */
void fut_timer_irq_handler(void);

/* ============================================================
 *   Exception Handling
 * ============================================================ */

/**
 * Handle synchronous exception.
 * Called for data aborts, instruction aborts, system calls, etc.
 * @param frame Exception frame
 * @param esr Exception syndrome register
 * @param far Fault address register (if applicable)
 */
void fut_handle_sync_exception(fut_interrupt_frame_t *frame, uint64_t esr, uint64_t far);

/**
 * Handle data abort exception.
 * Called when data memory access fails.
 * @param frame Exception frame
 * @param esr Exception syndrome register
 * @param far Fault address register
 */
void fut_handle_data_abort(fut_interrupt_frame_t *frame, uint64_t esr, uint64_t far);

/**
 * Handle instruction abort exception.
 * Called when instruction fetch fails.
 * @param frame Exception frame
 * @param esr Exception syndrome register
 * @param far Fault address register
 */
void fut_handle_instr_abort(fut_interrupt_frame_t *frame, uint64_t esr, uint64_t far);

/**
 * Handle system call (SVC) exception.
 * Called when user code issues SVC instruction.
 * @param frame Exception frame
 */
void fut_handle_syscall(fut_interrupt_frame_t *frame);

/* ============================================================
 *   Interrupt Dispatch
 * ============================================================ */

/**
 * Main IRQ dispatch function.
 * Called from assembly exception handler.
 * Reads IRQ number from GIC and dispatches to appropriate handler.
 * @param frame Exception frame
 */
void fut_irq_dispatch(fut_interrupt_frame_t *frame);

/**
 * Main exception dispatch function.
 * Called from assembly exception handlers.
 * Routes synchronous exceptions to appropriate handler.
 * @param frame Exception frame
 * @param esr Exception syndrome register
 */
void fut_exception_dispatch(fut_interrupt_frame_t *frame, uint64_t esr);

/* ============================================================
 *   Reschedule Signaling
 * ============================================================ */

/**
 * Check if scheduler should be run (reschedule pending).
 * @return true if reschedule is needed, false otherwise
 */
bool fut_reschedule_pending(void);

/**
 * Mark that reschedule is needed.
 * Called by interrupt handlers that need to trigger scheduling.
 */
void fut_request_reschedule(void);

/**
 * Clear reschedule flag.
 * Called by scheduler when handling context switch.
 */
void fut_clear_reschedule(void);
