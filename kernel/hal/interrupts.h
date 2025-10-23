// SPDX-License-Identifier: MPL-2.0
/*
 * kernel/hal/interrupts.h - Hardware Abstraction Layer for interrupt control
 *
 * Provides platform-independent interface for enabling and disabling interrupts.
 * Platform-specific implementations:
 * - x86-64: Uses cli/sti instructions
 * - ARM64: Uses msr daifclr/daifset instructions
 */

#pragma once

/**
 * Disable interrupts globally on the current CPU.
 * x86-64: Executes 'cli' (clear interrupt flag)
 * ARM64: Executes 'msr daifclr, #2' (clear IRQ bit in DAIF)
 *
 * Returns previous interrupt state for use with hal_intr_restore().
 */
unsigned long hal_intr_disable(void);

/**
 * Enable interrupts globally on the current CPU.
 * x86-64: Executes 'sti' (set interrupt flag)
 * ARM64: Executes 'msr daifset, #2' (set IRQ bit in DAIF)
 */
void hal_intr_enable(void);

/**
 * Restore interrupt state to a previous value.
 * Used to restore the interrupt state saved by hal_intr_disable().
 *
 * @param state - Previously saved interrupt state from hal_intr_disable()
 */
void hal_intr_restore(unsigned long state);

/**
 * Save current interrupt state without changing it.
 * Returns the current state for inspection.
 */
unsigned long hal_intr_state(void);

/**
 * Check if interrupts are currently enabled.
 * Returns non-zero if enabled, zero if disabled.
 */
int hal_intr_enabled(void);
