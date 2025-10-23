// SPDX-License-Identifier: MPL-2.0
/*
 * kernel/hal/halt.h - Hardware Abstraction Layer for CPU halt/sleep
 *
 * Provides platform-independent interface for CPU halt and wait-for-interrupt operations.
 * Platform-specific implementations:
 * - x86-64: Uses hlt instruction
 * - ARM64: Uses wfi (wait for interrupt) instruction
 */

#pragma once

/**
 * Halt the CPU unconditionally.
 * This is typically used when the kernel cannot proceed further.
 * x86-64: Executes 'hlt' instruction (halts until interrupt)
 * ARM64: Executes 'wfi' instruction (waits for interrupt)
 */
void hal_cpu_halt(void);

/**
 * Enable interrupts and wait for an interrupt.
 * Used by the idle thread to conserve power while remaining responsive.
 * x86-64: Executes 'sti; hlt' (set interrupt flag, then halt)
 * ARM64: Executes 'msr daifset, #2; wfi' (enable IRQ, then wait)
 */
void hal_cpu_wait_intr(void);

/**
 * Halt the CPU with a panic message.
 * Prints the message and then halts.
 */
void hal_cpu_panic_halt(const char *msg);
