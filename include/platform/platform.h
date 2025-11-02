/* platform.h - Futura OS Platform Abstraction Layer
 *
 * Copyright (c) 2025 Kelsi Davis
 * Licensed under the MPL v2.0 — see LICENSE for details.
 *
 * Unified interface for platform-specific operations.
 * All architecture-specific code must implement these operations.
 */

#pragma once

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>
#include <config/futura_config.h>

/* Forward declarations */
struct fut_thread;
struct fut_interrupt_frame;

/* ============================================================
 *   Platform Initialization
 * ============================================================ */

/**
 * Platform-specific early initialization.
 * Called before kernel subsystems are initialized.
 *
 * @param boot_magic   Boot loader magic number
 * @param boot_info    Boot loader information structure
 */
void fut_platform_early_init(uint32_t boot_magic, void *boot_info);

/**
 * Platform-specific late initialization.
 * Called after kernel subsystems are initialized.
 */
void fut_platform_late_init(void);

/* ============================================================
 *   Serial/UART Console (Debug Output)
 * ============================================================ */

/**
 * Initialize serial/UART console for debugging.
 */
void fut_serial_init(void);

/**
 * Enable interrupt-driven UART mode after system initialization.
 * Should be called after all subsystems are initialized.
 */
void fut_serial_enable_irq_mode(void);

/**
 * Write a single character to serial console.
 *
 * @param c Character to write
 */
void fut_serial_putc(char c);

/**
 * Write a null-terminated string to serial console.
 *
 * @param str String to write
 */
void fut_serial_puts(const char *str);

/**
 * Read a character from the serial console (non-blocking).
 *
 * @return Character read (0-255), or -1 if no data available
 */
int fut_serial_getc(void);

/**
 * Read a character from the serial console (blocking).
 * Waits until a character is available.
 *
 * @return Character read (0-255)
 */
int fut_serial_getc_blocking(void);

/**
 * Flush any pending characters from the serial input buffer.
 * This clears garbage characters that may have accumulated.
 */
void fut_serial_flush_input(void);

/**
 * Formatted output to serial console.
 *
 * @param fmt Format string
 * @param ... Variable arguments
 */
void fut_printf(const char *fmt, ...);

/* ============================================================
 *   Interrupt Management
 * ============================================================ */

/**
 * Enable CPU interrupts.
 */
void fut_enable_interrupts(void);

/**
 * Disable CPU interrupts.
 */
void fut_disable_interrupts(void);

/**
 * Save interrupt state and disable interrupts.
 *
 * @return Previous interrupt state (for fut_restore_interrupts)
 */
uint64_t fut_save_and_disable_interrupts(void);

/**
 * Restore interrupt state.
 *
 * @param state State returned from fut_save_and_disable_interrupts
 */
void fut_restore_interrupts(uint64_t state);

/**
 * Enable specific hardware IRQ.
 *
 * @param irq IRQ number
 */
void fut_irq_enable(uint8_t irq);

/**
 * Disable specific hardware IRQ.
 *
 * @param irq IRQ number
 */
void fut_irq_disable(uint8_t irq);

/**
 * Send End-Of-Interrupt signal.
 *
 * @param irq IRQ number
 */
void fut_irq_send_eoi(uint8_t irq);

/* ============================================================
 *   Timer Management
 * ============================================================ */

/**
 * Initialize platform timer (PIT, ARM generic timer, etc.).
 *
 * @param frequency Timer frequency in Hz
 */
void fut_timer_init(uint32_t frequency);

/**
 * Get current timer tick count.
 *
 * @return Current tick count
 */
uint64_t fut_timer_get_ticks(void);

/**
 * Get timer frequency in Hz.
 *
 * @return Timer frequency
 */
uint32_t fut_timer_get_frequency(void);

/* ============================================================
 *   Context Switching
 * ============================================================ */

/**
 * Switch to a different thread context.
 * This is a low-level assembly function.
 *
 * @param prev Previous thread (context will be saved here)
 * @param next Next thread (context will be loaded from here)
 */
void fut_context_switch(struct fut_thread *prev, struct fut_thread *next);

/**
 * Initialize thread context for first execution.
 *
 * @param thread       Thread to initialize
 * @param entry        Entry point function
 * @param arg          Argument to pass to entry function
 * @param stack_base   Stack base address
 * @param stack_size   Stack size in bytes
 */
void fut_context_init(struct fut_thread *thread,
                      void (*entry)(void *),
                      void *arg,
                      void *stack_base,
                      size_t stack_size);

/* ============================================================
 *   Memory Management
 * ============================================================ */

/**
 * Initialize platform memory management (paging, MMU, etc.).
 *
 * @param mem_lower Lower memory bound (from boot loader)
 * @param mem_upper Upper memory bound (from boot loader)
 */
void fut_platform_mem_init(uint64_t mem_lower, uint64_t mem_upper);

/**
 * Get physical memory size in bytes.
 *
 * @return Total physical memory
 */
uint64_t fut_platform_get_mem_size(void);

/**
 * Flush TLB (Translation Lookaside Buffer).
 */
void fut_platform_tlb_flush(void);

/**
 * Flush TLB entry for specific virtual address.
 *
 * @param vaddr Virtual address
 */
void fut_platform_tlb_flush_page(uint64_t vaddr);

/* ============================================================
 *   CPU Information
 * ============================================================ */

/**
 * Get current CPU ID (for SMP systems).
 *
 * @return CPU ID (0 for single-core)
 */
uint32_t fut_platform_get_cpu_id(void);

/**
 * Get number of available CPU cores.
 *
 * @return Number of CPUs
 */
uint32_t fut_platform_get_cpu_count(void);

/**
 * Halt CPU until next interrupt.
 */
void fut_platform_cpu_halt(void);

/**
 * Busy-wait for specified microseconds.
 *
 * @param usec Microseconds to wait
 */
void fut_platform_udelay(uint32_t usec);

/* ============================================================
 *   I/O Port Operations (x86_64 specific, stubbed on ARM64)
 * ============================================================ */

#ifdef ARCH_X86_64

/**
 * Output byte to I/O port.
 *
 * @param port Port address
 * @param value Byte to write
 */
void hal_outb(uint16_t port, uint8_t value);

/**
 * Input byte from I/O port.
 *
 * @param port Port address
 * @return Byte read from port
 */
uint8_t hal_inb(uint16_t port);

/**
 * Output word to I/O port.
 *
 * @param port Port address
 * @param value Word to write
 */
void hal_outw(uint16_t port, uint16_t value);

/**
 * Input word from I/O port.
 *
 * @param port Port address
 * @return Word read from port
 */
uint16_t hal_inw(uint16_t port);

/**
 * Output double-word to I/O port.
 *
 * @param port Port address
 * @param value Double-word to write
 */
void hal_outl(uint16_t port, uint32_t value);

/**
 * Input double-word from I/O port.
 *
 * @param port Port address
 * @return Double-word read from port
 */
uint32_t hal_inl(uint16_t port);

#endif /* ARCH_X86_64 */

/* ============================================================
 *   MMIO Operations (ARM64 specific, works on x86_64 too)
 * ============================================================ */

/**
 * Read 32-bit value from MMIO address.
 *
 * @param addr MMIO address
 * @return Value read
 */
uint32_t mmio_read32(volatile void *addr);

/**
 * Write 32-bit value to MMIO address.
 *
 * @param addr MMIO address
 * @param value Value to write
 */
void mmio_write32(volatile void *addr, uint32_t value);

/**
 * Read 64-bit value from MMIO address.
 *
 * @param addr MMIO address
 * @return Value read
 */
uint64_t mmio_read64(volatile void *addr);

/**
 * Write 64-bit value to MMIO address.
 *
 * @param addr MMIO address
 * @param value Value to write
 */
void mmio_write64(volatile void *addr, uint64_t value);

/* ============================================================
 *   Platform-Specific Panic Handler
 * ============================================================ */

/**
 * Platform-specific panic/halt.
 * Should never return.
 *
 * @param message Panic message
 */
[[noreturn]] void fut_platform_panic(const char *message);

/* ============================================================
 *   Debugging Support
 * ============================================================ */

/**
 * Dump CPU registers for debugging.
 *
 * @param frame Interrupt frame containing register state
 */
void fut_platform_dump_registers(struct fut_interrupt_frame *frame);

/**
 * Print stack trace for debugging.
 *
 * @param max_frames Maximum number of frames to print
 */
void fut_platform_stack_trace(int max_frames);

/* ============================================================
 *   Architecture Detection
 * ============================================================ */

/**
 * Get platform name string.
 *
 * @return Platform name (e.g., "x86_64", "arm64")
 */
const char *fut_platform_get_name(void);

/**
 * Get platform features as bitmask.
 *
 * @return Feature bitmask
 */
uint64_t fut_platform_get_features(void);

/* Platform feature flags */
#define PLATFORM_FEATURE_MMU        (1ULL << 0)
#define PLATFORM_FEATURE_FPU        (1ULL << 1)
#define PLATFORM_FEATURE_SIMD       (1ULL << 2)
#define PLATFORM_FEATURE_SMP        (1ULL << 3)
#define PLATFORM_FEATURE_TIMER      (1ULL << 4)
#define PLATFORM_FEATURE_UART       (1ULL << 5)
