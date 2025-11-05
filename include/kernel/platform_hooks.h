/* platform_hooks.h - Platform-Specific Initialization Hooks
 *
 * Copyright (c) 2025 Kelsi Davis
 * Licensed under the MPL v2.0 — see LICENSE for details.
 *
 * Defines callback interface for platform-specific initialization.
 * Platforms implement these hooks in platform/<arch>/platform_init.c
 */

#ifndef FUTURA_PLATFORM_HOOKS_H
#define FUTURA_PLATFORM_HOOKS_H

#include <stdint.h>
#include <stddef.h>

/**
 * arch_memory_config - Get platform-specific memory layout
 * @ram_start: Output - Start of usable RAM (physical address)
 * @ram_end: Output - End of usable RAM (physical address)
 * @heap_size: Output - Requested kernel heap size in bytes
 *
 * Called early during boot to determine memory layout.
 * Must be implemented by each platform.
 */
void arch_memory_config(uintptr_t *ram_start, uintptr_t *ram_end, size_t *heap_size);

/**
 * arch_early_init - Platform-specific early initialization
 *
 * Called before any kernel subsystems are initialized.
 * Platform should initialize:
 * - Serial/debug output
 * - Interrupt controllers (but not enable interrupts)
 * - Timers (but not start them)
 * - MMU/paging (if not already done by boot code)
 *
 * Must be implemented by each platform.
 */
void arch_early_init(void);

/**
 * arch_late_init - Platform-specific late initialization
 *
 * Called after all core kernel subsystems are ready:
 * - PMM, heap, timers
 * - VFS, networking
 * - Scheduler, threading
 *
 * Platform should:
 * - Spawn init/userspace
 * - Enable interrupts if appropriate
 * - Launch platform-specific services
 *
 * Optional - weak symbol with default no-op implementation.
 */
void arch_late_init(void);

/**
 * arch_idle_loop - Platform-specific idle loop
 *
 * Called when kernel has nothing to do.
 * Should enter low-power state and wait for interrupts.
 *
 * Optional - weak symbol with default infinite loop.
 */
void arch_idle_loop(void) __attribute__((noreturn));

#endif /* FUTURA_PLATFORM_HOOKS_H */
