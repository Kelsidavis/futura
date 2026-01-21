// SPDX-License-Identifier: MPL-2.0
/*
 * console.h - Kernel console interface
 *
 * Copyright (c) 2025 Kelsi Davis
 * Licensed under the MPL v2.0 — see LICENSE for details.
 *
 * Provides console initialization and input thread management for the
 * kernel's primary text output and input interface. The console supports
 * both serial and framebuffer output depending on build configuration.
 */

#pragma once

/**
 * Initialize the console subsystem.
 *
 * Sets up the primary console output (serial port and/or framebuffer).
 * Must be called early in boot before any console I/O. After this call,
 * fut_printf() and other output functions become available.
 *
 * Initialization order:
 *   1. Hardware detection (serial port, framebuffer)
 *   2. Output buffer allocation
 *   3. Character device registration (/dev/console)
 */
void fut_console_init(void);

/**
 * Start the console input thread.
 *
 * Creates a kernel thread to handle console input (keyboard, serial).
 * Must be called AFTER scheduler initialization (from kernel_main after
 * fut_sched_init) since thread creation requires a running scheduler.
 *
 * The input thread:
 *   - Polls keyboard/serial for input
 *   - Buffers keystrokes for read operations
 *   - Handles line editing in canonical mode
 */
void fut_console_start_input_thread(void);
