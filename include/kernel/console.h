/* include/kernel/console.h - Console interface functions
 *
 * Copyright (c) 2025 Kelsi Davis
 * Licensed under the MPL v2.0 — see LICENSE for details.
 *
 * Provides console initialization and input thread management.
 */

#pragma once

void fut_console_init(void);

/**
 * Start the console input thread.
 * Must be called AFTER scheduler initialization (from kernel_main after fut_sched_init).
 */
void fut_console_start_input_thread(void);
