// SPDX-License-Identifier: MPL-2.0

#pragma once

void fut_console_init(void);

/**
 * Start the console input thread.
 * Must be called AFTER scheduler initialization (from kernel_main after fut_sched_init).
 */
void fut_console_start_input_thread(void);
