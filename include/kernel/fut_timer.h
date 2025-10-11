/* fut_timer.h - Futura OS Timer Subsystem Header (C23)
 *
 * Copyright (c) 2025 Kelsi Davis
 * Licensed under the MPL v2.0 — see LICENSE for details.
 *
 * Timer tick handling and sleep management.
 */

#ifndef FUT_TIMER_H
#define FUT_TIMER_H

#include <stdint.h>
#include "fut_thread.h"

/* Timer frequency in Hz - 100 Hz for preemptive scheduling */
#define FUT_TIMER_HZ 100

/* PIT (Programmable Interval Timer) base frequency */
#define PIT_BASE_HZ 1193182

/**
 * Initialize timer subsystem.
 * Programs PIT to generate interrupts at FUT_TIMER_HZ.
 */
void fut_timer_init(void);

/**
 * Timer tick handler - called from IRQ0 handler.
 * Increments tick counter, wakes sleeping threads, triggers scheduling.
 */
void fut_timer_tick(void);

/**
 * Get current system ticks (milliseconds since boot).
 */
uint64_t fut_get_ticks(void);

/**
 * Put thread to sleep for specified milliseconds.
 * Thread is added to sleep queue and removed from ready queue.
 *
 * @param thread Thread to sleep
 * @param millis Milliseconds to sleep
 */
void fut_sleep_until(fut_thread_t *thread, uint64_t millis);

#endif /* FUT_TIMER_H */
