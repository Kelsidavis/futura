/* fut_timer.c - Futura OS Timer Subsystem (C23)
 *
 * Copyright (c) 2025 Kelsi Davis / Licensed under the MPL v2.0 — see LICENSE for details
 *
 * Timer tick handling, sleep queue management, and thread waking.
 */

#include "../../include/kernel/fut_timer.h"
#include "../../include/kernel/fut_thread.h"
#include "../../include/kernel/fut_sched.h"
#include <stdatomic.h>

/* I/O port access from platform layer */
extern void hal_outb(uint16_t port, uint8_t value);
extern uint8_t hal_inb(uint16_t port);

/* Convenience wrappers to match expected names */
static inline void outb(uint16_t port, uint8_t val) { hal_outb(port, val); }
static inline uint8_t inb(uint16_t port) { return hal_inb(port); }

/* External declarations */
extern void fut_printf(const char *fmt, ...);
extern void fut_schedule(void);
extern void serial_puts(const char *s);

/* ============================================================
 *   Timer State
 * ============================================================ */

/* Global tick counter (milliseconds) */
static _Atomic uint64_t system_ticks = 0;

/* Sleep queue (sorted by wake_time) */
static fut_thread_t *sleep_queue_head = nullptr;

/* Sleep queue lock */
static fut_spinlock_t sleep_lock = { .locked = 0 };

/* ============================================================
 *   Sleep Queue Management
 * ============================================================ */

/**
 * Insert thread into sleep queue (sorted by wake time).
 */
void fut_sleep_until(fut_thread_t *thread, uint64_t millis) {
    if (!thread) {
        return;
    }

    // Calculate absolute wake time
    uint64_t current = atomic_load_explicit(&system_ticks, memory_order_relaxed);
    thread->wake_time = current + millis;
    thread->state = FUT_THREAD_SLEEPING;

    // Remove from scheduler ready queue
    fut_sched_remove_thread(thread);

    // Insert into sleep queue (sorted by wake_time)
    fut_spinlock_acquire(&sleep_lock);

    if (!sleep_queue_head || thread->wake_time < sleep_queue_head->wake_time) {
        // Insert at head
        thread->next = sleep_queue_head;
        thread->prev = nullptr;
        if (sleep_queue_head) {
            sleep_queue_head->prev = thread;
        }
        sleep_queue_head = thread;
    } else {
        // Find insertion point
        fut_thread_t *curr = sleep_queue_head;
        while (curr->next && curr->next->wake_time <= thread->wake_time) {
            curr = curr->next;
        }

        // Insert after curr
        thread->next = curr->next;
        thread->prev = curr;
        if (curr->next) {
            curr->next->prev = thread;
        }
        curr->next = thread;
    }

    fut_spinlock_release(&sleep_lock);
}

/**
 * Wake threads whose time has expired.
 */
static void wake_sleeping_threads(void) {
    uint64_t current = atomic_load_explicit(&system_ticks, memory_order_relaxed);

    fut_spinlock_acquire(&sleep_lock);

    // Check sleep queue head
    while (sleep_queue_head && sleep_queue_head->wake_time <= current) {
        fut_thread_t *thread = sleep_queue_head;

        // Remove from sleep queue
        sleep_queue_head = thread->next;
        if (sleep_queue_head) {
            sleep_queue_head->prev = nullptr;
        }

        thread->next = nullptr;
        thread->prev = nullptr;

        // Mark as ready and add to scheduler
        thread->state = FUT_THREAD_READY;

        fut_spinlock_release(&sleep_lock);
        fut_sched_add_thread(thread);
        fut_spinlock_acquire(&sleep_lock);
    }

    fut_spinlock_release(&sleep_lock);
}

/* ============================================================
 *   Timer Tick Handler
 * ============================================================ */

/**
 * Timer tick handler - called from timer interrupt.
 *
 * Increments tick counter, wakes sleeping threads, and triggers scheduling.
 */
void fut_timer_tick(void) {
    // Increment tick counter
    atomic_fetch_add_explicit(&system_ticks, 1, memory_order_relaxed);

    // Wake any threads whose sleep time has expired
    wake_sleeping_threads();

    // Only trigger preemptive scheduling if the scheduler has been started
    // (i.e., current_thread != NULL). This prevents premature scheduling
    // before the test harness has created any threads.
    extern fut_thread_t *fut_thread_current(void);
    if (fut_thread_current() != nullptr) {
        // Trigger preemptive scheduling
        // This will call fut_switch_context_irq() if a thread switch is needed
        fut_schedule();
    }
}

/**
 * Get current system ticks (milliseconds).
 */
uint64_t fut_get_ticks(void) {
    return atomic_load_explicit(&system_ticks, memory_order_relaxed);
}

/* ============================================================
 *   PIT (Programmable Interval Timer) Hardware
 * ============================================================ */

/**
 * Program the PIT to generate timer interrupts at specified frequency.
 *
 * @param frequency Desired frequency in Hz (typically 1000 Hz = 1ms tick)
 */
static void pit_init(uint32_t frequency) {
    // Calculate divisor: base frequency / desired frequency
    uint32_t divisor = PIT_BASE_HZ / frequency;
    if (divisor > 65535) {
        divisor = 65535;  // Maximum divisor for 16-bit counter
    }

    // Command byte: channel 0, lo/hi byte, rate generator (mode 2)
    // 0x36 = 00 11 011 0
    //        |  |  |   |
    //        |  |  |   +-- BCD mode (0 = binary)
    //        |  |  +------ Mode 2 (rate generator)
    //        |  +--------- Access mode (3 = lo/hi byte)
    //        +------------ Channel 0
    outb(0x43, 0x36);

    // Send divisor (lo byte, then hi byte)
    outb(0x40, (uint8_t)(divisor & 0xFF));
    outb(0x40, (uint8_t)((divisor >> 8) & 0xFF));

    fut_printf("[fut_timer] PIT programmed for %u Hz\n", frequency);
}

/**
 * Initialize timer subsystem.
 * Programs PIT hardware and initializes sleep queue.
 */
void fut_timer_init(void) {
    atomic_store_explicit(&system_ticks, 0, memory_order_relaxed);
    sleep_queue_head = nullptr;
    fut_spinlock_init(&sleep_lock);

    // Program PIT hardware
    pit_init(FUT_TIMER_HZ);

    fut_printf("[TIMER] Timer subsystem initialized (%u Hz)\n", FUT_TIMER_HZ);
}
