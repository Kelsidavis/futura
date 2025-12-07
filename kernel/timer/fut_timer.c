/* fut_timer.c - Futura OS Timer Subsystem (C23)
 *
 * Copyright (c) 2025 Kelsi Davis / Licensed under the MPL v2.0 — see LICENSE for details
 *
 * Timer tick handling, sleep queue management, and thread waking.
 */

#include "../../include/kernel/fut_timer.h"
#include "../../include/kernel/fut_thread.h"
#include "../../include/kernel/fut_sched.h"
#include "../../include/kernel/fut_memory.h"
#include "../../include/kernel/fut_task.h"
#include "../../include/kernel/signal.h"
#include <stdatomic.h>

/* Forward declaration: LAPIC EOI is only used in interrupt handler */
extern void lapic_send_eoi(void);

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
extern void fut_irq_send_eoi(uint8_t irq);
extern int fut_signal_send(struct fut_task *task, int signum);

/* Forward declarations */
struct fut_task;

/* ============================================================
 *   Timer State
 * ============================================================ */

/* Global tick counter (milliseconds) */
static _Atomic uint64_t system_ticks = 0;

/* Sleep queue (sorted by wake_time) */
static fut_thread_t *sleep_queue_head = nullptr;

/* Sleep queue lock */
static fut_spinlock_t sleep_lock = { .locked = 0 };

typedef struct fut_timer_event {
    uint64_t expiry;
    void (*cb)(void *);
    void *arg;
    struct fut_timer_event *next;
} fut_timer_event_t;

static fut_timer_event_t *timer_events_head = nullptr;
static fut_spinlock_t timer_events_lock = { .locked = 0 };

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

static void process_timer_events(void) {
    uint64_t current = atomic_load_explicit(&system_ticks, memory_order_relaxed);

    fut_spinlock_acquire(&timer_events_lock);
    while (timer_events_head && timer_events_head->expiry <= current) {
        fut_timer_event_t *ev = timer_events_head;
        timer_events_head = ev->next;

        fut_spinlock_release(&timer_events_lock);
        if (ev->cb) {
            ev->cb(ev->arg);
        }
        fut_free(ev);
        fut_spinlock_acquire(&timer_events_lock);
    }
    fut_spinlock_release(&timer_events_lock);
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
    uint64_t ticks = atomic_fetch_add_explicit(&system_ticks, 1, memory_order_relaxed);

    // Debug: Log first few timer ticks to confirm IRQs are firing
    if (ticks < 5) {
        extern void fut_printf(const char *fmt, ...);
        fut_printf("[TIMER] Tick %llu\n", (unsigned long long)ticks);
    }

    // Wake any threads whose sleep time has expired
    wake_sleeping_threads();

    // Process timer events
    process_timer_events();

    // Check for expired alarms and deliver SIGALRM
    extern fut_task_t *fut_task_list;
    uint64_t current_ms = atomic_load_explicit(&system_ticks, memory_order_relaxed);

    for (fut_task_t *task = fut_task_list; task != nullptr; task = task->next) {
        if (task->alarm_expires_ms > 0 && current_ms >= task->alarm_expires_ms) {
            // Alarm has expired - queue SIGALRM for this task
            fut_signal_send(task, SIGALRM);
            // Clear alarm (only one alarm per task)
            task->alarm_expires_ms = 0;
        }
    }

    // Only trigger preemptive scheduling if the scheduler has been started
    // (i.e., current_thread != NULL). This prevents premature scheduling
    // before the test harness has created any threads.
    extern fut_thread_t *fut_thread_current(void);
    fut_thread_t *current = fut_thread_current();

    // Debug: Log timer tick to diagnose preemption issues (sparse logging)
    static int timer_debug_count = 0;
    if ((ticks % 50 == 0 && timer_debug_count < 50) || (current && current->tid >= 6)) {
        fut_printf("[TIMER-DBG] tick: current_tid=%llu ticks=%llu\n",
                   current ? (unsigned long long)current->tid : 0ULL, ticks);
        if (timer_debug_count < 50) timer_debug_count++;
    }

    if (current != nullptr) {
        // Trigger preemptive scheduling
        // This will call fut_switch_context_irq() if a thread switch is needed
        fut_schedule();
    }
}

int fut_timer_start(uint64_t ticks_from_now, void (*cb)(void *), void *arg) {
    if (!cb) {
        return -1;
    }
    if (ticks_from_now == 0) {
        cb(arg);
        return 0;
    }

    fut_timer_event_t *ev = (fut_timer_event_t *)fut_malloc(sizeof(fut_timer_event_t));
    if (!ev) {
        return -1;
    }
    uint64_t current = atomic_load_explicit(&system_ticks, memory_order_relaxed);
    ev->expiry = current + ticks_from_now;
    ev->cb = cb;
    ev->arg = arg;
    ev->next = nullptr;

    fut_spinlock_acquire(&timer_events_lock);
    if (!timer_events_head || ev->expiry < timer_events_head->expiry) {
        ev->next = timer_events_head;
        timer_events_head = ev;
    } else {
        fut_timer_event_t *curr = timer_events_head;
        while (curr->next && curr->next->expiry <= ev->expiry) {
            curr = curr->next;
        }
        ev->next = curr->next;
        curr->next = ev;
    }
    fut_spinlock_release(&timer_events_lock);
    return 0;
}

int fut_timer_cancel(void (*cb)(void *), void *arg) {
    if (!cb) {
        return -1;
    }
    fut_spinlock_acquire(&timer_events_lock);
    fut_timer_event_t *prev = NULL;
    fut_timer_event_t *curr = timer_events_head;
    while (curr) {
        if (curr->cb == cb && curr->arg == arg) {
            if (prev) {
                prev->next = curr->next;
            } else {
                timer_events_head = curr->next;
            }
            fut_spinlock_release(&timer_events_lock);
            fut_free(curr);
            return 0;
        }
        prev = curr;
        curr = curr->next;
    }
    fut_spinlock_release(&timer_events_lock);
    return -1;
}

/**
 * Get current system ticks (milliseconds).
 */
uint64_t fut_get_ticks(void) {
    return atomic_load_explicit(&system_ticks, memory_order_relaxed);
}

/**
 * Get high-resolution time in nanoseconds since boot (TSC-based).
 * Uses the TSC (Time Stamp Counter) for sub-millisecond precision.
 */
uint64_t fut_get_time_ns(void) {
#if defined(__x86_64__)
    extern uint64_t fut_rdtsc(void);
    extern uint64_t fut_cycles_to_ns(uint64_t cycles);
    return fut_cycles_to_ns(fut_rdtsc());
#else
    /* Fallback to millisecond precision on non-x86_64 platforms */
    return fut_get_ticks() * 1000000ULL;
#endif
}

/**
 * Get high-resolution time in microseconds since boot (TSC-based).
 * Uses the TSC (Time Stamp Counter) for sub-millisecond precision.
 */
uint64_t fut_get_time_us(void) {
    return fut_get_time_ns() / 1000ULL;
}

void fut_timer_irq(void) {
    // Debug: Check if timer IRQ is firing at low level
    static int irq_debug_count = 0;
    uint64_t ticks = atomic_load(&system_ticks);
    if (ticks % 100 == 0 && irq_debug_count < 30) {
        serial_puts("[TIMER-IRQ] ");
        irq_debug_count++;
    }

    fut_timer_tick();

    /* Send EOI to LAPIC - in IOAPIC mode (which we use), only LAPIC EOI is needed.
     * The legacy 8259 PIC is disabled by ACPI initialization.
     *
     * NOTE: If fut_timer_tick() triggers a context switch via fut_switch_context_irq(),
     * that function does its own IRETQ and never returns here. In that case, we need
     * to send EOI from the context switch path instead. */
#ifdef __x86_64__
    lapic_send_eoi();
#endif
}

/* ============================================================
 *   PIT (Programmable Interval Timer) Hardware (x86-64 only)
 * ============================================================ */

#if defined(__x86_64__)
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
#endif

/**
 * Initialize timer subsystem.
 * Programs PIT hardware and initializes sleep queue.
 */
void fut_timer_subsystem_init(void) {
    atomic_store_explicit(&system_ticks, 0, memory_order_relaxed);
    sleep_queue_head = nullptr;
    fut_spinlock_init(&sleep_lock);
    timer_events_head = nullptr;
    fut_spinlock_init(&timer_events_lock);

    // Program PIT hardware (x86-64 only)
#if defined(__x86_64__)
    pit_init(FUT_TIMER_HZ);
    // Note: Timer IRQ will be unmasked later after ACPI initialization
#else
    // ARM64: Timer is already initialized by platform layer (fut_timer_init)
#endif

    fut_printf("[TIMER] Timer subsystem initialized (%u Hz)\n", FUT_TIMER_HZ);
}
