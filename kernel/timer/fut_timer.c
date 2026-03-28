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
#include "../../include/kernel/signal_frame.h"
#include <shared/fut_sigevent.h>
#include <kernel/errno.h>
#include <platform/platform.h>
#include <stdatomic.h>

#if defined(__x86_64__)
#include <platform/x86_64/interrupt/lapic.h>
#endif
/* lapic_send_eoi provided by lapic.h for x86_64 */

#if defined(__x86_64__)
/* hal_outb, hal_inb provided by platform/platform.h (x86_64 I/O ports only) */
static inline void outb(uint16_t port, uint8_t val) { hal_outb(port, val); }
static inline uint8_t inb(uint16_t port) { return hal_inb(port); }
#endif

/* External declarations */
#include <kernel/kprintf.h>
/* fut_schedule provided by kernel/fut_sched.h */
/* serial_puts, fut_irq_send_eoi provided by platform/platform.h */

/* Forward declarations */
struct fut_task;

/* ============================================================
 *   Timer State
 * ============================================================ */

/* Global tick counter (milliseconds) */
static _Atomic uint64_t system_ticks = 0;
static _Atomic uint64_t idle_ticks = 0;  /* Ticks where no user work was happening */
static _Atomic uint64_t user_ticks = 0;  /* Ticks in user-mode context (ring 3) */
static _Atomic uint64_t kern_ticks = 0;  /* Ticks in kernel-mode on behalf of user process */
static _Atomic uint64_t irq_ticks = 0;   /* Ticks in interrupt/softirq handling */

/* PSI (Pressure Stall Information) counters.
 * CPU "some": ticks where at least one runnable task was waiting (run queue > 1).
 * Memory/IO: tracked when tasks are waiting for memory/IO (simplified). */
static _Atomic uint64_t psi_cpu_some_us = 0;  /* Cumulative CPU stall microseconds */
static _Atomic uint64_t psi_cpu_full_us = 0;  /* Cumulative full CPU stall microseconds */

/* PSI getters for procfs */
void fut_psi_get(uint64_t *cpu_some, uint64_t *cpu_full) {
    *cpu_some = atomic_load_explicit(&psi_cpu_some_us, memory_order_relaxed);
    *cpu_full = atomic_load_explicit(&psi_cpu_full_us, memory_order_relaxed);
}

/* Public getter for system tick count.
 * Only compiled for x86_64 — ARM64 provides its own in platform_init.c. */
#if !defined(__aarch64__)
uint64_t fut_timer_get_ticks(void) {
    return atomic_load_explicit(&system_ticks, memory_order_relaxed);
}
#endif

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

/* Deferred free list: timer events freed from IRQ context are queued here
 * and actually freed later in non-interrupt context.  Calling fut_free()
 * directly from an IRQ while the interrupted thread is mid-allocation
 * corrupts heap metadata. */
static fut_timer_event_t *deferred_free_head = nullptr;
static fut_spinlock_t deferred_free_lock = { .locked = 0 };

static void drain_deferred_frees(void);

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

    /* Drain deferred frees from previous IRQ-context timer expirations */
    drain_deferred_frees();

    /* Convert milliseconds to ticks. system_ticks increments at FUT_TIMER_HZ
     * (100 Hz = every 10ms). Round up so sub-tick sleeps don't become zero. */
    uint64_t ticks = millis / 10;
    if (millis % 10 != 0)
        ticks++;  /* Round up: 1ms → 1 tick (10ms), 15ms → 2 ticks (20ms) */
    if (ticks == 0 && millis > 0)
        ticks = 1;

    // Calculate absolute wake time
    uint64_t current = atomic_load_explicit(&system_ticks, memory_order_relaxed);
    thread->wake_time = current + ticks;
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

/**
 * Wake a specific sleeping thread early (e.g., for signal delivery).
 * Removes the thread from the sleep queue and adds it to the ready queue.
 * Returns 1 if the thread was found and woken, 0 otherwise.
 */
int fut_thread_wake_sleeping(fut_thread_t *target) {
    if (!target || target->state != FUT_THREAD_SLEEPING)
        return 0;

    fut_spinlock_acquire(&sleep_lock);

    /* Verify still sleeping (may have been woken by timer between check and lock) */
    if (target->state != FUT_THREAD_SLEEPING) {
        fut_spinlock_release(&sleep_lock);
        return 0;
    }

    /* Remove from doubly-linked sleep queue */
    if (target->prev) {
        target->prev->next = target->next;
    } else {
        /* Target is the head */
        sleep_queue_head = target->next;
    }
    if (target->next) {
        target->next->prev = target->prev;
    }
    target->next = nullptr;
    target->prev = nullptr;
    target->state = FUT_THREAD_READY;

    fut_spinlock_release(&sleep_lock);

    fut_sched_add_thread(target);
    return 1;
}

/* Drain the deferred-free list.  Must be called from non-IRQ context
 * (interrupts may be enabled; fut_free disables them internally). */
static void drain_deferred_frees(void) {
    fut_spinlock_acquire(&deferred_free_lock);
    fut_timer_event_t *list = deferred_free_head;
    deferred_free_head = nullptr;
    fut_spinlock_release(&deferred_free_lock);

    while (list) {
        fut_timer_event_t *next = list->next;
        fut_free(list);
        list = next;
    }
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
        /* Defer the free — we are in IRQ context and calling fut_free()
         * here can corrupt heap metadata if the interrupted thread was
         * mid-allocation. */
        fut_spinlock_acquire(&deferred_free_lock);
        ev->next = deferred_free_head;
        deferred_free_head = ev;
        fut_spinlock_release(&deferred_free_lock);
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
    /* Increment tick counter.  Note: fut_printf is intentionally NOT called
     * here — fut_serial_putc busy-waits for THRE with interrupts disabled,
     * which can hang the kernel on CI when the QEMU serial FIFO is full. */
    uint64_t current_ms = atomic_fetch_add_explicit(&system_ticks, 1, memory_order_relaxed);

    /* Track per-category CPU ticks for /proc/stat and per-thread accounting:
     * idle:   no runnable thread
     * user:   thread running in a user-space process (PID > 1)
     * system: kernel thread or kernel-mode work (PID <= 1) */
    {
        extern fut_thread_t *fut_thread_current(void);
        fut_thread_t *ct = fut_thread_current();
        if (!ct || !ct->task || ct->state != 0 /* FUT_THREAD_RUNNING */) {
            atomic_fetch_add_explicit(&idle_ticks, 1, memory_order_relaxed);
        } else if (ct->task->pid <= 1) {
            /* Kernel thread or init process: always system time */
            atomic_fetch_add_explicit(&kern_ticks, 1, memory_order_relaxed);
            ct->stats.cpu_ticks++;
            ct->stats.stime_ticks++;
        } else if (ct->in_syscall) {
            /* User process inside a syscall: system time */
            atomic_fetch_add_explicit(&kern_ticks, 1, memory_order_relaxed);
            ct->stats.cpu_ticks++;
            ct->stats.stime_ticks++;
        } else {
            /* User process running user code: user time */
            atomic_fetch_add_explicit(&user_ticks, 1, memory_order_relaxed);
            ct->stats.cpu_ticks++;
            ct->stats.utime_ticks++;
        }
    }

    /* PSI tracking: count CPU stall ticks.
     * "some" = at least one task was runnable but couldn't get CPU (run queue > 1).
     * Each tick = 10ms = 10000µs. */
    {
        extern uint64_t fut_sched_get_runnable_count(void);
        uint64_t runnable = fut_sched_get_runnable_count();
        if (runnable > 1) {
            /* More tasks than CPUs: some tasks are waiting */
            atomic_fetch_add_explicit(&psi_cpu_some_us, 10000, memory_order_relaxed);
        }
        /* "full" = ALL tasks stalled (no useful work happening — idle despite runnable tasks).
         * On single-CPU: this is when runnable > 0 but current tick was idle (shouldn't happen). */
    }

    // Wake any threads whose sleep time has expired
    wake_sleeping_threads();

    // Process timer events
    process_timer_events();

    // Check software watchdog timer
    {
        extern void watchdog_check(void);
        watchdog_check();
    }

    /* Replenish entropy pool from timer jitter (every tick adds ~8 bits) */
    {
        extern void getrandom_add_entropy(void);
        getrandom_add_entropy();
    }

    // Check for expired alarms and deliver SIGALRM
    extern fut_task_t *fut_task_list;

    /* Identify the currently running task for ITIMER_VIRTUAL/PROF */
    extern fut_thread_t *fut_thread_current(void);
    fut_thread_t *cur_thread = fut_thread_current();
    fut_task_t *cur_task = (cur_thread && cur_thread->task) ? cur_thread->task : NULL;

    for (fut_task_t *task = fut_task_list; task != nullptr; task = task->next) {
        if (task->alarm_expires_ms > 0 && current_ms >= task->alarm_expires_ms) {
            /* Alarm expired — deliver SIGALRM with si_code=SI_KERNEL */
            siginfo_t sinfo;
            __builtin_memset(&sinfo, 0, sizeof(sinfo));
            sinfo.si_signum = SIGALRM;
            sinfo.si_code   = SI_KERNEL;
            sinfo.si_pid    = (int64_t)task->pid;
            sinfo.si_uid    = (uint32_t)task->uid;
            extern int fut_signal_send_with_info(struct fut_task *t, int sig, const void *info);
            fut_signal_send_with_info(task, SIGALRM, &sinfo);
            // Reload for ITIMER_REAL interval, or disarm
            if (task->itimer_real_interval_ms > 0) {
                task->alarm_expires_ms = current_ms + task->itimer_real_interval_ms;
            } else {
                task->alarm_expires_ms = 0;
            }
        }

        /* ITIMER_VIRTUAL / ITIMER_PROF: decrement only for the running task.
         * These approximate virtual/profiling time using wall-clock ticks
         * since we don't have separate user/kernel mode time accounting. */
        if (task == cur_task) {
            /* ITIMER_VIRTUAL: fires SIGVTALRM when user CPU time is exhausted */
            if (task->itimer_virt_value_ms > 0) {
                if (task->itimer_virt_value_ms <= 10) {
                    uint64_t new_val = task->itimer_virt_interval_ms;
                    task->itimer_virt_value_ms = new_val;
                    fut_signal_send(task, SIGVTALRM);
                } else {
                    task->itimer_virt_value_ms -= 10;
                }
            }
            /* ITIMER_PROF: fires SIGPROF when profiling time (user+sys) expires */
            if (task->itimer_prof_value_ms > 0) {
                if (task->itimer_prof_value_ms <= 10) {
                    uint64_t new_val = task->itimer_prof_interval_ms;
                    task->itimer_prof_value_ms = new_val;
                    fut_signal_send(task, SIGPROF);
                } else {
                    task->itimer_prof_value_ms -= 10;
                }
            }
        }

        // Check POSIX per-process timers
        for (int i = 0; i < FUT_POSIX_TIMER_MAX; i++) {
            fut_posix_timer_t *pt = &task->posix_timers[i];
            if (!pt->active || !pt->armed || pt->expiry_ms == 0)
                continue;
            if (current_ms < pt->expiry_ms)
                continue;

            // Timer expired
            if (pt->notify == SIGEV_SIGNAL || pt->notify == SIGEV_THREAD_ID) {
                /* For SIGEV_THREAD_ID: check pending on the target thread.
                 * For SIGEV_SIGNAL: check task-wide pending bitmap. */
                int already_pending = 0;
                if (pt->notify == SIGEV_THREAD_ID && pt->target_tid != 0) {
                    extern fut_thread_t *fut_thread_find(uint64_t tid);
                    fut_thread_t *thr = fut_thread_find(pt->target_tid);
                    if (thr) {
                        uint64_t sig_bit = (1ULL << (pt->signo - 1));
                        uint64_t tpend = __atomic_load_n(
                            &thr->thread_pending_signals, __ATOMIC_ACQUIRE);
                        already_pending = (tpend & sig_bit) != 0;
                    }
                } else {
                    uint64_t sig_bit = (1ULL << (pt->signo - 1));
                    uint64_t pending = __atomic_load_n(
                        &task->pending_signals, __ATOMIC_ACQUIRE);
                    already_pending = (pending & sig_bit) != 0;
                }

                if (already_pending) {
                    pt->overrun++;
                } else {
                    /* POSIX: deliver SI_TIMER siginfo so SA_SIGINFO handlers get
                     * si_code=SI_TIMER, si_timerid=timer_id, si_overrun, si_value */
                    siginfo_t sinfo;
                    __builtin_memset(&sinfo, 0, sizeof(sinfo));
                    sinfo.si_signum  = pt->signo;
                    sinfo.si_code    = SI_TIMER;   /* -2 */
                    sinfo.si_timerid = i + 1;       /* 1-based timer ID */
                    sinfo.si_overrun = pt->overrun;
                    sinfo.si_pid     = (int64_t)task->pid;
                    sinfo.si_uid     = (uint32_t)task->uid;
                    sinfo.si_value   = pt->sigev_value;
                    pt->overrun = 0;
                    if (pt->notify == SIGEV_THREAD_ID && pt->target_tid != 0) {
                        extern fut_thread_t *fut_thread_find(uint64_t tid);
                        extern int fut_signal_send_thread_with_info(
                            fut_thread_t *thread, int sig, const void *info);
                        fut_thread_t *thr = fut_thread_find(pt->target_tid);
                        if (thr)
                            fut_signal_send_thread_with_info(thr, pt->signo, &sinfo);
                        else {
                            /* Thread gone — fall back to task-level delivery */
                            extern int fut_signal_send_with_info(
                                struct fut_task *t, int sig, const void *info);
                            fut_signal_send_with_info(task, pt->signo, &sinfo);
                        }
                    } else {
                        extern int fut_signal_send_with_info(
                            struct fut_task *t, int sig, const void *info);
                        fut_signal_send_with_info(task, pt->signo, &sinfo);
                    }
                }
            }

            if (pt->interval_ms > 0) {
                // Periodic: re-arm
                pt->expiry_ms = current_ms + pt->interval_ms;
            } else {
                // One-shot: disarm
                pt->armed = 0;
                pt->expiry_ms = 0;
            }
        }
    }

    // Only trigger preemptive scheduling if the scheduler has been started
    // (i.e., current_thread != NULL). This prevents premature scheduling
    // before the test harness has created any threads.
    if (cur_thread != nullptr) {
        // Trigger preemptive scheduling
        // This will call fut_switch_context_irq() if a thread switch is needed
        fut_schedule();
    }
}

int fut_timer_start(uint64_t ticks_from_now, void (*cb)(void *), void *arg) {
    if (!cb) {
        return -EINVAL;
    }

    /* Drain deferred frees from previous IRQ-context timer expirations */
    drain_deferred_frees();

    if (ticks_from_now == 0) {
        cb(arg);
        return 0;
    }

    fut_timer_event_t *ev = (fut_timer_event_t *)fut_malloc(sizeof(fut_timer_event_t));
    if (!ev) {
        return -ENOMEM;
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
        return -EINVAL;
    }

    /* Drain deferred frees from previous IRQ-context timer expirations */
    drain_deferred_frees();
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
    return -ENOENT;  /* Timer event not found */
}

/**
 * Get current system ticks (milliseconds).
 */
uint64_t fut_get_ticks(void) {
    return atomic_load_explicit(&system_ticks, memory_order_relaxed);
}

/**
 * Get idle ticks since boot (ticks where no user thread was running).
 */
uint64_t fut_get_idle_ticks(void) {
    return atomic_load_explicit(&idle_ticks, memory_order_relaxed);
}

/**
 * Get user-mode ticks since boot (time running user-space processes).
 */
uint64_t fut_get_user_ticks(void) {
    return atomic_load_explicit(&user_ticks, memory_order_relaxed);
}

/**
 * Get kernel-mode ticks since boot (time in kernel threads/syscall handling).
 */
uint64_t fut_get_kern_ticks(void) {
    return atomic_load_explicit(&kern_ticks, memory_order_relaxed);
}

/**
 * Get IRQ ticks since boot.
 */
uint64_t fut_get_irq_ticks(void) {
    return atomic_load_explicit(&irq_ticks, memory_order_relaxed);
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
    /* Fallback to tick precision on non-x86_64 platforms.
     * Each tick = 10ms = 10,000,000 ns at 100 Hz. */
    return fut_get_ticks() * 10000000ULL;
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
    deferred_free_head = nullptr;
    fut_spinlock_init(&deferred_free_lock);

    // Program PIT hardware (x86-64 only)
#if defined(__x86_64__)
    pit_init(FUT_TIMER_HZ);
    // Note: Timer IRQ will be unmasked later after ACPI initialization
#else
    // ARM64: Timer is already initialized by platform layer (fut_timer_init)
#endif

    fut_printf("[TIMER] Timer subsystem initialized (%u Hz)\n", FUT_TIMER_HZ);
}
