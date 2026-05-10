/* fut_irq.h — IRQ-state save/restore helpers
 *
 * Copyright (c) 2025 Kelsi Davis
 * Licensed under the MPL v2.0 — see LICENSE for details.
 *
 * Shared inline helpers for kernel code that needs to disable IRQs
 * around a critical section and restore the prior state on exit.
 *
 * Pattern (mirrors what was duplicated in pmm_irqsave / buddy_irqsave /
 * slab_irqsave / thread_list_irqsave):
 *
 *     unsigned long flags = fut_irqsave();
 *     fut_spinlock_acquire(&some_lock);
 *     ... critical section ...
 *     fut_spinlock_release(&some_lock);
 *     fut_irqrestore(flags);
 *
 * Why this matters: the kernel's spinlocks are not IRQ-aware on their
 * own. If a mainline thread holds a lock that an ISR also takes, and
 * the ISR fires on the same CPU, the ISR self-deadlocks against the
 * mainline thread (which can't make progress because the ISR is on
 * its stack).
 */

#ifndef FUT_IRQ_H
#define FUT_IRQ_H

static inline unsigned long fut_irqsave(void) {
    unsigned long flags;
#if defined(__x86_64__)
    __asm__ volatile("pushfq; pop %0; cli" : "=r"(flags) :: "memory");
#elif defined(__aarch64__)
    __asm__ volatile("mrs %0, daif; msr daifset, #0xF" : "=r"(flags) :: "memory");
#else
    flags = 0;
#endif
    return flags;
}

static inline void fut_irqrestore(unsigned long flags) {
#if defined(__x86_64__)
    if (flags & (1UL << 9))  /* IF bit */
        __asm__ volatile("sti" ::: "memory");
#elif defined(__aarch64__)
    __asm__ volatile("msr daif, %0" :: "r"(flags) : "memory");
#else
    (void)flags;
#endif
}

#endif /* FUT_IRQ_H */
