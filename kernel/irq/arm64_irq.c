/* arm64_irq.c - ARM64 Interrupt and Exception Handling
 *
 * Copyright (c) 2025 Kelsi Davis
 * Licensed under the MPL v2.0 — see LICENSE for details.
 *
 * ARM64 interrupt controller setup, exception dispatch, and IRQ routing.
 */

#include <arch/arm64/irq.h>
#include <arch/arm64/regs.h>
#include <stddef.h>
#include <stdatomic.h>

/* ============================================================
 *   IRQ Handler Table
 * ============================================================ */

static fut_irq_handler_t irq_handlers[FUT_MAX_IRQS] = {NULL};
static _Atomic(bool) reschedule_flag = false;

/* ============================================================
 *   Reschedule Flag Management
 * ============================================================ */

bool fut_reschedule_pending(void) {
    return atomic_load(&reschedule_flag);
}

void fut_request_reschedule(void) {
    atomic_store(&reschedule_flag, true);
}

void fut_clear_reschedule(void) {
    atomic_store(&reschedule_flag, false);
}

/* ============================================================
 *   IRQ Handler Registration
 * ============================================================ */

int fut_register_irq_handler(int irq, fut_irq_handler_t handler) {
    if (irq < 0 || irq >= FUT_MAX_IRQS) {
        return -1;  /* Invalid IRQ */
    }

    if (irq_handlers[irq] != NULL) {
        return -2;  /* Already registered */
    }

    irq_handlers[irq] = handler;
    return 0;
}

int fut_unregister_irq_handler(int irq) {
    if (irq < 0 || irq >= FUT_MAX_IRQS) {
        return -1;  /* Invalid IRQ */
    }

    irq_handlers[irq] = NULL;
    return 0;
}

/* ============================================================
 *   GICv2 Interface (Generic Interrupt Controller v2)
 * ============================================================ */

/* GICv2 Memory-mapped register addresses (typical QEMU virt machine) */
#define GIC_DIST_BASE   0x08000000ULL   /* Distributor */
#define GIC_CPU_BASE    0x08010000ULL   /* CPU interface */

/* GIC Distributor registers */
#define GIC_DIST_CTRL           0x000
#define GIC_DIST_CTR            0x004
#define GIC_DIST_ISR_BASE       0x080   /* Interrupt Security Registers */
#define GIC_DIST_ISENABLER_BASE 0x100   /* Interrupt Set-Enable */
#define GIC_DIST_ICENABLER_BASE 0x180   /* Interrupt Clear-Enable */
#define GIC_DIST_ISPENDR_BASE   0x200   /* Interrupt Set-Pending */
#define GIC_DIST_ICPENDR_BASE   0x280   /* Interrupt Clear-Pending */
#define GIC_DIST_IPRIORITY_BASE 0x400   /* Interrupt Priority */
#define GIC_DIST_ITARGETS_BASE  0x800   /* Interrupt CPU Targets */
#define GIC_DIST_ICFG_BASE      0xc00   /* Interrupt Configuration */

/* GIC CPU Interface registers */
#define GIC_CPU_CTRL            0x000
#define GIC_CPU_PRIMASK         0x004
#define GIC_CPU_BINPOINT       0x008
#define GIC_CPU_INTACK          0x00c
#define GIC_CPU_EOI             0x010
#define GIC_CPU_RUNNINGPRI      0x014
#define GIC_CPU_HIGHPRI         0x018

/**
 * Read GIC register.
 */
static inline uint32_t gic_read(uint64_t base, uint32_t offset) {
    return *(volatile uint32_t *)(base + offset);
}

/**
 * Write GIC register.
 */
static inline void gic_write(uint64_t base, uint32_t offset, uint32_t value) {
    *(volatile uint32_t *)(base + offset) = value;
}

/**
 * Initialize GICv2.
 */
void fut_gic_init(void) {
    /* Enable the distributor */
    gic_write(GIC_DIST_BASE, GIC_DIST_CTRL, 1);

    /* Set priority for all SPIs (Shared Peripheral Interrupts) */
    for (int i = 32; i < 256; i++) {
        int reg_offset = GIC_DIST_IPRIORITY_BASE + (i / 4) * 4;
        uint32_t shift = (i % 4) * 8;
        uint32_t current = gic_read(GIC_DIST_BASE, reg_offset);
        current &= ~(0xFF << shift);
        current |= (0x80 << shift);  /* Default priority */
        gic_write(GIC_DIST_BASE, reg_offset, current);
    }

    /* Enable CPU interface */
    gic_write(GIC_CPU_BASE, GIC_CPU_CTRL, 1);

    /* Set binary point (no preemption groups) */
    gic_write(GIC_CPU_BASE, GIC_CPU_BINPOINT, 0);

    /* Set priority mask to allow all interrupts */
    gic_write(GIC_CPU_BASE, GIC_CPU_PRIMASK, 0xFF);
}

int fut_irq_acknowledge(void) {
    uint32_t intack = gic_read(GIC_CPU_BASE, GIC_CPU_INTACK);
    int irq = intack & 0x3FF;

    /* Check for spurious interrupt */
    if (irq == 1023) {
        return -1;  /* Spurious interrupt */
    }

    return irq;
}

void fut_irq_send_eoi(int irq) {
    gic_write(GIC_CPU_BASE, GIC_CPU_EOI, irq & 0x3FF);
}

uint32_t fut_irq_get_priority(int irq) {
    if (irq < 0 || irq >= 256) {
        return 0;
    }

    int reg_offset = GIC_DIST_IPRIORITY_BASE + (irq / 4) * 4;
    int shift = (irq % 4) * 8;
    uint32_t current = gic_read(GIC_DIST_BASE, reg_offset);
    return (current >> shift) & 0xFF;
}

void fut_irq_set_priority(int irq, uint32_t priority) {
    if (irq < 0 || irq >= 256) {
        return;
    }

    int reg_offset = GIC_DIST_IPRIORITY_BASE + (irq / 4) * 4;
    int shift = (irq % 4) * 8;
    uint32_t current = gic_read(GIC_DIST_BASE, reg_offset);
    current &= ~(0xFF << shift);
    current |= ((priority & 0xFF) << shift);
    gic_write(GIC_DIST_BASE, reg_offset, current);
}

void fut_irq_enable(int irq) {
    if (irq < 0 || irq >= 256) {
        return;
    }

    int reg_offset = GIC_DIST_ISENABLER_BASE + (irq / 32) * 4;
    int shift = irq % 32;
    uint32_t value = 1U << shift;
    gic_write(GIC_DIST_BASE, reg_offset, value);
}

void fut_irq_disable(int irq) {
    if (irq < 0 || irq >= 256) {
        return;
    }

    int reg_offset = GIC_DIST_ICENABLER_BASE + (irq / 32) * 4;
    int shift = irq % 32;
    uint32_t value = 1U << shift;
    gic_write(GIC_DIST_BASE, reg_offset, value);
}

bool fut_irq_is_enabled(int irq) {
    if (irq < 0 || irq >= 256) {
        return false;
    }

    int reg_offset = GIC_DIST_ISENABLER_BASE + (irq / 32) * 4;
    int shift = irq % 32;
    uint32_t current = gic_read(GIC_DIST_BASE, reg_offset);
    return (current & (1U << shift)) != 0;
}

/* ============================================================
 *   ARM Generic Timer
 * ============================================================ */

/**
 * Initialize ARM Generic Timer.
 */
void fut_timer_init(void) {
    /* Get timer frequency */
    uint32_t freq = fut_timer_get_frequency();

    /* Set initial timeout to 1 second from now */
    uint64_t count = fut_timer_read_count();
    uint64_t timeout = count + freq;  /* 1 second */

    /* Program the physical timer comparator */
    __asm__ volatile("msr cntp_cval_el0, %0" :: "r"(timeout));

    /* Enable timer interrupt */
    uint32_t ctl = 1;  /* Enable bit */
    __asm__ volatile("msr cntp_ctl_el0, %0" :: "r"(ctl));

    /* Enable the timer IRQ in GIC */
    fut_irq_enable(FUT_IRQ_TIMER);
}

uint32_t fut_timer_get_frequency(void) {
    uint32_t freq;
    __asm__ volatile("mrs %0, cntfrq_el0" : "=r"(freq));
    return freq;
}

void fut_timer_set_timeout(uint64_t ticks) {
    uint64_t count = fut_timer_read_count();
    uint64_t timeout = count + ticks;
    __asm__ volatile("msr cntp_cval_el0, %0" :: "r"(timeout));
}

void fut_timer_irq_handler(void) {
    /* Re-enable timer for next interrupt */
    uint32_t freq = fut_timer_get_frequency();
    uint64_t count = fut_timer_read_count();
    uint64_t timeout = count + freq;  /* 1 second */
    __asm__ volatile("msr cntp_cval_el0, %0" :: "r"(timeout));
}

/* ============================================================
 *   Exception Handling
 * ============================================================ */

void fut_handle_sync_exception(fut_interrupt_frame_t *frame, uint64_t esr, uint64_t far) {
    uint32_t ec = fut_esr_get_ec(esr);

    switch (ec) {
        case ESR_EC_DABT_LOWER:
        case ESR_EC_DABT_CURRENT:
            fut_handle_data_abort(frame, esr, far);
            break;

        case ESR_EC_IABT_LOWER:
        case ESR_EC_IABT_CURRENT:
            fut_handle_instr_abort(frame, esr, far);
            break;

        case ESR_EC_SVC_AARCH64:
            fut_handle_syscall(frame);
            break;

        default:
            /* Unhandled exception - for now, just halt */
            __asm__ volatile("wfi");
            break;
    }
}

void fut_handle_data_abort(fut_interrupt_frame_t *frame, uint64_t esr, uint64_t far) {
    /* Check if it's a page fault that needs to be handled */
    uint32_t fsc = fut_esr_get_fsc(esr);

    /* Delegate to page fault handler */
    fut_page_fault_handler(frame, esr, far);
}

void fut_handle_instr_abort(fut_interrupt_frame_t *frame, uint64_t esr, uint64_t far) {
    /* Similar to data abort but for instruction fetches */
    uint32_t fsc = fut_esr_get_fsc(esr);
    fut_page_fault_handler(frame, esr, far);
}

void fut_handle_syscall(fut_interrupt_frame_t *frame) {
    /* Syscall handling would go here */
    /* For now, just a stub */
}

/* ============================================================
 *   Interrupt Dispatch
 * ============================================================ */

void fut_irq_dispatch(fut_interrupt_frame_t *frame) {
    int irq = fut_irq_acknowledge();

    if (irq < 0) {
        /* Spurious interrupt */
        return;
    }

    /* Call registered handler if exists */
    if (irq < FUT_MAX_IRQS && irq_handlers[irq] != NULL) {
        irq_handlers[irq](irq, frame);
    }

    /* Send EOI to acknowledge interrupt */
    fut_irq_send_eoi(irq);
}

void fut_exception_dispatch(fut_interrupt_frame_t *frame, uint64_t esr) {
    /* Read FAR for fault address (if applicable) */
    uint64_t far;
    __asm__ volatile("mrs %0, far_el1" : "=r"(far));

    fut_handle_sync_exception(frame, esr, far);
}

/* ============================================================
 *   Page Fault Handler (Stub - requires memory management)
 * ============================================================ */

__attribute__((weak))
void fut_page_fault_handler(void *frame, uint64_t esr, uint64_t far) {
    /* Stub implementation - actual implementation in memory manager */
    /* In a full implementation, this would:
     * 1. Check if page should be mapped
     * 2. Allocate page if needed
     * 3. Update page tables
     * 4. Resume execution
     */
}
