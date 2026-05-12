/* lapic.c - x86_64 Local APIC implementation
 *
 * Copyright (c) 2025 Futura OS
 * Licensed under the MPL v2.0 — see LICENSE for details.
 */

#include <platform/x86_64/interrupt/lapic.h>
#include <platform/x86_64/msr.h>
#include <platform/x86_64/memory/paging.h>
#include <platform/x86_64/memory/pmap.h>
#include <stddef.h>

#include <kernel/kprintf.h>

/* MSR for LAPIC base address */
#define MSR_APIC_BASE   0x1B
#define APIC_BASE_ENABLE (1ULL << 11)
#define APIC_BASE_EXTD   (1ULL << 10)   /* x2APIC mode */
#define APIC_BASE_BSP    (1ULL << 8)

/* LAPIC MMIO base address (virtual) - exported for assembly access */
volatile uint32_t *lapic_base = NULL;

/* x2APIC mode is enabled — when true, access LAPIC via MSRs instead of MMIO.
 *
 * Whiskey Lake and later UEFI firmware (Lenovo L490 specifically) often
 * boot with x2APIC already enabled. In x2APIC mode, MMIO writes to the
 * LAPIC region are SILENTLY IGNORED — the CPU only honors MSR writes.
 * Our LAPIC timer setup writes to LVT_TIMER and TIMER_INITIAL via MMIO;
 * with x2APIC on, those writes vanish and the timer never fires. */
static bool lapic_x2apic = false;

/* Flag indicating LAPIC is fully initialized and safe to use */
static bool lapic_initialized = false;

/* x2APIC MSR address for a LAPIC register: 0x800 + (offset >> 4). */
static inline uint32_t x2apic_msr_for_reg(uint32_t reg) {
    return 0x800u + (reg >> 4);
}

/**
 * Read LAPIC register. Uses MSR in x2APIC mode, MMIO otherwise.
 */
static inline uint32_t lapic_read(uint32_t reg) {
    if (lapic_x2apic) {
        return (uint32_t)rdmsr(x2apic_msr_for_reg(reg));
    }
    if (!lapic_base) return 0;
    return lapic_base[reg / 4];
}

/**
 * Write LAPIC register. Uses MSR in x2APIC mode, MMIO otherwise.
 */
static inline void lapic_write(uint32_t reg, uint32_t value) {
    if (lapic_x2apic) {
        wrmsr(x2apic_msr_for_reg(reg), (uint64_t)value);
        return;
    }
    if (!lapic_base) return;
    lapic_base[reg / 4] = value;
}

/**
 * Map LAPIC MMIO region to kernel virtual address space.
 */
static void *lapic_map_mmio(uint64_t phys_addr) {
    phys_addr_t phys_base = PAGE_ALIGN_DOWN(phys_addr);
    uint64_t offset = phys_addr - phys_base;
    uintptr_t virt_base = (uintptr_t)pmap_phys_to_virt(phys_base);

    int rc = pmap_map(virt_base,
                      phys_base,
                      PAGE_SIZE,
                      PTE_KERNEL_RW | PTE_CACHE_DISABLE | PTE_WRITE_THROUGH);
    if (rc != 0) {
        fut_printf("[LAPIC] ERROR: pmap_map failed rc=%d for phys=0x%llx\n",
                   rc, (unsigned long long)phys_base);
        return NULL;
    }

    return (void *)(virt_base + offset);
}

/**
 * Initialize Local APIC for the current CPU.
 */
void lapic_init(uint64_t lapic_phys_base) {
    fut_printf("[LAPIC] Initializing Local APIC at 0x%llx\n", lapic_phys_base);

    /* Map LAPIC MMIO region. Still needed even if x2APIC ends up enabled
     * (some callers like assembly EOI paths walk lapic_base directly). */
    lapic_base = (volatile uint32_t *)lapic_map_mmio(lapic_phys_base);
    if (!lapic_base) {
        fut_printf("[LAPIC] ERROR: Failed to map LAPIC MMIO region\n");
        return;
    }

    /* Read current APIC mode from MSR. */
    uint64_t apic_base_msr = rdmsr(MSR_APIC_BASE);
    fut_printf("[LAPIC] APIC_BASE MSR: 0x%llx\n", apic_base_msr);

    /* Check if this is the BSP (Bootstrap Processor) */
    bool is_bsp = (apic_base_msr & APIC_BASE_BSP) != 0;
    fut_printf("[LAPIC] CPU is %s\n", is_bsp ? "BSP (Bootstrap)" : "AP (Application Processor)");

    /* x2APIC detection. Whiskey Lake / Lenovo L490 BIOS boots with this
     * mode already enabled. In x2APIC mode the LAPIC MMIO region returns
     * 0/ignores writes — we MUST use MSR access for register I/O.
     *
     * The MSR addresses are 0x800 + (mmio_offset >> 4): e.g. EOI = 0x80B,
     * TIMER_INITIAL = 0x838. lapic_read/lapic_write above handle the dispatch. */
    lapic_x2apic = (apic_base_msr & APIC_BASE_EXTD) != 0;
    if (lapic_x2apic) {
        fut_printf("[LAPIC] x2APIC mode ENABLED — using MSR access (0x800+)\n");
    } else {
        fut_printf("[LAPIC] xAPIC (MMIO) mode\n");
    }

    /* Enable LAPIC in MSR if not already enabled */
    if (!(apic_base_msr & APIC_BASE_ENABLE)) {
        apic_base_msr |= APIC_BASE_ENABLE;
        wrmsr(MSR_APIC_BASE, apic_base_msr);
        fut_printf("[LAPIC] Enabled LAPIC via MSR\n");
    }

    /* Read LAPIC ID and version */
    uint32_t lapic_id = lapic_get_id();
    uint32_t lapic_version = lapic_get_version();
    uint32_t max_lvt = (lapic_version >> 16) & 0xFF;

    fut_printf("[LAPIC] ID: %u, Version: 0x%x, Max LVT: %u\n",
               lapic_id, lapic_version & 0xFF, max_lvt);

    /* Set up Spurious Interrupt Vector Register (SVR) */
    /* Enable APIC and set spurious vector to 0xFF */
    uint32_t svr = LAPIC_SPURIOUS_VECTOR | LAPIC_SVR_ENABLE;
    lapic_write(LAPIC_REG_SVR, svr);
    fut_printf("[LAPIC] Enabled via SVR (spurious vector: 0xFF)\n");

    /* Clear error status register (write before reading) */
    lapic_write(LAPIC_REG_ESR, 0);
    uint32_t esr = lapic_read(LAPIC_REG_ESR);
    if (esr != 0) {
        fut_printf("[LAPIC] WARNING: Error Status Register: 0x%x\n", esr);
    }

    /* Set Task Priority Register to 0 (accept all interrupts) */
    lapic_write(LAPIC_REG_TPR, 0);

    /* Mask all LVT entries - rely on PIC mode for external interrupts */
    lapic_write(LAPIC_REG_LVT_TIMER, LAPIC_LVT_MASKED);
    /* Note: LINT0/LINT1 left at default/reset state - don't configure them */
    /* lapic_write(LAPIC_REG_LVT_LINT0, LAPIC_LVT_MASKED); */
    /* lapic_write(LAPIC_REG_LVT_LINT1, LAPIC_LVT_MASKED); */
    lapic_write(LAPIC_REG_LVT_ERROR, LAPIC_LVT_MASKED);

    if (max_lvt >= 4) {
        lapic_write(LAPIC_REG_LVT_PERF, LAPIC_LVT_MASKED);
    }
    if (max_lvt >= 5) {
        lapic_write(LAPIC_REG_LVT_THERMAL, LAPIC_LVT_MASKED);
    }
    if (max_lvt >= 6) {
        lapic_write(LAPIC_REG_LVT_CMCI, LAPIC_LVT_MASKED);
    }

    /* Mark LAPIC as initialized and safe to use */
    lapic_initialized = true;

    fut_printf("[LAPIC] Initialization complete\n");
}

/**
 * Get the current CPU's APIC ID.
 */
uint32_t lapic_get_id(void) {
    uint32_t id_reg = lapic_read(LAPIC_REG_ID);
    return (id_reg >> 24) & 0xFF;
}

/**
 * Get LAPIC version information.
 */
uint32_t lapic_get_version(void) {
    return lapic_read(LAPIC_REG_VERSION);
}

/**
 * Check if LAPIC is initialized and safe to use.
 */
bool lapic_is_initialized(void) {
    return lapic_initialized;
}

/**
 * Send End-Of-Interrupt to LAPIC.
 * Caller must check lapic_is_initialized() before calling.
 */
void lapic_send_eoi(void) {
    lapic_write(LAPIC_REG_EOI, 0);
}

/**
 * Public wrapper for reading any LAPIC register, dispatched MMIO or MSR
 * according to the current xAPIC / x2APIC mode. Returns 0 if neither
 * is available. Used by diagnostic call sites that need to dump LAPIC
 * state from outside this translation unit.
 */
uint32_t lapic_read_reg(uint32_t reg) {
    return lapic_read(reg);
}

/**
 * Send IPI (Inter-Processor Interrupt) to target CPU.
 */
void lapic_send_ipi(uint32_t apic_id, uint32_t vector) {
    /* Write high part first (destination) */
    lapic_write(LAPIC_REG_ICR_HIGH, (uint32_t)apic_id << 24);

    /* Write low part (vector and control) */
    uint32_t icr_low = vector | LAPIC_DM_FIXED | LAPIC_DEST_PHYSICAL | LAPIC_LEVEL_ASSERT;
    lapic_write(LAPIC_REG_ICR_LOW, icr_low);

    /* Wait for delivery to complete */
    while (lapic_read(LAPIC_REG_ICR_LOW) & LAPIC_DS_PENDING) {
        __asm__ volatile("pause");
    }
}

/**
 * Send INIT IPI to target CPU (assert then deassert).
 * Per Intel MP spec, INIT must be deasserted before SIPI.
 */
void lapic_send_init_ipi(uint32_t apic_id) {
    /* Write destination */
    lapic_write(LAPIC_REG_ICR_HIGH, (uint32_t)apic_id << 24);

    /* Assert INIT (level-triggered, assert) */
    uint32_t icr_low = LAPIC_DM_INIT | LAPIC_DEST_PHYSICAL | LAPIC_LEVEL_ASSERT | LAPIC_TM_LEVEL;
    lapic_write(LAPIC_REG_ICR_LOW, icr_low);

    /* Wait for delivery */
    while (lapic_read(LAPIC_REG_ICR_LOW) & LAPIC_DS_PENDING) {
        __asm__ volatile("pause");
    }

    /* Small delay */
    for (volatile int i = 0; i < 1000; i++);

    /* Deassert INIT (level-triggered, deassert) */
    icr_low = LAPIC_DM_INIT | LAPIC_DEST_PHYSICAL | LAPIC_TM_LEVEL;  /* No LEVEL_ASSERT = deassert */
    lapic_write(LAPIC_REG_ICR_LOW, icr_low);

    /* Wait for delivery */
    while (lapic_read(LAPIC_REG_ICR_LOW) & LAPIC_DS_PENDING) {
        __asm__ volatile("pause");
    }
}

/**
 * Send SIPI (Startup IPI) to target CPU.
 * SIPI is edge-triggered and includes the startup vector.
 */
void lapic_send_sipi(uint32_t apic_id, uint8_t vector) {
    /* Write destination */
    lapic_write(LAPIC_REG_ICR_HIGH, (uint32_t)apic_id << 24);

    /* Write SIPI (edge-triggered, vector in low byte) */
    uint32_t icr_low = vector | LAPIC_DM_STARTUP | LAPIC_DEST_PHYSICAL;
    lapic_write(LAPIC_REG_ICR_LOW, icr_low);

    /* Wait for delivery */
    while (lapic_read(LAPIC_REG_ICR_LOW) & LAPIC_DS_PENDING) {
        __asm__ volatile("pause");
    }
}

/**
 * Send IPI to all CPUs except self using destination shorthand.
 * Uses physical addressing mode with "Others" shorthand.
 */
void lapic_send_ipi_all_except_self(uint32_t vector) {
    /* Set ICR_HIGH to 0 (not used with shorthand addressing) */
    lapic_write(LAPIC_REG_ICR_HIGH, 0);

    /* Send IPI with "Others" destination shorthand */
    uint32_t icr_low = vector | LAPIC_DM_FIXED | LAPIC_DEST_PHYSICAL | LAPIC_DSH_OTHERS;
    lapic_write(LAPIC_REG_ICR_LOW, icr_low);

    /* Wait for delivery to complete */
    while (lapic_read(LAPIC_REG_ICR_LOW) & LAPIC_DS_PENDING) {
        __asm__ volatile("pause");
    }
}

/**
 * Send IPI to all CPUs including self using destination shorthand.
 * Uses physical addressing mode with "All" shorthand.
 */
void lapic_send_ipi_all_including_self(uint32_t vector) {
    /* Set ICR_HIGH to 0 (not used with shorthand addressing) */
    lapic_write(LAPIC_REG_ICR_HIGH, 0);

    /* Send IPI with "All" destination shorthand */
    uint32_t icr_low = vector | LAPIC_DM_FIXED | LAPIC_DEST_PHYSICAL | LAPIC_DSH_ALL;
    lapic_write(LAPIC_REG_ICR_LOW, icr_low);

    /* Wait for delivery to complete */
    while (lapic_read(LAPIC_REG_ICR_LOW) & LAPIC_DS_PENDING) {
        __asm__ volatile("pause");
    }
}

/**
 * Enable LAPIC timer in one-shot mode.
 */
void lapic_timer_oneshot(uint32_t initial_count, uint8_t vector) {
    /* Set divide configuration to divide by 1 */
    lapic_write(LAPIC_REG_TIMER_DIVIDE, LAPIC_TIMER_DIV_1);

    /* Set LVT Timer Register (one-shot mode, not masked) */
    lapic_write(LAPIC_REG_LVT_TIMER, vector | LAPIC_TIMER_ONESHOT);

    /* Set initial count to start timer */
    lapic_write(LAPIC_REG_TIMER_INITIAL, initial_count);
}

/**
 * Enable LAPIC timer in periodic mode.
 */
void lapic_timer_periodic(uint32_t initial_count, uint8_t vector) {
    /* Set divide configuration to divide by 16 — must match calibration divider
     * used in lapic_timer_calibrate_and_start(), otherwise the timer fires at
     * the wrong frequency (DIV_1 with a DIV_16-calibrated count = 16x too fast) */
    lapic_write(LAPIC_REG_TIMER_DIVIDE, LAPIC_TIMER_DIV_16);

    /* Set LVT Timer Register (periodic mode, not masked) */
    lapic_write(LAPIC_REG_LVT_TIMER, vector | LAPIC_TIMER_PERIODIC);

    /* Set initial count to start timer */
    lapic_write(LAPIC_REG_TIMER_INITIAL, initial_count);
}

/**
 * Disable LAPIC timer.
 */
void lapic_timer_disable(void) {
    lapic_write(LAPIC_REG_LVT_TIMER, LAPIC_LVT_MASKED);
    lapic_write(LAPIC_REG_TIMER_INITIAL, 0);
}

/**
 * Calibrate and start LAPIC timer at the specified frequency.
 * Uses the PIT for calibration (10ms reference tick).
 * The LAPIC timer is local to the CPU and doesn't go through IOAPIC,
 * making it more reliable for preemptive scheduling.
 *
 * @param hz Target frequency in Hz (e.g., 100 for 100Hz)
 * @param vector IDT vector to fire on timer expiry (e.g., 32 for IRQ0)
 */
void lapic_timer_calibrate_and_start(uint32_t hz, uint8_t vector) {
    if (!lapic_base || !lapic_initialized) {
        /* ACPI MADT parsing didn't call lapic_init successfully on this
         * machine (observed on Lenovo L490 — the boot reaches this point
         * with lapic_base==NULL because something in the MADT walk
         * silently dropped out before reaching lapic_init). Fall back to
         * the architecturally-defined default LAPIC MMIO address. The
         * hardware will not actually relocate the LAPIC away from
         * 0xFEE00000 unless something explicitly wrote IA32_APIC_BASE
         * MSR with a different base, which firmware rarely does. */
        fut_printf("[LAPIC-TIMER] LAPIC not initialized — falling back to default 0xFEE00000\n");
        lapic_init(0xFEE00000);
        if (!lapic_base || !lapic_initialized) {
            fut_printf("[LAPIC-TIMER] Cannot start: LAPIC init still failed after fallback\n");
            return;
        }
    }

    /* I/O port helpers (lapic.c doesn't have platform_init's static outb/inb) */
    #define LAPIC_OUTB(port, val) __asm__ volatile("outb %0, %1" :: "a"((uint8_t)(val)), "Nd"((uint16_t)(port)))
    #define LAPIC_INB(port, result) __asm__ volatile("inb %1, %0" : "=a"(result) : "Nd"((uint16_t)(port)))

    /* Step 1: Calibrate by measuring LAPIC ticks during a known interval.
     * Use PIT channel 2 for a ~10ms calibration window. */

    /* Configure PIT channel 2 for one-shot mode, 10ms */
    uint32_t pit_10ms = 1193182 / 100;  /* ~11932 ticks = ~10ms */
    uint8_t port61;
    LAPIC_INB(0x61, port61);
    LAPIC_OUTB(0x61, (port61 & 0xFD) | 0x01);  /* Enable PIT ch2 gate */
    LAPIC_OUTB(0x43, 0xB0);  /* Channel 2, lobyte/hibyte, mode 0, binary */
    LAPIC_OUTB(0x42, pit_10ms & 0xFF);
    LAPIC_OUTB(0x42, (pit_10ms >> 8) & 0xFF);

    /* Step 2: Start LAPIC timer with max count */
    lapic_write(LAPIC_REG_TIMER_DIVIDE, LAPIC_TIMER_DIV_16);
    lapic_write(LAPIC_REG_LVT_TIMER, LAPIC_LVT_MASKED);  /* Masked during calibration */
    lapic_write(LAPIC_REG_TIMER_INITIAL, 0xFFFFFFFF);

    /* Step 3: Wait for PIT channel 2 to expire */
    /* Reset PIT ch2 output latch */
    LAPIC_INB(0x61, port61);
    uint8_t tmp = port61 & 0xFE;
    LAPIC_OUTB(0x61, tmp);
    LAPIC_OUTB(0x61, tmp | 0x01);
    uint8_t status;
    do {
        LAPIC_INB(0x61, status);
    } while (!(status & 0x20));

    /* Step 4: Read how many LAPIC ticks elapsed in ~10ms */
    uint32_t elapsed = 0xFFFFFFFF - lapic_read(LAPIC_REG_TIMER_CURRENT);
    lapic_write(LAPIC_REG_TIMER_INITIAL, 0);  /* Stop timer */

    if (elapsed == 0) {
        fut_printf("[LAPIC-TIMER] Calibration failed (0 ticks in 10ms)\n");
        return;
    }

    /* Step 5: Calculate count for desired frequency.
     * elapsed ticks = 10ms worth. For hz Hz, period = 1000/hz ms.
     * count = elapsed * (1000 / hz) / 10 = elapsed * 100 / hz */
    uint32_t count = elapsed * 100 / hz;

    fut_printf("[LAPIC-TIMER] Calibrated: %u ticks/10ms, count=%u for %u Hz\n",
               elapsed, count, hz);

    /* Step 6: Disable PIT to avoid dual timer interrupts on same vector.
     * ISA IRQ 0 (PIT) is remapped to GSI 2 via MADT interrupt override,
     * so mask IOAPIC entry 2, not entry 0. */
    {
        extern void ioapic_mask_irq(uint8_t irq);
        extern bool ioapic_is_available(void);
        extern uint32_t ioapic_get_gsi_for_isa_irq(uint8_t isa_irq);
        if (ioapic_is_available()) {
            uint32_t pit_gsi = ioapic_get_gsi_for_isa_irq(0);
            ioapic_mask_irq((uint8_t)pit_gsi);
        }
        /* Clear any in-service IRQs left from the PIT calibration period.
         * The PIC may have IRQ 0 (timer) stuck in its ISR, which blocks all
         * lower-priority IRQs (including keyboard on IRQ 1).  Send EOI to
         * both PICs to clear all pending in-service bits. */
        LAPIC_OUTB(0xA0, 0x20);  /* PIC2 (slave) non-specific EOI */
        LAPIC_OUTB(0x20, 0x20);  /* PIC1 (master) non-specific EOI */
        LAPIC_OUTB(0x20, 0x20);  /* Extra EOI in case multiple ISR bits */

        /* Mask most PIC IRQs but leave IRQ 1 (keyboard) and IRQ 12 (mouse)
         * unmasked.  In APIC mode the PIC INTR line is disconnected from the
         * CPU, so unmasked PIC IRQs won't cause spurious interrupts.  However
         * the i8042 PS/2 controller routes through the PIC in QEMU's i440FX
         * emulation: if the PIC masks IRQ 1, the IRQ line stays asserted and
         * the IOAPIC (edge-triggered) never sees a new edge, so only the
         * first keystroke generates an interrupt.  Leaving IRQ 1/12 unmasked
         * lets the PIC accept and deassert them, allowing the IOAPIC to
         * detect subsequent edges. */
        LAPIC_OUTB(0x21, 0xFD);  /* Mask all PIC master except IRQ 1 (kbd) */
        LAPIC_OUTB(0xA1, 0xEF);  /* Mask all PIC slave except IRQ 12 (mouse) */
    }

    /* Step 7: Start LAPIC timer in periodic mode */
    lapic_timer_periodic(count, vector);

    fut_printf("[LAPIC-TIMER] Started periodic timer at %u Hz (vector %u), PIT disabled\n", hz, vector);

    /* Diagnostic readback: confirm the writes actually took effect.
     * On L490 the timer self-test reports 0 ticks even after this whole
     * setup completes; reading back lets us check whether LVT_TIMER kept
     * the values we wrote, or whether the LAPIC silently rejected them
     * (which it does in x2APIC mode if we used MMIO, or vice versa). */
    {
        uint32_t lvt = lapic_read(LAPIC_REG_LVT_TIMER);
        uint32_t init = lapic_read(LAPIC_REG_TIMER_INITIAL);
        uint32_t cur = lapic_read(LAPIC_REG_TIMER_CURRENT);
        uint32_t div = lapic_read(LAPIC_REG_TIMER_DIVIDE);
        uint32_t tpr = lapic_read(LAPIC_REG_TPR);
        uint32_t svr = lapic_read(LAPIC_REG_SVR);
        fut_printf("[LAPIC-TIMER] readback: LVT_TIMER=0x%08x (vec=%u, mask=%u, mode=%s)\n",
                   lvt, lvt & 0xFF, (lvt >> 16) & 1,
                   (lvt & 0x20000) ? "periodic" : "oneshot/tsc");
        fut_printf("[LAPIC-TIMER] readback: TIMER_INITIAL=%u TIMER_CURRENT=%u DIVIDE=0x%x\n",
                   init, cur, div);
        fut_printf("[LAPIC-TIMER] readback: TPR=0x%x SVR=0x%x (enabled=%u)\n",
                   tpr, svr, (svr >> 8) & 1);
    }

    /* Step 8: Self-test — verify the timer ISR is actually firing into
     * system_ticks on an ongoing basis. On Lenovo L490 (Whiskey Lake)
     * we've seen LAPIC fire ONCE post-start (or a residual PIT IRQ that
     * was queued before we masked it land afterward) and then go silent
     * forever. Checking "ticks_after != ticks_before" passes that case
     * spuriously, so require at least 5 ticks advancement in 100 ms (we
     * expect 10 at 100 Hz).
     *
     * Why rdtsc instead of a sleep: this is a free-running TSC read with
     * no dependency on the very thing we're trying to test. */
    extern uint64_t fut_rdtsc(void);
    extern uint64_t fut_get_ticks(void);
    uint64_t ticks_before = fut_get_ticks();
    uint64_t tsc0 = fut_rdtsc();
    /* Estimate ~100ms of TSC cycles from the LAPIC calibration just
     * performed: LAPIC bus clock at DIV_16 = roughly CPU bus, so the
     * elapsed value above is "LAPIC ticks per 10 ms". The TSC runs at
     * the nominal CPU clock which is much faster, but we don't have
     * that calibrated yet — assume 3 GHz for the self-test budget. */
    const uint64_t TSC_100MS_GUESS = 300ULL * 1000ULL * 1000ULL; /* 3 GHz × 100ms */
    while (fut_rdtsc() - tsc0 < TSC_100MS_GUESS) {
        __asm__ volatile("pause" ::: "memory");
    }
    uint64_t ticks_after = fut_get_ticks();
    /* Require ≥5 ticks (half the 100-ms-at-100Hz expectation) so that a
     * one-shot fire or residual queued IRQ doesn't fool us into thinking
     * the timer is working ongoing. */
    if ((ticks_after - ticks_before) < 5) {
        fut_printf("\n");
        fut_printf("####################################################################\n");
        fut_printf("##  WARNING: LAPIC TIMER ISR NOT FIRING — falling back to PIT     ##\n");
        fut_printf("##  Calibration reported success (elapsed=%u, count=%u)         ##\n", elapsed, count);
        fut_printf("##  Got only %llu ticks in 100ms (expected ≥5). LAPIC fire-once  ##\n",
                   (unsigned long long)(ticks_after - ticks_before));
        fut_printf("##  pattern likely — IRQ delivered then no more. Switching now.   ##\n");
        fut_printf("####################################################################\n");
        fut_printf("\n");

        /* Disable LAPIC timer cleanly so it can't interfere. */
        lapic_timer_disable();

        /* Un-mask the PIT GSI in the IOAPIC. pit_init() in
         * fut_timer_subsystem_init has already programmed PIT ch0 at
         * FUT_TIMER_HZ; we just need to let its IRQs through. */
        {
            extern void ioapic_unmask_irq(uint8_t irq);
            extern bool ioapic_is_available(void);
            extern uint32_t ioapic_get_gsi_for_isa_irq(uint8_t isa_irq);
            if (ioapic_is_available()) {
                uint32_t pit_gsi = ioapic_get_gsi_for_isa_irq(0);
                ioapic_unmask_irq((uint8_t)pit_gsi);
                fut_printf("[LAPIC-TIMER] PIT fallback: unmasked IOAPIC GSI %u for PIT ch0\n",
                           pit_gsi);
            }
        }

        /* Re-test: did PIT IRQs start landing? */
        uint64_t retick_before = fut_get_ticks();
        uint64_t retsc0 = fut_rdtsc();
        while (fut_rdtsc() - retsc0 < TSC_100MS_GUESS) {
            __asm__ volatile("pause" ::: "memory");
        }
        uint64_t retick_after = fut_get_ticks();
        if ((retick_after - retick_before) < 5) {
            fut_printf("\n");
            fut_printf("####################################################################\n");
            fut_printf("##  CRITICAL: PIT FALLBACK ALSO NOT FIRING — system has no timer  ##\n");
            fut_printf("##  Got %llu ticks in 100ms via PIT (expected ≥5).               ##\n",
                       (unsigned long long)(retick_after - retick_before));
            fut_printf("##  Kernel will continue but nanosleep/select/poll/sleep are all  ##\n");
            fut_printf("##  on the rdtsc-busy fallback. Preemption disabled. SMP unsafe.  ##\n");
            fut_printf("####################################################################\n");
            fut_printf("\n");
            extern _Atomic int g_timer_ticks_broken;
            __atomic_store_n(&g_timer_ticks_broken, 1, __ATOMIC_RELEASE);
            extern uint64_t g_lapic_timer_self_test_advance;
            g_lapic_timer_self_test_advance = retick_after - retick_before;
            extern int g_lapic_timer_source;
            g_lapic_timer_source = 0; /* none */
        } else {
            fut_printf("[LAPIC-TIMER] PIT fallback OK: system_ticks advanced %llu -> %llu in ~100ms\n",
                       (unsigned long long)retick_before,
                       (unsigned long long)retick_after);
            extern uint64_t g_lapic_timer_self_test_advance;
            g_lapic_timer_self_test_advance = retick_after - retick_before;
            extern int g_lapic_timer_source;
            g_lapic_timer_source = 2; /* PIT */
        }
    } else {
        fut_printf("[LAPIC-TIMER] self-test OK: system_ticks advanced from %llu to %llu in ~100ms\n",
                   (unsigned long long)ticks_before,
                   (unsigned long long)ticks_after);
        extern uint64_t g_lapic_timer_self_test_advance;
        g_lapic_timer_self_test_advance = ticks_after - ticks_before;
        extern int g_lapic_timer_source;
        g_lapic_timer_source = 1; /* LAPIC */
    }
}

/* Set by the LAPIC self-test in lapic_timer_calibrate_and_start so that
 * later boot phases can print "LAPIC timer health: N ticks in 100ms" once
 * the screen has scrolled past the noisy device-driver init. Helps the
 * user see at-a-glance whether the timer is working without scrolling
 * back through hundreds of lines. */
uint64_t g_lapic_timer_self_test_advance = 0;
/* 0 = none (both LAPIC and PIT failed), 1 = LAPIC, 2 = PIT fallback. */
int g_lapic_timer_source = 0;

/* Dump the current LAPIC state for late-boot diagnostics. Safe to call
 * any time after lapic_init has run. */
void lapic_dump_state(void) {
    if (!lapic_base && !lapic_x2apic) {
        fut_printf("[LAPIC-STATE] LAPIC not initialized\n");
        return;
    }
    uint64_t apic_base_msr = rdmsr(MSR_APIC_BASE);
    uint32_t lvt = lapic_read(LAPIC_REG_LVT_TIMER);
    uint32_t init = lapic_read(LAPIC_REG_TIMER_INITIAL);
    uint32_t cur = lapic_read(LAPIC_REG_TIMER_CURRENT);
    uint32_t div = lapic_read(LAPIC_REG_TIMER_DIVIDE);
    uint32_t tpr = lapic_read(LAPIC_REG_TPR);
    uint32_t svr = lapic_read(LAPIC_REG_SVR);
    fut_printf("[LAPIC-STATE] APIC_BASE_MSR=0x%llx (x2APIC=%u enabled=%u)\n",
               (unsigned long long)apic_base_msr,
               (unsigned)((apic_base_msr >> 10) & 1),
               (unsigned)((apic_base_msr >> 11) & 1));
    fut_printf("[LAPIC-STATE] LVT_TIMER=0x%08x (vec=%u mask=%u %s)\n",
               lvt, lvt & 0xFF, (lvt >> 16) & 1,
               (lvt & 0x20000) ? "periodic" : "oneshot/tsc");
    fut_printf("[LAPIC-STATE] TIMER_INITIAL=%u CURRENT=%u DIVIDE=0x%x\n",
               init, cur, div);
    fut_printf("[LAPIC-STATE] TPR=0x%x SVR=0x%x (enabled=%u)\n",
               tpr, svr, (svr >> 8) & 1);
}

/**
 * Check if LAPIC is enabled.
 */
bool lapic_is_enabled(void) {
    if (!lapic_base) return false;
    uint32_t svr = lapic_read(LAPIC_REG_SVR);
    return (svr & LAPIC_SVR_ENABLE) != 0;
}
