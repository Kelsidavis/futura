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

extern void fut_printf(const char *fmt, ...);

/* MSR for LAPIC base address */
#define MSR_APIC_BASE   0x1B
#define APIC_BASE_ENABLE (1ULL << 11)
#define APIC_BASE_BSP    (1ULL << 8)

/* LAPIC MMIO base address (virtual) */
static volatile uint32_t *lapic_base = NULL;

/* Flag indicating LAPIC is fully initialized and safe to use */
static bool lapic_initialized = false;

/**
 * Read LAPIC register.
 */
static inline uint32_t lapic_read(uint32_t reg) {
    if (!lapic_base) return 0;
    return lapic_base[reg / 4];
}

/**
 * Write LAPIC register.
 */
static inline void lapic_write(uint32_t reg, uint32_t value) {
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

    /* Map LAPIC MMIO region */
    lapic_base = (volatile uint32_t *)lapic_map_mmio(lapic_phys_base);
    if (!lapic_base) {
        fut_printf("[LAPIC] ERROR: Failed to map LAPIC MMIO region\n");
        return;
    }

    /* Enable LAPIC via MSR */
    uint64_t apic_base_msr = rdmsr(MSR_APIC_BASE);
    fut_printf("[LAPIC] APIC_BASE MSR: 0x%llx\n", apic_base_msr);

    /* Check if this is the BSP (Bootstrap Processor) */
    bool is_bsp = (apic_base_msr & APIC_BASE_BSP) != 0;
    fut_printf("[LAPIC] CPU is %s\n", is_bsp ? "BSP (Bootstrap)" : "AP (Application Processor)");

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
    /* Set divide configuration to divide by 1 */
    lapic_write(LAPIC_REG_TIMER_DIVIDE, LAPIC_TIMER_DIV_1);

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
 * Check if LAPIC is enabled.
 */
bool lapic_is_enabled(void) {
    if (!lapic_base) return false;
    uint32_t svr = lapic_read(LAPIC_REG_SVR);
    return (svr & LAPIC_SVR_ENABLE) != 0;
}
