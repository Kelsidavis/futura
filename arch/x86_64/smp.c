/* smp.c - x86_64 SMP (Symmetric Multi-Processing) initialization
 *
 * Copyright (c) 2025 Futura OS
 * Licensed under the MPL v2.0 — see LICENSE for details.
 */

#include <arch/x86_64/lapic.h>
#include <kernel/fut_percpu.h>
#include <stdint.h>
#include <stdbool.h>
#include <stdatomic.h>
#include <string.h>

extern void fut_printf(const char *fmt, ...);

/* Trampoline code symbols from ap_trampoline.S */
extern uint8_t ap_trampoline_start[];
extern uint8_t ap_trampoline_end[];
extern uint64_t ap_trampoline_gdt64;
extern uint64_t ap_trampoline_pml4;
extern uint64_t ap_trampoline_stack;
extern uint64_t ap_trampoline_target;
extern uint64_t ap_trampoline_cpu_id;

/* Trampoline location in low memory (16KB at 0x8000) */
#define AP_TRAMPOLINE_ADDR  0x8000
#define AP_TRAMPOLINE_PAGE  (AP_TRAMPOLINE_ADDR >> 12)  /* SIPI vector */

/* Track CPU states */
#define MAX_CPUS 256
static volatile bool cpu_online[MAX_CPUS];
static _Atomic uint32_t cpu_count = 1;  /* Start at 1 (BSP is CPU 0) */
static uint32_t bsp_apic_id = 0;

/**
 * Get current CPU count.
 */
uint32_t smp_get_cpu_count(void) {
    return cpu_count;
}

/**
 * Check if CPU is online.
 */
bool smp_is_cpu_online(uint32_t apic_id) {
    if (apic_id >= MAX_CPUS) return false;
    return cpu_online[apic_id];
}

/**
 * Microsecond delay using busy loop.
 */
static void udelay(uint32_t usec) {
    /* Rough estimate: 1000 iterations per microsecond */
    for (uint32_t i = 0; i < usec * 1000; i++) {
        __asm__ volatile("pause");
    }
}

/**
 * AP entry point (called from trampoline in 64-bit mode).
 * This is the first C code executed by APs.
 */
void ap_main(uint32_t apic_id) {
    fut_printf("[SMP] AP CPU %u online\n", apic_id);

    /* Initialize LAPIC for this CPU */
    extern void lapic_init(uint64_t lapic_base);
    lapic_init(0xFEE00000);  /* Standard LAPIC address */

    /* Get unique CPU index atomically */
    uint32_t cpu_index = atomic_fetch_add_explicit(&cpu_count, 1, memory_order_seq_cst);

    /* Initialize per-CPU data for this AP */
    fut_percpu_init(apic_id, cpu_index);
    fut_percpu_set(&fut_percpu_data[cpu_index]);

    /* Mark CPU as online */
    cpu_online[apic_id] = true;

    fut_printf("[SMP] AP CPU %u initialized as CPU #%u (total CPUs: %u)\n",
               apic_id, cpu_index, atomic_load_explicit(&cpu_count, memory_order_seq_cst));

    /* Initialize scheduler for this CPU (creates per-CPU idle thread) */
    extern void fut_sched_init_cpu(void);
    fut_sched_init_cpu();

    fut_printf("[SMP] AP CPU %u entering scheduler loop\n", apic_id);

    /* Enter scheduler loop - each CPU independently schedules threads */
    while (1) {
        __asm__ volatile("sti\n\thlt" ::: "memory");
    }
}

/**
 * Start an Application Processor via SIPI.
 * This is the proper way to start APs on x86_64 systems.
 */
static bool smp_start_ap(uint32_t apic_id) {
    fut_printf("[SMP] Starting AP CPU %u via SIPI...\n", apic_id);

    /* Allocate per-CPU stack (16KB) */
    extern void *fut_malloc(uint64_t size);
    void *stack = fut_malloc(16384);
    if (!stack) {
        fut_printf("[SMP] ERROR: Failed to allocate stack for CPU %u\n", apic_id);
        return false;
    }

    /* Stack grows down, so point to top */
    uint64_t stack_top = (uint64_t)stack + 16384;

    /* Get kernel page table (CR3 value) */
    uint64_t pml4;
    __asm__ volatile("mov %%cr3, %0" : "=r"(pml4));

    /* Get GDT descriptor location */
    struct {
        uint16_t limit;
        uint64_t base;
    } __attribute__((packed)) gdtr;
    __asm__ volatile("sgdt %0" : "=m"(gdtr));

    /* Access trampoline via identity mapping (low memory is identity-mapped at boot) */
    uint8_t *trampoline = (uint8_t *)(uint64_t)AP_TRAMPOLINE_ADDR;

    /* Calculate trampoline size */
    size_t trampoline_size = ap_trampoline_end - ap_trampoline_start;
    fut_printf("[SMP] Trampoline size: %u bytes\n", (uint32_t)trampoline_size);
    fut_printf("[SMP] Trampoline source: 0x%llx\n", (uint64_t)ap_trampoline_start);
    fut_printf("[SMP] Source first 16 bytes: %02x %02x %02x %02x %02x %02x %02x %02x "
               "%02x %02x %02x %02x %02x %02x %02x %02x\n",
               ap_trampoline_start[0], ap_trampoline_start[1], ap_trampoline_start[2], ap_trampoline_start[3],
               ap_trampoline_start[4], ap_trampoline_start[5], ap_trampoline_start[6], ap_trampoline_start[7],
               ap_trampoline_start[8], ap_trampoline_start[9], ap_trampoline_start[10], ap_trampoline_start[11],
               ap_trampoline_start[12], ap_trampoline_start[13], ap_trampoline_start[14], ap_trampoline_start[15]);

    /* Copy trampoline code to low memory */
    memcpy(trampoline, ap_trampoline_start, trampoline_size);

    fut_printf("[SMP] Trampoline copied to 0x%llx (phys 0x%x)\n",
               (uint64_t)trampoline, AP_TRAMPOLINE_ADDR);
    fut_printf("[SMP] First 16 bytes: %02x %02x %02x %02x %02x %02x %02x %02x "
               "%02x %02x %02x %02x %02x %02x %02x %02x\n",
               trampoline[0], trampoline[1], trampoline[2], trampoline[3],
               trampoline[4], trampoline[5], trampoline[6], trampoline[7],
               trampoline[8], trampoline[9], trampoline[10], trampoline[11],
               trampoline[12], trampoline[13], trampoline[14], trampoline[15]);

    /* Fill in trampoline variables (relative to trampoline base) */
    uint8_t *gdt64_ptr = trampoline + ((uint8_t *)&ap_trampoline_gdt64 - ap_trampoline_start);
    uint64_t *pml4_ptr = (uint64_t *)(trampoline + ((uint8_t *)&ap_trampoline_pml4 - ap_trampoline_start));
    uint64_t *stack_ptr = (uint64_t *)(trampoline + ((uint8_t *)&ap_trampoline_stack - ap_trampoline_start));
    uint64_t *target_ptr = (uint64_t *)(trampoline + ((uint8_t *)&ap_trampoline_target - ap_trampoline_start));
    uint64_t *cpu_id_ptr = (uint64_t *)(trampoline + ((uint8_t *)&ap_trampoline_cpu_id - ap_trampoline_start));

    /* Copy GDT descriptor structure (limit + base) */
    *(uint16_t *)gdt64_ptr = gdtr.limit;
    *(uint64_t *)(gdt64_ptr + 2) = gdtr.base;

    *pml4_ptr = pml4;
    *stack_ptr = stack_top;
    *target_ptr = (uint64_t)ap_main;
    *cpu_id_ptr = apic_id;

    fut_printf("[SMP] Sending INIT IPI to CPU %u\n", apic_id);

    /* Send INIT IPI (resets the AP) */
    lapic_send_init_ipi(apic_id);
    udelay(10000);  /* Wait 10ms */

    fut_printf("[SMP] Sending SIPI #1 to CPU %u (vector 0x%x)\n",
               apic_id, AP_TRAMPOLINE_PAGE);

    /* Send SIPI (Startup IPI) */
    lapic_send_sipi(apic_id, AP_TRAMPOLINE_PAGE);
    udelay(200);    /* Wait 200us */

    /* Send second SIPI (Intel recommends sending twice) */
    fut_printf("[SMP] Sending SIPI #2 to CPU %u\n", apic_id);
    lapic_send_sipi(apic_id, AP_TRAMPOLINE_PAGE);
    udelay(200);

    /* Wait for AP to come online (timeout after 100ms instead of 1s for faster boot) */
    for (int i = 0; i < 100; i++) {
        if (cpu_online[apic_id]) {
            fut_printf("[SMP] AP CPU %u is online\n", apic_id);
            return true;
        }
        udelay(1000);  /* Wait 1ms */
    }

    fut_printf("[SMP] TIMEOUT: AP CPU %u did not respond (skipping)\n", apic_id);
    return false;
}

/* External symbols from boot.S for flag-based AP waking */
extern uint32_t ap_ready_flag;
extern uint64_t ap_entry_addr_64;

/* Flag-based AP wake disabled - not needed for QEMU which requires SIPI */
#if 0
static bool smp_try_flag_wake(void) {
    extern void ap_main(uint32_t apic_id);
    fut_printf("[SMP] Trying flag-based AP wake (for boot.S APs)...\n");
    uint32_t initial_count = cpu_count;
    ap_entry_addr_64 = (uint64_t)ap_main;
    __atomic_store_n(&ap_ready_flag, 1, __ATOMIC_RELEASE);
    for (int i = 0; i < 100; i++) {
        udelay(1000);
        if (cpu_count > initial_count) {
            fut_printf("[SMP] Flag wake successful, %u APs started\n",
                      cpu_count - initial_count);
            return true;
        }
    }
    fut_printf("[SMP] Flag wake: no APs responded\n");
    return false;
}
#endif

/**
 * Initialize SMP and start all Application Processors.
 */
void smp_init(uint32_t *apic_ids, uint32_t num_cpus) {
    (void)apic_ids;  /* Will be used when SIPI is re-enabled */

    fut_printf("[SMP] Initializing SMP with %u CPUs\n", num_cpus);

    /* Mark BSP as online */
    bsp_apic_id = lapic_get_id();
    cpu_online[bsp_apic_id] = true;
    cpu_count = 1;

    fut_printf("[SMP] BSP is CPU %u\n", bsp_apic_id);

    if (num_cpus > 1) {
        /* Skip flag-based wake - APs are not running in QEMU, need SIPI */
        fut_printf("[SMP] Using SIPI to start %u Application Processors...\n", num_cpus - 1);

        /* Start each AP using SIPI */
        for (uint32_t i = 0; i < num_cpus; i++) {
            uint32_t apic_id = apic_ids[i];

            /* Skip BSP */
            if (apic_id == bsp_apic_id) {
                continue;
            }

            fut_printf("[SMP] Starting AP %u (APIC ID %u)...\n", i, apic_id);

            if (!smp_start_ap(apic_id)) {
                fut_printf("[SMP] WARNING: Failed to start AP %u (continuing boot)\n", apic_id);
                /* Continue boot even if AP fails to start */
            }
        }

        fut_printf("[SMP] Total online CPUs: %u (expected %u)\n", cpu_count, num_cpus);

        if (cpu_count < num_cpus) {
            fut_printf("[SMP] WARNING: Only %u of %u CPUs started (continuing)\n", cpu_count, num_cpus);
        }
    }
}
