/* smp.c - x86_64 SMP (Symmetric Multi-Processing) initialization
 *
 * Copyright (c) 2025 Futura OS
 * Licensed under the MPL v2.0 — see LICENSE for details.
 */

#include <platform/x86_64/interrupt/lapic.h>
#include <kernel/fut_percpu.h>
#include <stdint.h>
#include <stdbool.h>
#include <stdatomic.h>
#include <string.h>

#include <kernel/kprintf.h>

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

/* ============================================================
 *   Inter-processor interrupts
 * ============================================================ */

#define IPI_VECTOR_HALT 240
#define IPI_VECTOR_TLB  241
#define IPI_VECTOR_RESCHEDULE 242

static void udelay(uint32_t usec);

/* Outstanding TLB shootdown: number of CPUs that still need to ack.
 * One shootdown in flight at a time (tlb_ipi_lock). */
static _Atomic uint32_t tlb_ipi_pending;
static _Atomic uint32_t tlb_ipi_lock;

/* Handler for IPI_VECTOR_HALT — another CPU is dumping a panic and
 * needs the console (and the machine state) frozen. Never returns;
 * the LAPIC EOI is irrelevant at this point. */
void smp_ipi_halt_handler(void) {
    for (;;) {
        __asm__ volatile("cli\n\thlt" ::: "memory");
    }
}

/* Handler for IPI_VECTOR_TLB — flush this CPU's entire TLB (CR3
 * reload; global pages survive but the kernel maps user+heap without
 * PTE_GLOBAL) and ack. EOI is sent by irq_common_stub on return. */
void smp_ipi_tlb_handler(void) {
    uint64_t cr3;
    __asm__ volatile("mov %%cr3, %0\n\tmov %0, %%cr3" : "=r"(cr3) :: "memory");
    atomic_fetch_sub_explicit(&tlb_ipi_pending, 1, memory_order_release);
}

/**
 * Freeze every other CPU. Used by the panic path so a crash dump
 * isn't interleaved with output (or further damage) from other
 * cores. Safe to call before SMP is up — broadcasts nothing when
 * this is the only online CPU.
 */
void fut_smp_halt_others(void) {
    if (atomic_load_explicit(&cpu_count, memory_order_acquire) <= 1) {
        return;
    }
    lapic_send_ipi_all_except_self(IPI_VECTOR_HALT);
}

/**
 * Flush the TLB on every online CPU and wait for acknowledgement.
 *
 * Callers must NOT hold spinlocks another CPU could be spinning on
 * with IRQs disabled — that CPU can't take the IPI and the wait
 * would deadlock. The wait therefore has a timeout: on expiry we
 * proceed anyway (the remote CPU will flush on its next natural CR3
 * reload; a stale translation window is preferable to a hard hang).
 */
void fut_tlb_shootdown_all(void) {
    uint32_t online = atomic_load_explicit(&cpu_count, memory_order_acquire);
    if (online <= 1) {
        return; /* Caller already flushed locally (or will) */
    }

    /* Serialize shootdowns — the pending counter is single-shot. */
    uint32_t expected = 0;
    while (!atomic_compare_exchange_weak_explicit(&tlb_ipi_lock, &expected, 1,
                                                  memory_order_acquire,
                                                  memory_order_relaxed)) {
        expected = 0;
        __asm__ volatile("pause");
    }

    atomic_store_explicit(&tlb_ipi_pending, online - 1, memory_order_release);
    lapic_send_ipi_all_except_self(IPI_VECTOR_TLB);

    /* ~10ms timeout at the udelay calibration used elsewhere here. */
    for (int i = 0; i < 10000; i++) {
        if (atomic_load_explicit(&tlb_ipi_pending, memory_order_acquire) == 0) {
            break;
        }
        udelay(1);
    }

    atomic_store_explicit(&tlb_ipi_lock, 0, memory_order_release);
}

/**
 * Wake a CPU that may be halted in its AP idle loop after a remote
 * scheduler enqueue. The IPI handler itself is a no-op; returning from the
 * interrupt gets the AP back to the idle loop, which immediately polls the
 * scheduler before halting again.
 */
void fut_smp_reschedule_cpu(uint32_t cpu_index) {
    uint32_t online = atomic_load_explicit(&cpu_count, memory_order_acquire);
    if (online <= 1 || cpu_index >= MAX_CPUS) {
        return;
    }

    fut_percpu_t *percpu = &fut_percpu_data[cpu_index];
    if (!percpu->self) {
        return;
    }

    lapic_send_ipi(percpu->cpu_id, IPI_VECTOR_RESCHEDULE);
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
 *
 * Bring-up order is load-bearing:
 *   1. lidt            — any exception before this triple-faults silently
 *   2. per-CPU GDT/TSS — segment reload zeroes GS base, so this MUST
 *                        precede fut_percpu_set; ltr needs a per-CPU
 *                        TSS descriptor (busy-bit forbids sharing)
 *   3. fut_percpu_set  — GS base; ISR stubs write %gs:PERCPU_* from
 *                        the first interrupt on
 *   4. syscall MSRs    — LSTAR/STAR/FMASK/EFER.SCE are per-CPU
 *   5. LAPIC + timer   — BSP-calibrated count so all CPUs tick alike
 */
void ap_main(uint32_t apic_id) {
    /* Load the kernel IDT into THIS CPU's IDTR before doing anything that
     * might raise an exception. The BSP's IDT is fully populated and is
     * shared by every CPU (interrupt gates don't have busy bits). */
    extern void fut_idt_load(void);
    fut_idt_load();

    /* Program this CPU's CR0/CR4/XCR0/EFER from the BSP-detected
     * feature set. Must precede any memset/memcpy: those use SSE
     * (pxor %xmm...) and the AP arrives with CR4.OSFXSR clear — the
     * first SSE instruction is an immediate #UD. */
    extern void cpu_features_init(void);
    cpu_features_init();

    /* Validate APIC ID is within bounds */
    if (apic_id >= MAX_CPUS) {
        for (;;) __asm__ volatile("hlt");
    }

    /* Get unique CPU index atomically */
    uint32_t cpu_index = atomic_fetch_add_explicit(&cpu_count, 1, memory_order_seq_cst);
    if (cpu_index >= FUT_MAX_CPUS) {
        for (;;) __asm__ volatile("hlt");
    }

    /* Initialize per-CPU data for this AP (memsets the slot, stamps
     * self/cpu_id/cpu_index, inits the ready-queue lock). */
    fut_percpu_init(apic_id, cpu_index);

    /* Per-CPU GDT + TSS, then GS base, then syscall MSRs. */
    extern int fut_tss_init_ap(fut_percpu_t *percpu);
    extern void fut_syscall_msr_init(void);
    if (fut_tss_init_ap(&fut_percpu_data[cpu_index]) != 0) {
        fut_printf("[SMP] ERROR: TSS init failed for CPU %u, halting AP\n", apic_id);
        for (;;) __asm__ volatile("hlt");
    }
    fut_percpu_set(&fut_percpu_data[cpu_index]);
    fut_syscall_msr_init();

    /* Initialize LAPIC for this CPU */
    extern void lapic_init(uint64_t lapic_base);
    lapic_init(0xFEE00000);  /* Standard LAPIC address */

    /* Mark CPU as online */
    cpu_online[apic_id] = true;

    fut_printf("[SMP] AP CPU %u initialized as CPU #%u (total CPUs: %u)\n",
               apic_id, cpu_index, atomic_load_explicit(&cpu_count, memory_order_seq_cst));

    /* Initialize scheduler for this CPU (creates per-CPU idle thread,
     * sets it as current so the first timer-tick fut_schedule has a
     * valid prev). */
    extern void fut_sched_init_cpu(void);
    fut_sched_init_cpu();

    /* Reuse the BSP's PIT-calibrated count (lapic_timer_calibrate runs
     * inside acpi_parse_madt, before smp_init). Fallback to 10M (~6 Hz)
     * only if calibration somehow failed. */
    extern void lapic_timer_periodic(uint32_t initial_count, uint8_t vector);
    extern uint32_t lapic_timer_get_calibrated_count(void);
    #define LAPIC_TIMER_FALLBACK_COUNT 10000000
    #define LAPIC_TIMER_INT_VECTOR 32  /* INT_APIC_TIMER */
    uint32_t timer_count = lapic_timer_get_calibrated_count();
    if (timer_count == 0) {
        timer_count = LAPIC_TIMER_FALLBACK_COUNT;
    }
    lapic_timer_periodic(timer_count, LAPIC_TIMER_INT_VECTOR);

    fut_printf("[SMP] AP CPU %u entering idle loop (timer count %u)\n",
               apic_id, timer_count);

    /* Idle loop. Timer IRQs (vector 32) drive fut_sched_tick →
     * fut_schedule on this CPU; when a thread lands on our ready
     * queue the IRQ path context-switches away, and switching back
     * to the idle thread resumes right here. */
    while (1) {
        __asm__ volatile("sti\n\thlt" ::: "memory");
        fut_schedule();
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
    if (apic_id >= MAX_CPUS) {
        fut_printf("[SMP] ERROR: APIC ID %u out of range\n", apic_id);
        return false;
    }
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
