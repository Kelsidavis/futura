// SPDX-License-Identifier: MPL-2.0
/*
 * gdt.c - Helper routines for x86_64 GDT/TSS management
 *
 * SMP: the TSS cannot be shared between CPUs — ltr marks the
 * descriptor busy (a second ltr on the same descriptor #GPs), and
 * rsp0 is inherently per-CPU (it's where ring3→ring0 transitions
 * land). Each AP therefore gets its own GDT copy with its own TSS
 * descriptor in slot 5 (fut_tss_init_ap); selectors stay identical
 * across CPUs so STAR/IDT/asm never need per-CPU values. The BSP
 * keeps the static gdt64_table + g_kernel_tss it has always used.
 */

#include <platform/x86_64/gdt.h>
#include <platform/x86_64/regs.h>
#include <kernel/fut_percpu.h>

#include <string.h>

extern uint64_t gdt64_table[];
extern void *fut_malloc(uint64_t size);

#define TSS_SELECTOR 0x28
#define USER_DATA_SELECTOR 0x1b
#define DF_IST_STACK_SIZE 16384
#define GDT_QUADS 7   /* null, kcode, kdata, udata, ucode, TSS lo, TSS hi */

static tss_t g_kernel_tss __attribute__((aligned(16)));
static uint8_t g_df_ist_stack[DF_IST_STACK_SIZE] __attribute__((aligned(16)));

/* Encode a 64-bit TSS descriptor into two GDT quads. */
static void tss_descriptor(tss_t *tss, uint64_t *lo, uint64_t *hi) {
    uint64_t base = (uint64_t)tss;
    uint64_t limit = sizeof(tss_t) - 1u;

    uint64_t low = 0;
    low |= (limit & 0xFFFFu);
    low |= (base & 0xFFFFFFu) << 16;
    low |= ((uint64_t)0x89) << 40; /* Type=0x9 (available TSS), present */
    low |= (limit & 0xF0000u) << 32;
    low |= ((base >> 24) & 0xFFu) << 56;

    *lo = low;
    *hi = (base >> 32) & 0xFFFFFFFFu;
}

void fut_gdt_set_tss(tss_t *tss) {
    if (!tss) {
        return;
    }
    tss_descriptor(tss, &gdt64_table[5], &gdt64_table[6]);
}

void fut_tss_init(void) {
    memset(&g_kernel_tss, 0, sizeof(g_kernel_tss));
    g_kernel_tss.iomap_base = sizeof(tss_t);

    /* Use current stack as initial ring0 stack */
    uint64_t rsp = fut_get_rsp();
    g_kernel_tss.rsp0 = rsp;
    g_kernel_tss.ist[0] = (uint64_t)(uintptr_t)(g_df_ist_stack + sizeof(g_df_ist_stack));

    fut_gdt_set_tss(&g_kernel_tss);
    fut_ltr(TSS_SELECTOR);
}

/* Resolve the calling CPU's TSS: APs stash theirs in percpu->tss
 * during fut_tss_init_ap; the BSP (and the earliest boot window,
 * before per-CPU data exists) falls back to the static kernel TSS. */
static tss_t *current_cpu_tss(void) {
    tss_t *tss = (tss_t *)fut_percpu_get_or_bsp()->tss;
    return tss ? tss : &g_kernel_tss;
}

void fut_tss_set_kernel_stack(uint64_t rsp0) {
    current_cpu_tss()->rsp0 = rsp0;
}

uint64_t fut_tss_get_kernel_stack(void) {
    return current_cpu_tss()->rsp0;
}

/**
 * Give an Application Processor its own GDT + TSS and load them.
 *
 * Called from ap_main() early in AP bring-up, BEFORE fut_percpu_set:
 * the segment reload in the lgdt sequence writes the GS selector,
 * which zeroes the GS base MSR — any earlier per-CPU setup through
 * GS would be lost. Caller passes this CPU's fut_percpu_t so the TSS
 * pointer can be stashed for fut_tss_set_kernel_stack.
 *
 * Returns 0 on success, negative on allocation failure.
 */
int fut_tss_init_ap(fut_percpu_t *percpu) {
    if (!percpu) {
        return -1;
    }

    /* One allocation for GDT + TSS + double-fault IST stack. The GDT
     * needs 16-byte alignment; fut_malloc returns 16-aligned blocks. */
    uint64_t *gdt = fut_malloc(GDT_QUADS * sizeof(uint64_t));
    tss_t *tss = fut_malloc(sizeof(tss_t));
    uint8_t *df_stack = fut_malloc(DF_IST_STACK_SIZE);
    if (!gdt || !tss || !df_stack) {
        return -2;
    }

    /* Clone the BSP's GDT — segment descriptors are identical on
     * every CPU; only the TSS descriptor differs. */
    memcpy(gdt, gdt64_table, GDT_QUADS * sizeof(uint64_t));

    memset(tss, 0, sizeof(*tss));
    tss->iomap_base = sizeof(tss_t);
    tss->rsp0 = fut_get_rsp();
    tss->ist[0] = (uint64_t)(uintptr_t)(df_stack + DF_IST_STACK_SIZE);

    tss_descriptor(tss, &gdt[5], &gdt[6]);

    /* Load the per-CPU GDT and task register. */
    struct {
        uint16_t limit;
        uint64_t base;
    } __attribute__((packed)) gdtr = {
        .limit = (uint16_t)(GDT_QUADS * sizeof(uint64_t) - 1),
        .base = (uint64_t)gdt,
    };
    __asm__ volatile(
        "lgdt %0\n\t"
        /* Reload CS to 0x08 via far return. The AP arrives here with
         * CS=0x18 from the trampoline's transition GDT; in the kernel
         * GDT layout 0x18 is the USER DATA slot, so the first IRETQ
         * (which reloads CS from the current GDT) would #GP. */
        "pushq $0x08\n\t"
        "leaq 1f(%%rip), %%rax\n\t"
        "pushq %%rax\n\t"
        "lretq\n\t"
        "1:\n\t"
        /* Reload data segments from the new GDT (same values, but the
         * hidden descriptor caches should come from our table). */
        "movw $0x10, %%ax\n\t"
        "movw %%ax, %%ds\n\t"
        "movw %%ax, %%es\n\t"
        "movw %%ax, %%ss\n\t"
        :
        : "m"(gdtr)
        : "rax", "memory");
    fut_ltr(TSS_SELECTOR);

    percpu->tss = tss;
    return 0;
}
