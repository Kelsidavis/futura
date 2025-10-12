// SPDX-License-Identifier: MPL-2.0
/*
 * gdt.c - Helper routines for x86_64 GDT/TSS management
 */

#include <arch/x86_64/gdt.h>
#include <arch/x86_64/regs.h>

#include <string.h>

extern uint64_t gdt64_table[];

#define TSS_SELECTOR 0x28
#define USER_DATA_SELECTOR 0x23

static tss_t g_kernel_tss __attribute__((aligned(16)));

void fut_gdt_set_tss(tss_t *tss) {
    if (!tss) {
        return;
    }

    uint64_t base = (uint64_t)tss;
    uint64_t limit = sizeof(tss_t) - 1u;

    uint64_t low = 0;
    low |= (limit & 0xFFFFu);
    low |= (base & 0xFFFFFFu) << 16;
    low |= ((uint64_t)0x89) << 40; /* Type=0x9 (available TSS), present */
    low |= (limit & 0xF0000u) << 32;
    low |= ((base >> 24) & 0xFFu) << 56;

    uint64_t high = (base >> 32) & 0xFFFFFFFFu;

    gdt64_table[5] = low;
    gdt64_table[6] = high;
}

void fut_tss_init(void) {
    memset(&g_kernel_tss, 0, sizeof(g_kernel_tss));
    g_kernel_tss.iomap_base = sizeof(tss_t);

    /* Use current stack as initial ring0 stack */
    uint64_t rsp = fut_get_rsp();
    g_kernel_tss.rsp0 = rsp;

    fut_gdt_set_tss(&g_kernel_tss);
    fut_ltr(TSS_SELECTOR);
}

void fut_tss_set_kernel_stack(uint64_t rsp0) {
    g_kernel_tss.rsp0 = rsp0;
}
