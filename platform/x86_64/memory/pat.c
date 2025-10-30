// SPDX-License-Identifier: MPL-2.0
/*
 * pat.c - Page Attribute Table setup for x86_64
 */

#include <platform/x86_64/memory/pat.h>

#include <platform/x86_64/regs.h>
#include <platform/x86_64/memory/paging.h>

#define MSR_IA32_PAT 0x277u

static int cpu_has_pat(void) {
    uint32_t eax, ebx, ecx, edx;
    fut_cpuid(0x00000001u, &eax, &ebx, &ecx, &edx);
    return (edx & (1u << 16)) != 0; /* PAT bit */
}

void pat_init(void) {
    if (!cpu_has_pat()) {
        return;
    }

    uint64_t value = 0;
    /* PAT entries from 0 to 7 */
    const uint8_t entries[8] = {
        PAT_MT_WB,
        PAT_MT_WC,
        PAT_MT_WT,
        PAT_MT_UC_MINUS,
        PAT_MT_WB,
        PAT_MT_WC,
        PAT_MT_WT,
        PAT_MT_UC,
    };

    for (int i = 7; i >= 0; --i) {
        value <<= 8;
        value |= entries[i] & 0xFFu;
    }

    fut_write_msr(MSR_IA32_PAT, value);
}

uint64_t pat_choose_page_attr_wc(void) {
    /* Select PAT index 1 (001b) = WC: PWT=1, PCD=0, PAT=0 */
    return PTE_WRITE_THROUGH;
}
