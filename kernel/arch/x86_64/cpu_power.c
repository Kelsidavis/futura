// SPDX-License-Identifier: MPL-2.0
/*
 * kernel/arch/x86_64/cpu_power.c - x86-64 CPU power-management policy
 *
 * Implements the architecture-neutral cpu_power_* API from
 * include/kernel/cpu_power.h.  All MSR access is gated behind a
 * CPUID vendor check so this code stays no-op on AMD, VIA, Zhaoxin,
 * and any other non-Intel x86_64 part where 0xE2 / 0x1FC don't
 * exist (a #GP from rdmsr/wrmsr on a missing MSR would panic the
 * boot).  Future AMD support belongs in its own branch here.
 */

#include <kernel/cpu_power.h>
#include <kernel/errno.h>

#include <stdint.h>
#include <stdbool.h>

extern void fut_printf(const char *fmt, ...);

#define MSR_PKG_CST_CONFIG_CONTROL  0xE2u
#define IA32_POWER_CTL              0x1FCu
#define MSR_PMG_IO_CAPTURE_BASE     0xE4u

static inline uint64_t cpup_rdmsr(uint32_t msr) {
    uint32_t lo, hi;
    __asm__ volatile("rdmsr" : "=a"(lo), "=d"(hi) : "c"(msr));
    return ((uint64_t)hi << 32) | lo;
}

static inline void cpup_wrmsr(uint32_t msr, uint64_t value) {
    uint32_t lo = (uint32_t)value;
    uint32_t hi = (uint32_t)(value >> 32);
    __asm__ volatile("wrmsr" :: "a"(lo), "d"(hi), "c"(msr));
}

static bool cpu_is_intel(void) {
    uint32_t eax, ebx, ecx, edx;
    __asm__ volatile("cpuid"
                     : "=a"(eax), "=b"(ebx), "=c"(ecx), "=d"(edx)
                     : "a"(0u));
    /* "GenuineIntel": EBX="Genu", EDX="ineI", ECX="ntel" (LE). */
    return ebx == 0x756e6547u
        && edx == 0x49656e69u
        && ecx == 0x6c65746eu;
}

int cpu_power_cap_cstates(unsigned int max_cstate) {
    if (!cpu_is_intel()) {
        return -ENOSYS;
    }
    if (max_cstate > 15u) {
        max_cstate = 15u;  /* MSR field is 4 bits */
    }

    uint64_t cur = cpup_rdmsr(MSR_PKG_CST_CONFIG_CONTROL);
    bool locked = (cur & (1ULL << 15)) != 0;
    fut_printf("[CSTATE] MSR_PKG_CST_CONFIG_CONTROL=0x%llx (CFG_LOCK=%d, current_limit=%u)\n",
               (unsigned long long)cur, locked ? 1 : 0, (unsigned)(cur & 0xFu));
    if (locked) {
        return -EBUSY;
    }

    uint64_t next = (cur & ~0xFULL) | (uint64_t)(max_cstate & 0xFu);
    cpup_wrmsr(MSR_PKG_CST_CONFIG_CONTROL, next);
    uint64_t after = cpup_rdmsr(MSR_PKG_CST_CONFIG_CONTROL);
    fut_printf("[CSTATE] cap applied: limit=%u readback=0x%llx\n",
               max_cstate, (unsigned long long)after);

    /* Disable I/O-based C-state entry too.  Some Intel parts let the
     * PCU enter deep C-states when the OS does a read on a magic
     * I/O port; clearing PMG_IO_CAPTURE_BASE shuts that path. */
    uint64_t io_cap = cpup_rdmsr(MSR_PMG_IO_CAPTURE_BASE);
    cpup_wrmsr(MSR_PMG_IO_CAPTURE_BASE, 0ULL);
    fut_printf("[CSTATE] MSR_PMG_IO_CAPTURE_BASE 0x%llx -> 0x0 (I/O-based C-state disabled)\n",
               (unsigned long long)io_cap);

    return 0;
}

int cpu_power_disable_c1e(void) {
    if (!cpu_is_intel()) {
        return -ENOSYS;
    }
    uint64_t cur = cpup_rdmsr(IA32_POWER_CTL);
    if ((cur & (1ULL << 1)) == 0) {
        /* Already off. */
        fut_printf("[CSTATE] IA32_POWER_CTL=0x%llx (C1E already disabled)\n",
                   (unsigned long long)cur);
        return 0;
    }
    uint64_t next = cur & ~(1ULL << 1);
    cpup_wrmsr(IA32_POWER_CTL, next);
    uint64_t after = cpup_rdmsr(IA32_POWER_CTL);
    fut_printf("[CSTATE] IA32_POWER_CTL 0x%llx -> 0x%llx (C1E disabled)\n",
               (unsigned long long)cur, (unsigned long long)after);
    return 0;
}
