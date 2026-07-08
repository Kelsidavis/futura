/* cpu_features.c - x86_64 CPU feature negotiation
 *
 * Copyright (c) 2025 Futura OS
 * Licensed under the MPL v2.0 — see LICENSE for details.
 */

#include <platform/x86_64/cpu.h>
#include <platform/x86_64/msr.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdatomic.h>

#include <kernel/kprintf.h>

extern bool fut_serial_ready(void);

static inline void cpuid(uint32_t leaf, uint32_t subleaf,
                         uint32_t *a, uint32_t *b, uint32_t *c, uint32_t *d) {
    __asm__ volatile("cpuid"
                     : "=a"(*a), "=b"(*b), "=c"(*c), "=d"(*d)
                     : "a"(leaf), "c"(subleaf));
}

static inline uint64_t read_cr0(void) {
    uint64_t value;
    __asm__ volatile("mov %%cr0, %0" : "=r"(value));
    return value;
}

static inline void write_cr0(uint64_t value) {
    __asm__ volatile("mov %0, %%cr0" :: "r"(value) : "memory");
}

static inline uint64_t read_cr4(void) {
    uint64_t value;
    __asm__ volatile("mov %%cr4, %0" : "=r"(value));
    return value;
}

static inline void write_cr4(uint64_t value) {
    __asm__ volatile("mov %0, %%cr4" :: "r"(value) : "memory");
}

static inline void cpu_relax(void) {
    __asm__ volatile("pause");
}

#define CR0_EM            (1ULL << 2)
#define CR0_MP            (1ULL << 1)
#define CR0_NE            (1ULL << 5)

#define CR4_PGE           (1ULL << 7)
#define CR4_FSGSBASE      (1ULL << 16)
#define CR4_OSFXSR        (1ULL << 9)
#define CR4_OSXMMEXCPT    (1ULL << 10)
#define CR4_OSXSAVE       (1ULL << 18)
#define CR4_SMEP          (1ULL << 20)
#define CR4_SMAP          (1ULL << 21)

#define MSR_EFER          0xC0000080
#define EFER_NXE          (1ULL << 11)

#define XCR0_X87          (1ULL << 0)
#define XCR0_SSE          (1ULL << 1)

static fut_cpu_features_t g_features;
static _Atomic uint32_t g_state = 0; /* 0 = uninitialised, 1 = in-progress, 2 = done */
static _Atomic bool g_summary_printed = false;

static void maybe_print_summary(void) {
    if (atomic_load_explicit(&g_summary_printed, memory_order_acquire)) {
        return;
    }

    if (!fut_serial_ready()) {
        return;
    }

    fut_printf("[CPU] NX=%u OSXSAVE=%u SSE=%u AVX=%u FSGSBASE=%u PGE=%u SMEP=%u SMAP=%u PSE=%u PDPE1GB=%u\n",
               g_features.nx,
               g_features.osxsave,
               g_features.sse,
               g_features.avx,
               g_features.fsgsbase,
               g_features.pge,
               g_features.smep,
               g_features.smap,
               g_features.pse,
               g_features.pdpe1gb);

    atomic_store_explicit(&g_summary_printed, true, memory_order_release);
}

/* Apply the already-detected feature set to the CALLING CPU's control
 * registers. CR0/CR4/XCR0/EFER are per-CPU: detection can be done once
 * on the BSP, but every AP must program its own registers or the first
 * SSE instruction it executes (memset/memcpy use pxor) is a #UD. */
static void cpu_features_apply(const fut_cpu_features_t *f) {
    uint64_t cr0 = read_cr0();
    cr0 &= ~CR0_EM;
    cr0 |= CR0_MP | CR0_NE;
    write_cr0(cr0);

    uint64_t cr4 = read_cr4();
    if (f->sse)      cr4 |= CR4_OSFXSR | CR4_OSXMMEXCPT;
    if (f->pge)      cr4 |= CR4_PGE;
    if (f->fsgsbase) cr4 |= CR4_FSGSBASE;
    if (f->osxsave)  cr4 |= CR4_OSXSAVE;
    if (f->smep)     cr4 |= CR4_SMEP;
    if (f->smap)     cr4 |= CR4_SMAP;
    write_cr4(cr4);

    if (f->osxsave) {
        xsetbv(0, XCR0_X87 | XCR0_SSE);
    }

    if (f->nx) {
        uint64_t efer = rdmsr(MSR_EFER);
        efer |= EFER_NXE;
        wrmsr(MSR_EFER, efer);
    }
}

void cpu_features_init(void) {
    uint32_t expected = 0;
    if (!atomic_compare_exchange_strong_explicit(&g_state, &expected, 1,
                                                 memory_order_acquire,
                                                 memory_order_relaxed)) {
        /* Another core is initialising or done; wait, then apply the
         * detected features to THIS CPU's control registers. */
        while (atomic_load_explicit(&g_state, memory_order_acquire) == 1) {
            cpu_relax();
        }
        cpu_features_apply(&g_features);
        maybe_print_summary();
        return;
    }

    fut_cpu_features_t detected = {0};

    uint32_t max_basic = 0, ebx = 0, ecx = 0, edx = 0;
    cpuid(0, 0, &max_basic, &ebx, &ecx, &edx);

    uint32_t leaf1_eax = 0, leaf1_ebx = 0, leaf1_ecx = 0, leaf1_edx = 0;
    if (max_basic >= 1) {
        cpuid(1, 0, &leaf1_eax, &leaf1_ebx, &leaf1_ecx, &leaf1_edx);
    }

    uint32_t leaf7_ebx = 0;
    if (max_basic >= 7) {
        uint32_t l7eax = 0, l7ecx = 0, l7edx = 0;
        cpuid(7, 0, &l7eax, &leaf7_ebx, &l7ecx, &l7edx);
    }

    uint32_t max_extended = 0;
    uint32_t ext_eax = 0, ext_ebx = 0, ext_ecx = 0, ext_edx = 0;
    cpuid(0x80000000, 0, &max_extended, &ext_ebx, &ext_ecx, &ext_edx);
    if (max_extended >= 0x80000001) {
        cpuid(0x80000001, 0, &ext_eax, &ext_ebx, &ext_ecx, &ext_edx);
    }

    detected.sse      = (leaf1_edx & (1u << 25)) ? 1 : 0;
    detected.pge      = (leaf1_edx & (1u << 13)) ? 1 : 0;
    /* PSE (Page Size Extension) for 2MB large pages - bit 3 of EDX */
    detected.pse      = (leaf1_edx & (1u << 3)) ? 1 : 0;
    detected.fsgsbase = (leaf7_ebx & (1u << 0)) ? 1 : 0;
    detected.osxsave  = (leaf1_ecx & (1u << 27)) ? 1 : 0;
    detected.smep     = (leaf7_ebx & (1u << 7)) ? 1 : 0;
    detected.smap     = (leaf7_ebx & (1u << 20)) ? 1 : 0;
    detected.nx       = (ext_edx & (1u << 20)) ? 1 : 0;
    /* AVX is probed but not enabled yet (XCR0 stays X87|SSE) */
    detected.avx      = 0;
    /* PDPE1GB (1GB pages support) - bit 26 of extended EDX */
    detected.pdpe1gb  = (ext_edx & (1u << 26)) ? 1 : 0;

    g_features = detected;

    cpu_features_apply(&g_features);

    atomic_store_explicit(&g_state, 2, memory_order_release);
    maybe_print_summary();
}

const fut_cpu_features_t *cpu_features_get(void) {
    while (atomic_load_explicit(&g_state, memory_order_acquire) == 1) {
        cpu_relax();
    }
    return &g_features;
}
