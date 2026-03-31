// SPDX-License-Identifier: MPL-2.0
/*
 * pmap.h - Physical memory mapping helpers for x86_64
 *
 * Phase 0 scaffolding: provides the minimal kernel helpers needed to ensure
 * that page-table entries store raw physical frame numbers while the kernel
 * can still obtain a temporary virtual mapping of those frames when touching
 * the tables. Later phases will extend this interface to cover additional
 * MMU features, but the small surface below keeps the paging code decoupled
 * from direct pointer arithmetic.
 */

#pragma once

#include <stddef.h>
#include <stdint.h>

#include <platform/x86_64/memory/paging.h>

typedef uint64_t phys_addr_t;

/* Permanent kernel direct-map window (higher-half). */
#define PMAP_DIRECT_VIRT_BASE  KERNEL_VIRTUAL_BASE

static inline uintptr_t pmap_phys_to_virt(phys_addr_t phys) {
    /* Map physical addresses to kernel virtual addresses.
     * The direct-map window at PMAP_DIRECT_VIRT_BASE (0xFFFFFFFF80000000)
     * only covers physical addresses 0 to 0x7FFFFFFF (2GB) because adding
     * higher physical addresses wraps around past 64-bit boundary.
     *
     * For MMIO devices above 2GB physical (LAPIC at 0xFEE00000, framebuffer
     * at 0xFD000000, etc.), use a secondary mapping window at 0xFFFFFFFF00000000
     * which covers physical 0x80000000 to 0xFFFFFFFF. */
    if (phys >= 0x80000000ULL && phys < 0x100000000ULL) {
        /* High physical: map into 0xFFFFFFFF00000000 + (phys - 0x80000000) */
        return (uintptr_t)(0xFFFFFFFF00000000ULL + (phys - 0x80000000ULL));
    }
    return (uintptr_t)(phys + PMAP_DIRECT_VIRT_BASE);
}

static inline phys_addr_t pmap_virt_to_phys(uintptr_t virt) {
    /* Reverse the secondary MMIO window mapping (0xFFFFFFFF00000000-0xFFFFFFFF7FFFFFFF) */
    if (virt >= 0xFFFFFFFF00000000ULL && virt < PMAP_DIRECT_VIRT_BASE) {
        return (phys_addr_t)((virt - 0xFFFFFFFF00000000ULL) + 0x80000000ULL);
    }
    if (virt >= PMAP_DIRECT_VIRT_BASE) {
        return (phys_addr_t)(virt - PMAP_DIRECT_VIRT_BASE);
    }
    return (phys_addr_t)virt;
}

void *pmap_kmap(phys_addr_t phys);
void pmap_kunmap(void *virt);

int pmap_map(uint64_t vaddr, phys_addr_t paddr, size_t len, uint64_t prot);
int pmap_unmap(uint64_t vaddr, size_t len);
int pmap_protect(uint64_t vaddr, size_t len, uint64_t prot);
void pmap_dump(uint64_t vaddr, size_t len);
int pmap_probe_pte(struct fut_vmem_context *ctx, uint64_t vaddr, uint64_t *pte_out);
int pmap_map_user(struct fut_vmem_context *ctx, uint64_t uaddr, phys_addr_t paddr,
                  size_t len, uint64_t prot);
int pmap_set_page_ro(struct fut_vmem_context *ctx, uint64_t vaddr);
void pmap_free_tables(struct fut_vmem_context *ctx);
