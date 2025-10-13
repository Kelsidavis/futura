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

#include <arch/x86_64/paging.h>

typedef uint64_t phys_addr_t;

/* Permanent kernel direct-map window (higher-half). */
#define PMAP_DIRECT_VIRT_BASE  KERNEL_VIRTUAL_BASE

static inline uintptr_t pmap_phys_to_virt(phys_addr_t phys) {
    return (uintptr_t)(phys + PMAP_DIRECT_VIRT_BASE);
}

static inline phys_addr_t pmap_virt_to_phys(uintptr_t virt) {
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
