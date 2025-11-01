/* pmap.h - ARM64 Physical Memory Mapping
 *
 * Copyright (c) 2025 Kelsi Davis
 * Licensed under the MPL v2.0 — see LICENSE for details.
 *
 * ARM64 physical memory mapping helpers matching x86_64/pmap.h interface.
 */

#pragma once

#include <platform/arm64/memory/paging.h>
#include <stddef.h>
#include <stdint.h>

typedef uint64_t phys_addr_t;

/* Permanent kernel direct-map window (higher-half). */
#define PMAP_DIRECT_VIRT_BASE  KERNEL_VIRTUAL_BASE

static inline uintptr_t pmap_phys_to_virt(phys_addr_t phys) {
    /* For MMIO regions, we use direct kernel mapping in higher-half */
    return (uintptr_t)phys | PMAP_DIRECT_VIRT_BASE;
}

static inline phys_addr_t pmap_virt_to_phys(uintptr_t virt) {
    if (virt >= PMAP_DIRECT_VIRT_BASE) {
        /* Mask off the high kernel bits to get physical address */
        return (phys_addr_t)(virt & ~PMAP_DIRECT_VIRT_BASE);
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
