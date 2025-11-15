/* pmap.h - ARM64 Physical Memory Address Translation
 *
 * Copyright (c) 2025 Kelsi Davis
 * Licensed under the MPL v2.0 — see LICENSE for details.
 *
 * Physical to virtual address translation for ARM64 high-VA kernel.
 */

#ifndef ARM64_PMAP_H
#define ARM64_PMAP_H

#include <stdint.h>

/* ARM64 Memory Layout (after high VA kernel migration):
 *
 * Physical Memory:
 *   0x40000000 - 0x48000000  Kernel code/data/stack (128 MB)
 *   0x48000000 - 0x60000000  Available for allocation
 *
 * Virtual Memory (TTBR1 - Kernel Space):
 *   0xFFFFFF8040000000 - 0xFFFFFF8048000000  Kernel (maps PA 0x40000000)
 *   0xFFFFFF8000000000 - 0xFFFFFF8040000000  Peripherals (maps PA 0x00000000)
 *
 * Virtual Memory (TTBR0 - User Space):
 *   0x0000000000400000 - ...  User code/data/stack
 */

/* Kernel physical base (where QEMU loads the kernel) */
#define KERN_PA_BASE      0x40000000ULL

/* Kernel virtual base (where kernel is linked) */
#define KERN_VA_BASE      0xFFFFFF8040000000ULL

/* Kernel virtual offset (VA - PA) */
#define KERNEL_VIRT_OFFSET (KERN_VA_BASE - KERN_PA_BASE)

/* Convert physical address to kernel virtual address */
static inline void *pmap_phys_to_virt(uint64_t pa) {
    return (void *)(pa + KERNEL_VIRT_OFFSET);
}

/* Convert kernel virtual address to physical address */
static inline uint64_t pmap_virt_to_phys(const void *va) {
    return (uint64_t)va - KERNEL_VIRT_OFFSET;
}

/* Backwards compatibility aliases */
#define phys_to_virt pmap_phys_to_virt
#define virt_to_phys pmap_virt_to_phys

typedef uint64_t phys_addr_t;

/* Forward declaration for vmem context */
struct fut_vmem_context;

/* Platform-specific paging functions */
int pmap_probe_pte(struct fut_vmem_context *ctx, uint64_t vaddr, uint64_t *pte_out);
int pmap_map_user(struct fut_vmem_context *ctx, uint64_t uaddr, phys_addr_t paddr,
                  size_t len, uint64_t prot);
int pmap_unmap(uint64_t vaddr, size_t len);
void *pmap_kmap(phys_addr_t phys);

#endif /* ARM64_PMAP_H */
