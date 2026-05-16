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
#include <stddef.h>

/* ARM64 Memory Layout (after high VA kernel migration):
 *
 * Physical Memory:
 *   0x40000000 - 0x48000000  Kernel code/data/stack (128 MB)
 *   0x48000000 - 0x80000000  Available for allocation (~1.875 GB window
 *                            after the kernel image; PMM ram_end is
 *                            currently 0x80000000 to match boot.S L2_dram)
 *
 * Virtual Memory (TTBR1 - Kernel Space):
 *   0xFFFFFF8040000000 - 0xFFFFFF8080000000  Kernel + direct map (PA 0x40000000-0x80000000)
 *   0xFFFFFF8000000000 - 0xFFFFFF8040000000  Peripherals (maps PA 0x00000000)
 *
 * Virtual Memory (TTBR0 - User Space):
 *   0x0000000000400000 - ...  User code/data/stack
 */

/* Kernel physical base — QEMU virt places DTB at RAM base (0x40000000) and
 * loads the kernel Image at the next 2MB boundary (0x40200000).
 *
 * Compile-time literal; correct for QEMU virt only.  The runtime
 * actual load PA is also published by boot.S in `g_kernel_load_pa`
 * (see below) — once all callers of KERNEL_VIRT_OFFSET migrate to the
 * runtime accessor, this #define can drop and the kernel will be
 * relocatable in PA (Apple Silicon bring-up blocker #3). */
#define KERN_PA_BASE      0x40200000ULL

/* Kernel virtual base (where kernel is linked) */
#define KERN_VA_BASE      0xFFFFFF8040000000ULL

/* Kernel virtual offset (VA - PA) */
#define KERNEL_VIRT_OFFSET (KERN_VA_BASE - KERN_PA_BASE)

/* Runtime load metadata published by platform/arm64/boot.S.  These
 * are populated before any C code runs, from `adr x21, _start`:
 *
 *   g_kernel_load_pa   = 2 MiB-aligned-down _start PA  (the kernel
 *                        high-VA mapping's target PA)
 *   g_kernel_dram_pa   = 1 GiB-aligned-down identity DRAM base
 *   g_kernel_l1_index  = g_kernel_dram_pa >> 30        (boot L1 idx)
 *
 * On QEMU virt these are exactly 0x40200000 / 0x40000000 / 1 — the
 * same literals KERN_PA_BASE / 1 GiB-floor / L1[1] use today.  On
 * relocated boots (m1n1, future m1n1-loaded ARM64 hardware) they
 * carry the real load metadata so the runtime can adapt. */
extern uint64_t g_kernel_load_pa;
extern uint64_t g_kernel_dram_pa;
extern uint64_t g_kernel_l1_index;

/* Runtime accessors for the load metadata.  Use these (not the
 * compile-time KERN_PA_BASE / KERNEL_VIRT_OFFSET literals) in any
 * code that needs to keep working when the kernel is loaded at a
 * non-QEMU-virt physical address.  Until blocker #3 lands, the
 * literals and the runtime values agree on QEMU virt, so existing
 * callers stay correct. */
static inline uint64_t fut_kernel_load_pa(void) {
    return g_kernel_load_pa;
}

static inline uint64_t fut_kernel_dram_pa(void) {
    return g_kernel_dram_pa;
}

static inline uint64_t fut_kernel_virt_offset(void) {
    /* Runtime equivalent of KERNEL_VIRT_OFFSET = KERN_VA_BASE - load_PA. */
    return KERN_VA_BASE - g_kernel_load_pa;
}

/* Convert physical address to kernel virtual address.
 *
 * Reads the runtime offset published by boot.S so the conversion
 * tracks the actual load PA.  For QEMU virt this is identical to
 * the compile-time `KERNEL_VIRT_OFFSET` literal; for relocated
 * loads (m1n1, future ARM64 boards) it adapts automatically.
 * Closes the active half of Apple Silicon bring-up blocker #3. */
static inline void *pmap_phys_to_virt(uint64_t pa) {
    return (void *)(pa + fut_kernel_virt_offset());
}

/* Convert kernel virtual address to physical address.  Symmetric
 * to `pmap_phys_to_virt`. */
static inline uint64_t pmap_virt_to_phys(uintptr_t va) {
    return (uint64_t)va - fut_kernel_virt_offset();
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
