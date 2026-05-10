/* SPDX-License-Identifier: MPL-2.0
 * x86_mtrr_wc.c — mark a physical range Write-Combining via the boot
 * identity map's PD entries.
 *
 * Boot.S sets up four PD pages (boot_pd / boot_pd1 / boot_pd2 / boot_pd3)
 * each mapping 1 GiB of physical memory with 512 × 2 MiB huge pages, so
 * the first 4 GiB of phys is identity-mapped (and the first 2 GiB is
 * also mirrored into the higher-half kernel mapping). pat_init then
 * programs the IA32_PAT MSR so that PAT index 1 = Write-Combining.
 *
 * For a 2 MiB huge-page PD entry, the memory-type selector bits are:
 *   PWT  = bit 3
 *   PCD  = bit 4
 *   PAT  = bit 12  (different from 4 KiB pages where PAT lives at bit 7)
 *
 * Setting PWT=1, PCD=0, PAT=0 selects PAT index 1, which is WC. So all
 * we need to do is OR bit 3 into the relevant PD entries and INVLPG
 * each 2 MiB virtual page they cover.
 *
 * Why this matters:
 *   On the GOP framebuffer Coreboot/UEFI hands us, the physical pages
 *   default to Write-Back caching unless the firmware configured an
 *   MTRR override. WB framebuffer writes go L1 → L2 → L3 → DRAM, with
 *   each pixel write potentially spilling a cache line — visibly slow
 *   on bare metal during the boot-log scroll. WC writes batch into
 *   64-byte bursts in a small write-combining buffer, then flush in
 *   one go; ~5-10x faster for sequential pixel writes.
 *
 * Boundaries:
 *   - Range must lie within the first 4 GiB (we only have PDs for that).
 *   - Anything outside that range is silently skipped.
 *   - The 2 MiB granularity means surrounding memory in the same huge
 *     page also becomes WC. That's fine for FB BARs which are usually
 *     isolated MMIO; not fine for marking system DRAM WC. */

#include <stdint.h>
#include <stddef.h>
#include <kernel/kprintf.h>

extern uint64_t boot_pd[512];
extern uint64_t boot_pd1[512];
extern uint64_t boot_pd2[512];
extern uint64_t boot_pd3[512];

#define PDE_PWT_BIT      (1ULL << 3)   /* PAT selector bit 0 → selects PAT[1] = WC */
#define HUGE_PAGE_SIZE   (2ULL * 1024 * 1024)
#define KERNEL_HALF_BASE 0xFFFFFFFF80000000ULL

void x86_mark_phys_wc(uint64_t phys, uint64_t size) {
    if (size == 0) return;
    uint64_t start = phys & ~(HUGE_PAGE_SIZE - 1);
    uint64_t end = (phys + size + HUGE_PAGE_SIZE - 1) & ~(HUGE_PAGE_SIZE - 1);
    if (start >= (4ULL << 30) || end > (4ULL << 30)) {
        fut_printf("[MTRR-WC] phys 0x%llx + size 0x%llx outside 0-4 GiB boot map; skipped\n",
                   (unsigned long long)phys, (unsigned long long)size);
        return;
    }

    int updated = 0;
    for (uint64_t p = start; p < end; p += HUGE_PAGE_SIZE) {
        uint64_t *pd;
        uint64_t idx;
        if (p < (1ULL << 30))         { pd = boot_pd;  idx = p / HUGE_PAGE_SIZE; }
        else if (p < (2ULL << 30))    { pd = boot_pd1; idx = (p - (1ULL << 30)) / HUGE_PAGE_SIZE; }
        else if (p < (3ULL << 30))    { pd = boot_pd2; idx = (p - (2ULL << 30)) / HUGE_PAGE_SIZE; }
        else                          { pd = boot_pd3; idx = (p - (3ULL << 30)) / HUGE_PAGE_SIZE; }

        if ((pd[idx] & PDE_PWT_BIT) == 0) {
            pd[idx] |= PDE_PWT_BIT;
            updated++;
        }

        /* Flush TLB for both the identity-map and (when applicable) the
         * higher-half mirror of this 2 MiB page. Higher-half mirror
         * covers phys 0-2 GiB only (PDPT[510] → boot_pd, PDPT[511] →
         * boot_pd1) so we only INVLPG the higher half if p < 2 GiB. */
        __asm__ volatile("invlpg (%0)" :: "r"(p) : "memory");
        if (p < (2ULL << 30)) {
            __asm__ volatile("invlpg (%0)" :: "r"(KERNEL_HALF_BASE + p) : "memory");
        }
    }

    fut_printf("[MTRR-WC] Marked %d × 2 MiB pages WC (phys 0x%llx, %d MiB)\n",
               updated,
               (unsigned long long)start,
               (int)((end - start) / (1024 * 1024)));
}
