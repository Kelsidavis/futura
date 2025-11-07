# ARM64 Page Table Bugs Fixed - Session 2025-11-07

## Summary

Fixed **two critical ARM64 page table bugs** that were preventing user-space execution. The system now successfully loads ELF binaries, maps pages, and attempts ERET to user mode.

## Bugs Fixed

### Bug 1: L3 Page Descriptor Type Bits (kernel/mm/arm64_paging.c:321)

**Problem**: ARM64 L3 page descriptors require bits [1:0] = 0b11 to indicate a valid page descriptor. The code was only setting PTE_VALID (bit 0 = 1), resulting in bits [1:0] = 0b01, which the MMU treats as an invalid descriptor.

**Symptoms**:
- Translation fault at level 2 (FSC=0x06) when trying to execute user code
- Pages were mapped via `pmap_map_user()` but CPU couldn't fetch instructions
- QEMU exception log: `Taking exception 3 [Prefetch Abort]...with ESR 0x82000006...with FAR 0x400000`

**Root Cause**:
```c
/* BEFORE (BUGGY) - line 321 */
pte_t pte = fut_make_pte(paddr, arm64_flags);  // Missing PTE_TABLE bit!
pte_table->entries[pte_idx] = pte;
```

According to ARM64 descriptor format:
- **Table descriptors** (L1/L2): bits [1:0] = 0b11 (PTE_TYPE_TABLE = 0x3)
- **Page descriptors** (L3): bits [1:0] = 0b11 (PTE_TYPE_PAGE = 0x3)
- **Block descriptors** (L1/L2): bits [1:0] = 0b01 (PTE_TYPE_BLOCK = 0x1)
- **Invalid**: bits [1:0] = 0b00

The code was creating L3 entries with only PTE_VALID set, making them look like L1/L2 block descriptors at the wrong level.

**Fix**:
```c
/* AFTER (FIXED) - line 321 */
/* For level 3 page descriptors, bits [1:0] must be 0b11 (PTE_TYPE_PAGE)
 * This means we need PTE_VALID (bit 0) | PTE_TABLE (bit 1) = 0b11 */
pte_t pte = fut_make_pte(paddr, arm64_flags | PTE_TABLE);
pte_table->entries[pte_idx] = pte;
```

**Result**: Translation faults eliminated! Pages now translate correctly.

---

### Bug 2: 4-Level → 3-Level Page Table Fix (platform/arm64/memory/pmap.c:112-162)

**Problem**: `pmap_probe_pte()` was using a 4-level page table hierarchy, but ARM64 with T0SZ=25 (39-bit virtual address space) only needs 3 levels.

**Symptoms**:
- `exec_copy_to_user()` failed with -EFAULT
- Debug output: `[MAP-SEG-ARM64] ERROR: exec_copy_to_user failed`
- ELF segment data couldn't be copied to user space

**Root Cause**:
```c
/* BEFORE (BUGGY) - lines 139-165 */
/* L2: PTE walk */
uint64_t pte_phys = fut_pte_to_phys(pmde);
page_table_t *pte = pmap_table_from_phys(pte_phys);
pte_t pte_entry = pte->entries[pte_idx];
if (!fut_pte_is_present(pte_entry)) {
    return -EFAULT;
}

/* Level 3: PAGE walk (final level) - WRONG! This doesn't exist! */
uint64_t pt_phys = fut_pte_to_phys(pte_entry);  // Treats L3 page as table pointer
page_table_t *page_tbl = pmap_table_from_phys(pt_phys);
pte_t page_entry = page_tbl->entries[page_idx];  // Tries to access non-existent L4
```

The function was:
1. Walking L1 (PGD) → L2 (PMD) → L3 (PTE table) correctly
2. Reading L3 entry (which should be the **final page descriptor**)
3. **BUG**: Treating L3 entry as a table pointer to non-existent L4
4. Using PAGE_INDEX() to extract bits [11:0], which duplicates PTE_INDEX bits

**ARM64 with T0SZ=25 (39-bit VA) uses 3-level paging**:
- **L1 (PGD)**: bits [38:30] → 512 entries × 1GB = 512GB range
- **L2 (PMD)**: bits [29:21] → 512 entries × 2MB = 1GB range
- **L3 (PTE)**: bits [20:12] → 512 entries × 4KB = 2MB range (FINAL LEVEL)
- **Offset**: bits [11:0] → 4KB page offset

**Fix**:
```c
/* AFTER (FIXED) - lines 112-162 */
/* ARM64 with T0SZ=25 (39-bit VA) uses 3-level page tables:
 * L1 (PGD): bits [38:30] -> L2 table
 * L2 (PMD): bits [29:21] -> L3 table
 * L3 (PTE): bits [20:12] -> physical page
 */
uint64_t pgd_idx = PGD_INDEX(vaddr);
uint64_t pmd_idx = PMD_INDEX(vaddr);
uint64_t pte_idx = PTE_INDEX(vaddr);

/* L1 (PGD) walk */
pte_t pgde = pgd->entries[pgd_idx];
if (!fut_pte_is_present(pgde)) {
    return -EFAULT;
}

/* L2 (PMD) walk */
uint64_t pmd_phys = fut_pte_to_phys(pgde);
page_table_t *pmd = pmap_table_from_phys(pmd_phys);
pte_t pmde = pmd->entries[pmd_idx];
if (!fut_pte_is_present(pmde)) {
    return -EFAULT;
}

/* Check if this is a block descriptor (2MB page at L2) */
if (fut_pte_is_block(pmde)) {
    *pte_out = pmde;
    return 0;
}

/* L3 (PTE) walk - final level, read page descriptor */
uint64_t pte_phys = fut_pte_to_phys(pmde);
page_table_t *pte_table = pmap_table_from_phys(pte_phys);
pte_t pte_entry = pte_table->entries[pte_idx];
if (!fut_pte_is_present(pte_entry)) {
    return -EFAULT;
}

/* L3 is the final level - this is the page descriptor */
*pte_out = pte_entry;
return 0;
```

**Result**: `exec_copy_to_user()` now succeeds! ELF segments load correctly.

---

## Testing Results

### Before Fixes:
```
[MAP-SEG-ARM64] Page 0: vaddr=0x400000 phys=0x4181a000 prot=7
[MAP-SEG-ARM64] Successfully mapped 3 pages
[MAP-SEG-ARM64] Copying data to user space at 0x400000
[MAP-SEG-ARM64] ERROR: exec_copy_to_user failed  ← Bug 2
```

QEMU interrupt log:
```
Taking exception 3 [Prefetch Abort] on CPU 0
...from EL0 to EL1
...with ESR 0x82000006  ← Translation fault level 2
...with FAR 0x400000
```

### After Fixes:
```
[MAP-SEG-ARM64] Page 0: vaddr=0x400000 phys=0x4181a000 prot=7
[MAP-SEG-ARM64] Successfully mapped 3 pages
[MAP-SEG-ARM64] Copying data to user space at 0x400000
[MAP-SEG-ARM64] Segment load complete  ← Bug 2 FIXED!
[EXEC-ARM64] About to create thread
[USER-TRAMPOLINE-ARM64] ENTERED!
[USER-TRAMPOLINE-ARM64] entry=0x400000 sp=0x7fffffffdfd0
[TRAMPOLINE] Entry first instruction: 0x94000140
[TRAMPOLINE] About to ERET to EL0
```

No more translation faults! ✅

---

---

## Bug 3: Virtual Address Used as Physical in TTBR0 (kernel/exec/elf64.c:1335)

**Problem**: TTBR0_EL1 was being loaded with a virtual address instead of a physical address.

**Symptoms**:
- ERET instruction executed but didn't transition to EL0
- "Undefined Instruction" exceptions from EL1 to EL1
- SPSR showed 0x3c5 (EL1h mode) instead of 0x3c0 (EL0t mode)

**Root Cause**:
```c
/* BEFORE (BUGGY) - line 1335 */
uint64_t pgd_phys = (uint64_t)mm->ctx.pgd;  // Treats virtual address as physical!
```

TTBR0_EL1 requires a physical address, but `mm->ctx.pgd` is a `page_table_t *` pointer (virtual address). Casting it directly to `uint64_t` doesn't convert it to physical.

**Fix**:
```c
/* AFTER (FIXED) - line 1335 */
uint64_t pgd_phys = pmap_virt_to_phys((uintptr_t)mm->ctx.pgd);
```

Used `pmap_virt_to_phys()` static inline function from `<platform/arm64/memory/pmap.h>` to properly convert the virtual address to physical.

**Result**: Fix applied and kernel rebuilt successfully.

---

## Remaining Issue

After fixing Bug 3, the system now executes ERET but still encounters "Undefined Instruction" exceptions:

```
Taking exception 1 [Undefined Instruction] on CPU 0
...from EL1 to EL1
...with ESR 0x0/0x2000000
...with SPSR 0x3c5
...with ELR 0x40000f94
```

**Analysis**:
- Exceptions are "from EL1 to EL1" (not from EL0)
- SPSR is 0x3c5 (EL1h mode) instead of expected 0x3c0 (EL0t mode)
- ELR 0x40000f94 is in the exception handler itself
- Suggests ERET is not successfully transitioning to EL0

**Next Steps**: Investigate ERET transition code and SPSR setup.

---

## Files Modified

1. **kernel/mm/arm64_paging.c** (line 321):
   - Added `| PTE_TABLE` to set bits [1:0] = 0b11 for L3 page descriptors
   - Added comment explaining ARM64 descriptor format requirement

2. **platform/arm64/memory/pmap.c** (lines 112-162):
   - Removed non-existent L4 page table walk
   - Fixed to use 3-level hierarchy for 39-bit VA space
   - Made L3 the final level (page descriptors, not table pointers)
   - Removed PAGE_INDEX() usage
   - Added detailed comments explaining ARM64 3-level paging structure

3. **kernel/exec/elf64.c** (line 1335):
   - Changed `(uint64_t)mm->ctx.pgd` to `pmap_virt_to_phys((uintptr_t)mm->ctx.pgd)`
   - Properly converts virtual address to physical address for TTBR0_EL1

---

## References

- Previous session: `docs/SESSION_2025_11_06_PAGE_TABLE_FIX.md`
- ARM Architecture Reference Manual D5.3 (VMSAv8-64 translation table format)
- TCR_EL1.T0SZ=25 → 39-bit VA space (512GB) → 3-level paging

---

## Build/Test Commands

```bash
# Build ARM64 kernel with fixes
make PLATFORM=arm64

# Test with QEMU
timeout 10 qemu-system-aarch64 -machine virt -cpu cortex-a72 -m 256 \
  -serial stdio -display none -kernel build/bin/futura_kernel.elf \
  -no-reboot -no-shutdown

# Test with interrupt logging
timeout 5 qemu-system-aarch64 -machine virt -cpu cortex-a72 -m 256 \
  -serial stdio -display none -kernel build/bin/futura_kernel.elf \
  -no-reboot -no-shutdown -d int
```
