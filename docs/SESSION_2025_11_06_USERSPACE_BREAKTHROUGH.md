# ARM64 User-Space Execution Breakthrough - Session 2025-11-06

## Summary

**MAJOR MILESTONE ACHIEVED**: ARM64 kernel successfully transitions to EL0 (user mode) and executes user-space code! 🎉

Fixed **three critical bugs** that were preventing user-space execution:
1. **Bug #4**: Wrong page table index macros (48-bit VA instead of 39-bit VA)
2. **Bug #5**: Missing instruction cache maintenance
3. **Bug #6**: TTBR0_EL1 never loaded with user page tables

## Bug #4: Page Table Index Macros for Wrong VA Size

### Problem

Page table index extraction macros were using bit positions for 48-bit VA (4-level paging), but the system uses T0SZ=25 which gives 39-bit VA space (3-level paging).

**Symptoms**:
- `exec_copy_to_user()` wrote code to WRONG physical page
- Debug showed: vaddr 0x400000 should map to phys 0x4181a000 (Page 0)
- But `pmap_probe_pte()` returned PTE with phys 0x4181e000 (Page 2!)

**Root Cause**:

TWO header files had wrong macros:
- `include/arch/arm64/paging.h`
- `include/platform/arm64/memory/paging.h`

```c
/* BEFORE (WRONG - for 48-bit VA, 4-level paging) */
#define PGD_INDEX(vaddr)    (((vaddr) >> 39) & 0x1FF)   /* Level 0 */
#define PMD_INDEX(vaddr)    (((vaddr) >> 30) & 0x1FF)   /* Level 1 */
#define PTE_INDEX(vaddr)    (((vaddr) >> 21) & 0x1FF)   /* Level 2 */
#define PAGE_INDEX(vaddr)   (((vaddr) >> 12) & 0x1FF)   /* Level 3 */
```

ARM64 with T0SZ=25 (39-bit VA) uses **3-level** paging:
- **L1 (PGD)**: bits [38:30] → 512 entries × 1GB = 512GB range
- **L2 (PMD)**: bits [29:21] → 512 entries × 2MB = 1GB range
- **L3 (PTE)**: bits [20:12] → 512 entries × 4KB = 2MB range (FINAL LEVEL)
- **Offset**: bits [11:0] → 4KB page offset

### Fix

```c
/* AFTER (FIXED - for 39-bit VA, 3-level paging) */
#define PGD_INDEX(vaddr)    (((vaddr) >> 30) & 0x1FF)   /* L1: bits [38:30] */
#define PMD_INDEX(vaddr)    (((vaddr) >> 21) & 0x1FF)   /* L2: bits [29:21] */
#define PTE_INDEX(vaddr)    (((vaddr) >> 12) & 0x1FF)   /* L3: bits [20:12] (FINAL) */
#define PAGE_INDEX(vaddr)   (((vaddr) >> 12) & 0x1FF)   /* Same as PTE for 3-level */
```

### Result

✅ `exec_copy_to_user()` now writes to **CORRECT** page:
```
[COPY-TO-USER] First probe: vaddr=0x400000 pte=0x2000004181a753 phys=0x4181a000
[COPY-DEBUG] After memcpy: phys=0x4181a000 first_4bytes=0xd280001d
```

Code is now at phys 0x4181a000 (Page 0), not 0x4181e000 (Page 2)!

---

## Bug #5: Missing Instruction Cache Maintenance

### Problem

ARM64 has separate instruction and data caches. After writing code via data cache (`memcpy`), the instruction cache still had stale/uninitialized data.

**Symptoms**:
- Kernel could read correct instruction (0xd280001d) from memory
- But trampoline code reading entry point saw wrong value (0x94000140)

**Root Cause**:

No cache maintenance after writing user code pages.

### Fix

Added ARM64 cache synchronization after `memcpy` in `kernel/exec/elf64.c`:

```c
/* ARM64: Clean data cache and invalidate instruction cache for code pages */
uint8_t *kern_start = (uint8_t *)virt;
uint8_t *kern_end = kern_start + chunk_size;

/* DC CVAU - Clean data cache to point of unification */
for (uint8_t *addr = kern_start; addr < kern_end; addr += 64) {
    __asm__ volatile("dc cvau, %0" :: "r"(addr) : "memory");
}
__asm__ volatile("dsb ish" ::: "memory");  /* Ensure DC completes */

/* IC IVAU - Invalidate instruction cache */
for (uint8_t *addr = kern_start; addr < kern_end; addr += 64) {
    __asm__ volatile("ic ivau, %0" :: "r"(addr) : "memory");
}
__asm__ volatile("dsb ish" ::: "memory");  /* Ensure IC completes */
__asm__ volatile("isb" ::: "memory");      /* Synchronize pipeline */
```

### Result

✅ Correct instruction (0xd280001d = `mov x29, #0`) is now read from entry point!

---

## Bug #6: TTBR0_EL1 Never Loaded with User Page Tables

### Problem

The code to switch TTBR0_EL1 to the user page table was **commented out** as a "temporary" measure!

**Symptoms**:
- User pages were correctly mapped in user PGD at phys 0x41819000
- But ERET still used boot page tables (which don't have vaddr 0x400000 mapped)
- Result: "Undefined Instruction" exception when trying to fetch from 0x400000

**Root Cause**:

Lines 1445-1446 in `kernel/exec/elf64.c`:
```c
/* TEMPORARY: Skip TTBR0 switch for identity mapping */
/* TODO: Implement proper higher-half kernel to enable per-process page tables */
```

The assembly code before ERET had no TTBR0 switch!

### Fix

```c
__asm__ volatile(
    /* Set TTBR0_EL1 to user page table */
    "msr ttbr0_el1, %2\n\t"
    /* Invalidate TLB for TTBR0 changes */
    "tlbi vmalle1\n\t"
    "dsb ish\n\t"
    "isb\n\t"
    /* Set SP_EL0 (user mode stack pointer) */
    "msr sp_el0, %0\n\t"
    /* Set ELR_EL1 (return address for ERET) */
    "msr elr_el1, %1\n\t"
    /* Set SPSR_EL1 for EL0t mode */
    "mov x10, #0x3C0\n\t"
    "msr spsr_el1, x10\n\t"
    /* Synchronize before ERET */
    "isb\n\t"
    /* Return to user mode */
    "eret\n\t"
    :
    : "r"(sp), "r"(entry), "r"(pgd_phys)
    : "x10", "memory"
);
```

### Result

✅ **ERET SUCCEEDED! System transitions to EL0 and executes user code!**

QEMU interrupt log:
```
Exception return from AArch64 EL1 to AArch64 EL0 PC 0x400000
```

First user instruction (`mov x29, #0` at 0x400000) **executed successfully**!

---

## Current Status

### ✅ Working
1. ELF loading and parsing
2. User page table creation (3-level, 39-bit VA)
3. Page mapping with correct indices
4. Cache maintenance (DC CVAU + IC IVAU)
5. TTBR0_EL1 switching
6. ERET transition from EL1 to EL0
7. **First user instruction executes!**

### ❌ Next Issue

Data Abort when second instruction tries to access stack:

```
Taking exception 4 [Data Abort] on CPU 0
...from EL0 to EL1
...with ESR 0x24/0x92000004
...with FAR 0x7fffffffdfd0  ← Stack pointer
...with ELR 0x400004        ← Second instruction
```

The instruction sequence:
```asm
400000:  d280001d   mov  x29, #0x0           ← Executed successfully!
400004:  f84087e0   ldr  x0, [sp], #8        ← Data Abort (stack not mapped)
```

**Cause**: We mapped code pages (0x400000-0x402fff) but didn't map the stack page at 0x7fffffffdfd0.

---

## Files Modified

1. **include/arch/arm64/paging.h** (lines 126-136)
   - Fixed page table index macros for 39-bit VA

2. **include/platform/arm64/memory/paging.h** (lines 126-136)
   - Fixed page table index macros for 39-bit VA

3. **kernel/exec/elf64.c** (lines ~1270)
   - Added DC CVAU + IC IVAU cache maintenance after memcpy

4. **kernel/exec/elf64.c** (lines 1435-1458)
   - Added TTBR0_EL1 switch before ERET
   - Added TLB invalidation (tlbi vmalle1)

5. **platform/arm64/exception_handlers.c** (lines 36-46, 174-218)
   - Added EC codes for WFX_TRAP and ILL_STATE
   - Added better exception logging with instruction decoding

---

## Testing Results

### Before Fixes

```
[MAP-SEG-ARM64] Page 0: vaddr=0x400000 phys=0x4181a000
[COPY-TO-USER] First probe: phys=0x4181e000  ← WRONG PAGE!
[TRAMPOLINE] Entry first instruction: 0x94000140  ← WRONG INSTRUCTION!
[TRAMPOLINE] About to ERET to EL0
[EXCEPTION] EC=0x00 (Unknown/Undefined)
```

### After Bug #4 Fix

```
[MAP-SEG-ARM64] Page 0: vaddr=0x400000 phys=0x4181a000
[COPY-TO-USER] First probe: phys=0x4181a000  ← CORRECT PAGE!
[COPY-DEBUG] first_4bytes=0xd280001d  ← CORRECT INSTRUCTION!
```

### After Bug #5 Fix

```
[TRAMPOLINE] Entry first instruction: 0xd280001d  ← Kernel sees correct instruction!
```

### After Bug #6 Fix (BREAKTHROUGH!)

```
[TRAMPOLINE] About to ERET to EL0
```

QEMU logs:
```
Exception return from AArch64 EL1 to AArch64 EL0 PC 0x400000
```

**User code is running in EL0!** ✅

Then:
```
Taking exception 4 [Data Abort] on CPU 0
...from EL0 to EL1
...with FAR 0x7fffffffdfd0  ← Stack not mapped
```

---

## Lessons Learned

1. **Check ALL header files**: We had duplicate macros in two files, both needed fixing

2. **ARM64 cache architecture**: Separate I/D caches require explicit synchronization:
   - DC CVAU for data
   - IC IVAU for instructions
   - DSB + ISB for ordering

3. **Identity mapping ≠ Shared page tables**: Even with identity mapping (virt == phys for kernel), user processes need their own page tables in TTBR0_EL1

4. **Page table levels vs VA size**:
   - 48-bit VA → 4 levels (0, 1, 2, 3)
   - 39-bit VA → 3 levels (1, 2, 3)
   - Index extraction must match!

5. **TODO comments can hide critical bugs**: The "TEMPORARY" TTBR0 skip had been there since initial implementation

---

## Next Steps

1. **Map user stack**: Need to map the page at 0x7fffffffdfd0
2. **Verify stack setup**: Ensure argc, argv, envp are correctly placed
3. **Test full init execution**: Let init process run to completion
4. **Add syscall handling**: Test SVC instruction from EL0
5. **Multi-process testing**: Fork, exec, waitpid with proper page table isolation

---

## References

- Previous sessions:
  - `docs/SESSION_2025_11_05.md` - Initial ARM64 driver work
  - `docs/SESSION_2025_11_06_PAGE_TABLE_FIX.md` - Fixed L3 page descriptor type
  - `docs/SESSION_2025_11_07_PAGE_TABLE_FIXES.md` - Fixed 3-level hierarchy

- ARM Architecture Reference Manual:
  - D5.3 VMSAv8-64 translation table format
  - D4.2.8 Translation granule sizes
  - B2.2.4 Cache maintenance operations

- TCR_EL1 configuration:
  - T0SZ=25 → 39-bit VA for TTBR0_EL1
  - TG0=00 → 4KB granule
  - 3-level page table walk

---

## Build/Test Commands

```bash
# Build ARM64 kernel
make PLATFORM=arm64 clean
make PLATFORM=arm64

# Test with basic run
timeout 10 qemu-system-aarch64 -machine virt -cpu cortex-a72 -m 256 \
  -serial stdio -display none -kernel build/bin/futura_kernel.elf \
  -no-reboot -no-shutdown

# Test with interrupt logging (see exceptions)
timeout 5 qemu-system-aarch64 -machine virt -cpu cortex-a72 -m 256 \
  -serial stdio -display none -kernel build/bin/futura_kernel.elf \
  -no-reboot -no-shutdown -d int 2>&1 | grep -A10 "About to ERET"
```

---

**Session Date**: November 6, 2025
**Duration**: Extended debugging session
**Commits**:
- 5b3ddff: ARM64: Fix page table index macros for 39-bit VA and add cache maintenance
- 49bac45: ARM64: Enable TTBR0 switch for user page tables - ERET to EL0 SUCCESS!
