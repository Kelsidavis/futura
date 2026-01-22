# ARM64 Exception Handling Bug - Session 2025-11-06

> **Note**: Historical session log. Paths and line references reflect the author's environment at the time and may not match the current tree.

## Problem Summary

User-space syscalls don't work because the kernel crashes with Prefetch Abort exceptions in an infinite loop **BEFORE** reaching user mode.

## Root Cause

### Exception Vector Translation Failure

QEMU debug output shows:
```
Taking exception 3 [Prefetch Abort] on CPU 0
...from EL1 to EL1
...with ESR 0x86000005
...with FAR 0x4006d200
...with ELR 0x4006d200
```

**Analysis:**
- ESR 0x86000005 = EC:0x21 (Instruction Abort from same EL) + FSC:0x05 (Translation fault level 1)
- FAR 0x4006d200 = Exception vector address (arm64_exception_vectors + 0x200)
- Exception vectors at 0x4006d000 (verified via `nm`)
- Offset 0x200 = "Synchronous exception from current EL with SPx"

### Address Translation Issue

**TCR_EL1 Configuration** (boot.S:298-302):
- T0SZ = 25: TTBR0 range = 0x0000000000000000 - 0x0000007FFFFFFFFF (lower 2GB)
- T1SZ = 25: TTBR1 range = 0xFFFFFF8000000000 - 0xFFFFFFFFFFFFFFFF (upper VA)

**Problem**:
- Kernel code at 0x40000000-0x4006d000+ is in **TTBR0 range** (lower 2GB)
- Exception vectors at 0x4006d000 are accessed via TTBR0
- After context switch loads TTBR0 with user page table, exceptions fail to translate

### Why User Page Tables Don't Work

**Current Code** (kernel/mm/arm64_paging.c:556):
```c
fut_vmem_context_t *fut_vmem_create(void) {
    extern page_table_t boot_l1_table;
    ...
    /* Copy entire page table from boot_l1_table */
    memcpy(ctx->pgd->entries, boot_l1_table.entries, 512 * sizeof(pte_t));
    ...
}
```

We copy boot_l1_table to user page tables, which SHOULD include mappings for:
- L1[0]: Peripherals (0x00000000-0x3FFFFFFF)
- L1[1]: DRAM (0x40000000-0x7FFFFFFF) ← Kernel code here!
- L1[256]: PCIe ECAM (0x4000000000+)

**But translation still fails!**

Possible reasons:
1. Page table entries not properly marked as valid
2. Wrong permissions (Execute-Never set?)
3. Cache/TLB coherency issue
4. Page table allocation issue

## Timeline of Events

1. **Kernel boots successfully** with MMU enabled, using boot_l1_table for both TTBR0 and TTBR1
2. **Init process spawned** (tid=6), user page table allocated at 0x41819000
3. **Context switch** loads TTBR0 = 0x41819000 (user page table)
4. **Scheduler tries to context switch** to another thread
5. **Timer/exception occurs** while in kernel mode
6. **CPU tries to fetch exception vector** at 0x4006d200
7. **Translation fails** because TTBR0 (user PT) doesn't have valid mapping
8. **Recursive exception loop** - every exception causes another exception

## Evidence

### Kernel Build Output
```
$ aarch64-elf-nm build/bin/futura_kernel.elf | grep exception_vectors
0000000040000800 T exception_vectors          (boot vector table)
000000004006d000 T arm64_exception_vectors    (runtime vector table)
```

### Boot Process
```
[ARM64-SPAWNER] Executing /sbin/init...
[MM-CREATE] ARM64: PGD allocated successfully at 0x41819000
[THREAD-CREATE] tid=6 priority=128 entry=0x4001d738
[THREAD-CREATE] Set ttbr0_el1=41819000 from task mm
[TRAMPOLINE] About to ERET to EL0
<system hangs - infinite exception loop>
```

### QEMU Debug Output
Infinite loop of:
```
Taking exception 3 [Prefetch Abort]
...from EL1 to EL1
...with FAR 0x4006d200
```

## Solution Options

### Option 1: Move Kernel to Higher-Half (Proper Solution)
Move kernel to 0xFFFFFF8000000000+ range (TTBR1):
- Requires linker script changes
- Dual mapping during boot
- Transition from identity to higher-half
- User page tables only need TTBR0 (no kernel mappings)

### Option 2: Keep Boot Exception Vectors (Quick Fix)
Don't call `arm64_install_exception_vectors()`:
- Keep using boot exception vectors at 0x40000800
- These are always accessible via boot_l1_table
- Avoids the TTBR0/TTBR1 split issue
- **Downside**: Boot vectors might be simpler/less featured

### Option 3: Fix Page Table Copy (Investigate First)
Debug why copied boot_l1_table entries don't work:
- Check entry validity bits
- Check permissions (AF, XN, AP bits)
- Add debug output in fut_vmem_create()
- Verify TLB invalidation

## Next Steps

1. Try Option 2 (quick fix) to unblock syscall testing
2. Add debug output to dump page table entries
3. Investigate why copied entries don't translate
4. Plan higher-half kernel migration (long-term)

## Files Modified (This Session)

1. **platform/arm64/interrupt/arm64_exceptions.c**:
   - Added debug output to `arm64_exception_dispatch()` (line 38)
   - Added debug output to `arm64_svc_handler()` (line 103)

## References

- ARM64 MMU Investigation: `docs/ARM64_MMU_IMPLEMENTATION.md`
- Previous user-space session: `docs/SESSION_2025_11_06_CONTINUED.md`
- ARM64 Exception Handling: ARM Architecture Reference Manual D1.10
- TCR_EL1 Register: ARM DDI 0487 D13.2.120
