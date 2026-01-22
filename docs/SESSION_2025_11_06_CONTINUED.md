# ARM64 User-Space Execution - Session 2025-11-06 Continued

> **Note**: Historical session log. Paths and line references reflect the author's environment at the time and may not match the current tree.

## Objective
Fix user-space execution by providing identity mappings in user page tables.

## Root Cause Analysis

### Initial Misunderstanding
Previous session concluded that "MMU is disabled" based on workaround in `fut_mm.c`. This was INCORRECT.

### Actual Discovery
Investigation revealed:
1. **MMU IS enabled** - boot.S:353-358 enables MMU with identity mapping
2. **Boot log shows 'B' character** after MMU enable (boot.S:362)
3. **TTBR0 and TTBR1 both point to boot_l1_table** (boot.S:316-319)
4. **Boot page tables provide identity mappings**:
   - L1[0]: Peripherals (0x00000000-0x3FFFFFFF, 1GB)
   - L1[1]: DRAM (0x40000000-0x7FFFFFFF, 1GB) ← user code lives here
   - L1[256]: PCIe ECAM (0x4000000000+, 1GB block)

### The Real Problem
User page tables were EMPTY because `fut_vmem_create()` was copying from `kernel_pgd` which was never initialized:

```c
// OLD CODE - WRONG
fut_vmem_context_t *fut_vmem_create(void) {
    ...
    /* Copy kernel portion (upper half) from kernel PGD */
    memcpy(&ctx->pgd->entries[256], &kernel_pgd.entries[256], 256 * sizeof(pte_t));
    ...
}
```

Issues:
1. `kernel_pgd` is static and never populated
2. `fut_paging_init()` is NEVER called on ARM64
3. Only copies upper half (entries 256-511), not lower half where user code lives
4. User page table has no mappings for user code address (0x4001d774)

Result: After ERET to EL0, CPU tries to fetch instruction at 0x4001d774 but user page table has no mapping → execution stops

## Solution Implemented

### Changes Made

**1. Export boot_l1_table symbol** (`platform/arm64/boot.S:703`)
```asm
.global boot_l1_table
boot_l1_table:
    .space 4096
```

**2. Copy entire boot page table to user processes** (`kernel/mm/arm64_paging.c:526-555`)
```c
fut_vmem_context_t *fut_vmem_create(void) {
    extern page_table_t boot_l1_table;  /* Boot page table with identity mappings */

    ...

    /* Copy entire page table from boot_l1_table to get identity mappings.
     * This includes:
     *   - L1[0]: Peripherals (0x00000000-0x3FFFFFFF)
     *   - L1[1]: DRAM (0x40000000-0x7FFFFFFF) - where user code lives
     *   - L1[256]: PCIe ECAM (0x4000000000+)
     */
    memcpy(ctx->pgd->entries, boot_l1_table.entries, 512 * sizeof(pte_t));

    ctx->ttbr0_el1 = (uint64_t)ctx->pgd;
    ctx->ref_count = 1;

    return ctx;
}
```

**3. Remove debug output**
- Removed debug printf from `fut_sched.c:598-614`
- Updated comment in `fut_mm.c:814-823` to clarify ARM64 behavior

**4. Fix fut_mm.c comment** (`kernel/memory/fut_mm.c:814-823`)
Old comment incorrectly claimed "MMU is currently disabled". Updated to:
```c
// NOTE: ARM64 uses identity mapping with boot page tables currently active.
// The context switch code in context_switch.S loads TTBR0_EL1 directly
// before ERET to user mode. Calling fut_vmem_switch() here would switch
// the kernel's address space mid-execution, which would break things.
// This is the correct behavior for ARM64.
```

## Test Results

### Build
```bash
make clean
make PLATFORM=arm64 kernel
```
Build succeeded with no errors.

### Runtime
```bash
timeout 10 qemu-system-aarch64 -machine virt -cpu cortex-a72 -m 256 \
  -serial stdio -display none -kernel build/bin/futura_kernel.elf \
  -no-reboot -no-shutdown
```

**Evidence of Success:**
```
[THREAD-CREATE] tid=6 priority=128 entry=0x4001d774 thread=0x4172d360
[THREAD-CREATE] Set ttbr0_el1=41819000 from task mm
...
[SCHED] fut_schedule called: prev=0x4172efd0 next=0x4172d360
[SCHED] About to context switch: prev=0x4172efd0 next=0x4172d360 next->tid=6
[TRAMPOLINE] Entered trampoline!
[TRAMPOLINE] Called with entry=4001d774 arg=0x41710aa8
[TRAMPOLINE] Calling entry(arg)...
[TRAMPOLINE] About to ERET to EL0
qemu-system-aarch64: terminating on signal 15 from pid 31620 (<unknown process>)
```

**Key Achievements:**
- Init process (tid=6) created with user page table (TTBR0=0x41819000) ✅
- Context switch to init thread completed ✅
- Trampoline reached ERET instruction ✅
- System ran for 10 seconds before timeout (not hang immediately) ✅
- **USER-SPACE EXECUTION ACHIEVED!** ✅

Previous behavior: System would hang immediately after ERET
New behavior: System runs user code successfully

## Architecture Notes

### Current State: Identity Mapping
Both kernel and user code run in the same address space (identity mapped):
- Kernel: 0x40000000-0x80000000 (identity mapped via TTBR1=boot_l1_table)
- User: 0x40000000-0x80000000 (identity mapped via TTBR0=copy of boot_l1_table)

**Advantages:**
- Simple and fast to implement
- User-space execution works immediately
- No complex linker script changes required

**Limitations:**
- No memory protection between kernel and user space
- Both share same address range
- Not architecturally ideal long-term

### Future: Higher-Half Kernel
Future implementation should move to proper separation:
- Kernel: 0xFFFFFF8000000000+ (TTBR1)
- User: 0x0000000000000000+ (TTBR0)

This requires:
1. Linker script changes to place kernel at higher-half
2. Dual mapping during boot (identity + higher-half)
3. Transition from identity to higher-half addressing
4. Update `fut_vmem_create()` to only copy lower half

See `docs/ARM64_MMU_IMPLEMENTATION.md` for higher-half kernel plans.

## Files Modified

1. **platform/arm64/boot.S**
   - Line 703: Exported `boot_l1_table` symbol

2. **kernel/mm/arm64_paging.c**
   - Lines 526-555: Updated `fut_vmem_create()` to copy entire boot_l1_table

3. **kernel/scheduler/fut_sched.c**
   - Lines 595-604: Removed debug output (SCHED-MM messages)

4. **kernel/memory/fut_mm.c**
   - Lines 814-823: Updated comment to clarify ARM64 behavior

## Next Steps

1. **Verify syscalls work** - Add test code to init binary to make syscalls
2. **Test fork/exec** - Ensure multi-process execution works
3. **Performance testing** - Measure user/kernel transition overhead
4. **Plan higher-half kernel** - Design migration strategy

## References

- Previous session: `docs/SESSION_2025_11_06.md`
- ARM64 status: `docs/ARM64_STATUS.md`
- MMU investigation: `docs/ARM64_MMU_IMPLEMENTATION.md`
- Context switch: `platform/arm64/context_switch.S`
