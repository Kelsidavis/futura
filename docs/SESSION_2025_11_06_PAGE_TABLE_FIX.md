# ARM64 Page Table Bug - Session 2025-11-06

> **Note**: Historical session log. Paths and line references reflect the author's environment at the time and may not match the current tree.

## Problem Summary

User-space syscalls don't work because the kernel crashes with Prefetch Abort exceptions **before** reaching user mode. The system fails immediately after context switch loads TTBR0 with user page tables.

## Root Cause

**User page tables were completely empty** because `fut_mm_create()` on ARM64 doesn't populate them properly.

### Code Flow Analysis

1. `fut_mm_create()` (kernel/memory/fut_mm.c:747-762) allocates a PGD page
2. Calls `copy_kernel_half(pgd)` to populate it
3. **BUG**: ARM64's `copy_kernel_half()` (line 718-723) is a **no-op**:

```c
static void copy_kernel_half(page_table_t *dst) {
    /* ARM64: No-op for identity mapping.
     * In identity mapping, kernel and user share the same lower-half address space.
     * There is no higher-half kernel mapping to copy. */
    (void)dst;  /* DOES NOTHING! */
}
```

4. Result: Empty page table with **zero valid entries**
5. When `context_switch.S` loads TTBR0 with the empty page table, **nothing translates**
6. CPU tries to fetch next instruction → Translation fault → Prefetch Abort
7. CPU tries to fetch exception vector → Translation fault → Recursive exception loop

### Why User Page Tables Must Include Kernel Mappings

On ARM64 with identity mapping:
- **Kernel code** lives at 0x40000000-0x4FFFFFFF (DRAM)
- **Exception vectors** live at 0x40000800 (boot vectors) or 0x4006d000 (runtime vectors)
- **Both are in TTBR0 range** (lower 2GB: 0x0-0x7FFFFFFF)

After context switch:
- TTBR0 → User page table (for user VA translation)
- TTBR1 → Boot page table (unused with identity mapping)

**Problem**: When an exception occurs (syscall, timer, page fault), the CPU tries to fetch the exception handler. The handler address (0x4006d000) is in TTBR0 range, but the user page table is empty, so translation fails.

## The Fix

Updated `copy_kernel_half()` in `kernel/memory/fut_mm.c` (lines 718-745) to copy `boot_l1_table` entries to user page tables:

```c
static void copy_kernel_half(page_table_t *dst) {
    extern void fut_printf(const char *, ...);
    extern page_table_t boot_l1_table;  /* From boot.S */

    /* ARM64: Copy boot L1 table to user page tables.
     * User processes need access to kernel code, exception vectors,
     * and peripherals that live in the lower 2GB (TTBR0 range).
     */

    fut_printf("[COPY-KERNEL] Copying boot_l1_table from %p to %p\n",
               (void*)&boot_l1_table, (void*)dst);

    /* Copy all 512 entries from boot L1 table */
    for (size_t i = 0; i < 512; i++) {
        dst->entries[i] = boot_l1_table.entries[i];
    }

    /* Debug: Verify critical mappings were copied */
    fut_printf("[COPY-KERNEL] L1[0] = 0x%llx (peripherals)\n",
               (unsigned long long)dst->entries[0]);
    fut_printf("[COPY-KERNEL] L1[1] = 0x%llx (DRAM - kernel/vectors)\n",
               (unsigned long long)dst->entries[1]);
    fut_printf("[COPY-KERNEL] L1[256] = 0x%llx (PCIe ECAM)\n",
               (unsigned long long)dst->entries[256]);
}
```

### What Gets Copied

- **L1[0]**: Peripherals (0x00000000-0x3FFFFFFF) - UART, GIC, etc.
- **L1[1]**: DRAM (0x40000000-0x7FFFFFFF) - **Kernel code & exception vectors**
- **L1[256]**: PCIe ECAM (0x4000000000+) - PCI configuration space

## Why Previous Fix Didn't Work

The previous session (SESSION_2025_11_06_CONTINUED.md) documented updating `fut_vmem_create()` in `kernel/mm/arm64_paging.c` to copy `boot_l1_table`.

**But ARM64 doesn't call `fut_vmem_create()`!**

- x86-64 uses `fut_vmem_create()` to allocate page tables
- ARM64 has its own implementation directly in `fut_mm_create()` (line 747)
- The x86-64/ARM64 split happens via `#ifdef __aarch64__` at line 651
- ARM64's `copy_kernel_half()` was a no-op, so the fix to `fut_vmem_create()` was never executed

## Expected Behavior After Fix

With the fix, user page tables will have valid mappings for:
1. **User code** at 0x4001d000+ (via L1[1] DRAM mapping)
2. **Kernel code** at 0x40000000-0x4FFFFFFF (via L1[1])
3. **Exception vectors** at 0x40000800 or 0x4006d000 (via L1[1])
4. **Peripherals** at 0x00000000-0x3FFFFFFF (via L1[0])

When an exception occurs:
1. CPU saves context, switches to EL1
2. CPU fetches exception vector from 0x40000a00 (boot vectors)
3. **Translation succeeds** because L1[1] maps 0x40000000-0x7FFFFFFF
4. Exception handler executes
5. Syscall dispatcher is invoked
6. ERET returns to user mode

## Testing

To verify the fix works:
1. Build kernel with updated `copy_kernel_half()`
2. Run init process which attempts `sys_write(1, "Hello", 5)` syscall
3. Expected output: `[COPY-KERNEL]` debug messages showing L1 entries
4. Expected output: `[INIT-USER] Hello from user mode! Syscalls work!`
5. No Prefetch Aborts, no infinite exception loop

## Long-Term Solution

The current fix works but isn't ideal - user processes can access kernel memory because they share the same page table entries.

**Proper solution**: Move kernel to higher-half (0xFFFFFF8000000000+)
- Kernel uses TTBR1 range (upper VA space)
- User uses TTBR0 range (lower VA space)
- User page tables DON'T need kernel mappings
- Memory protection between kernel and user space
- Requires linker script changes and boot-time dual mapping

See `docs/ARM64_MMU_IMPLEMENTATION.md` for higher-half kernel plans.

## Files Modified

1. **kernel/memory/fut_mm.c** (lines 718-745):
   - Updated `copy_kernel_half()` to copy boot_l1_table entries
   - Added debug output to verify mappings

2. **kernel/mm/arm64_paging.c** (lines 526-575):
   - Previous session added debug output to `fut_vmem_create()`
   - **This function is NOT called on ARM64** - can remove debug output

## References

- Previous session: `docs/SESSION_2025_11_06_EXCEPTION_BUG.md`
- User-space session: `docs/SESSION_2025_11_06_CONTINUED.md`
- ARM64 MMU plans: `docs/ARM64_MMU_IMPLEMENTATION.md`
- Exception handling: `platform/arm64/interrupt/arm64_exceptions.c`
- Context switch: `platform/arm64/context_switch.S`
