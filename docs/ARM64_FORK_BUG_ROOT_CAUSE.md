# ARM64 Fork Bug: Root Cause Analysis

**Date**: 2025-11-14
**Status**: Root cause identified, fix pending

## Summary

Fork crashes on ARM64 due to **unmapping the kernel during context switch**. The kernel runs at low VA (0x40000000) mapped via TTBR0_EL1, but context switching changes TTBR0_EL1 to the child's page table, which doesn't include kernel mappings. The subsequent `eret` instruction faults.

## Investigation Timeline

### Initial Symptoms
- Child process created by `fork()` crashes immediately with "Unknown exception"
- Exception PC: 0x402781f4 (corrupted)
- Expected PC: 0x400170 (userspace return address)
- ESR: 0x02000000

### Initial Hypothesis (WRONG)
We initially suspected:
- Cache coherency issues
- Wrong offset in context structure
- PC/LR confusion
- Base pointer corruption

### Breakthrough: Checkpoint Debugging
Added checkpoints to track ELR_EL1 through context switch:
```
[CHECKPOINT-A] ELR_EL1=0x400170  ✓ After SPSR/SP_EL0 set
[CHECKPOINT-B] ELR_EL1=0x400170  ✓ After callee-saved restore
[CHECKPOINT-C] ELR_EL1=0x400170  ✓ Before page table switch
[CHECKPOINT-D] ELR_EL1=0x400170  ✓ After page table switch
[PRE-ERET]     ELR_EL1=0x400170  ✓ Right before eret
[EXCEPTION]    ELR_EL1=0x402781f4  ✗ When exception taken!
```

**Key finding**: ELR_EL1 is correct until the `eret` itself faults!

### Root Cause Discovery

#### The Setup (boot.S:317-318)
```assembly
adrp    x0, boot_l1_table
add     x0, x0, :lo12:boot_l1_table
msr     ttbr1_el1, x0        # Both TTBRs point to
msr     ttbr0_el1, x0        # the same table!
```

**Problem**: Kernel is linked at **0x40000000** (low VA), so it executes via **TTBR0_EL1** mappings.

#### The Context Switch (context_switch.S)
```assembly
ldr     x2, [sp], #16             # Pop TTBR0 value into x2
msr     ttbr0_el1, x2             # Switch to child's page table!
isb                               # Instruction synchronization barrier
...
eret                              # Tries to fetch from unmapped kernel!
```

**What happens**:
1. Before `msr ttbr0_el1`: Kernel at 0x4007xxxx is mapped via TTBR0 (boot_l1_table)
2. After `msr ttbr0_el1`: TTBR0 now points to **child's page table**
3. After `isb`: TLB flushed, kernel code at 0x4007xxxx **no longer mapped**
4. CPU tries to fetch `eret` instruction → **translation fault**
5. Exception handler tries to read faulting PC → gets corrupted value

#### The Corruption
The PC corruption (+0x02000000 == ESR value) is a secondary artifact of the fault mechanism. The primary bug is simply: **we unmapped the kernel from under ourselves**.

## ARM64 TTBR Architecture

### Canonical Design (what we need)
```
TTBR1_EL1 → Kernel mappings (high VA: 0xFFFF000000000000+)
            ├── Kernel code, data, page tables
            ├── Exception vectors
            └── Always accessible regardless of TTBR0

TTBR0_EL1 → User mappings (low VA: 0x0000000000000000+)
            ├── User code, data, heap, stack
            └── Changed on every context switch
```

### What We Currently Have (broken)
```
TTBR1_EL1 → boot_l1_table (unused for actual execution)
TTBR0_EL1 → boot_l1_table (maps kernel at 0x40000000)
            ├── Kernel thinks it can switch TTBR0 per-process
            └── But kernel code is IN TTBR0, so switching unmaps it!
```

### Alternative (not recommended)
You *could* keep kernel at low VA in TTBR0, but then:
- Every process's TTBR0 page table must replicate all kernel mappings
- More memory usage, more complexity, more error-prone
- Defeats the purpose of having two TTBRs

## The Fix

### Required Changes

#### 1. Change Kernel Link Address
**File**: `platform/arm64/linker.ld` (or equivalent)
```
OLD: . = 0x40000000;
NEW: . = 0xFFFF000040000000;
```

#### 2. Update Boot Page Tables
**File**: `platform/arm64/boot.S`
- Create `kernel_l1_table` for TTBR1 mapping high VA
- Create `user_l1_table` for TTBR0 (initially empty or bootstrap)
- Set TTBR1 = kernel_l1_table
- Set TTBR0 = user_l1_table (or 0)

#### 3. Update Exception Vectors
**File**: `platform/arm64/arm64_vectors.S`
- Ensure exception vector table is in high-half kernel VA
- VBAR_EL1 must point to high VA address
- Handlers must be reachable via TTBR1

#### 4. Fix Context Switch
**File**: `platform/arm64/context_switch.S`
```assembly
# OLD (changes TTBR0, unmaps kernel):
msr     ttbr0_el1, x2

# NEW (only changes TTBR0, TTBR1 stays constant):
msr     ttbr0_el1, x2     # Switch user mappings only
# TTBR1_EL1 never changes after boot
```

#### 5. Update Exception Entry
**File**: `platform/arm64/arm64_exception_entry.S`
```assembly
# OLD (switches TTBR0 to kernel table):
adrp    x1, boot_l1_table
msr     ttbr0_el1, x1

# NEW (TTBR0 stays as-is for user, TTBR1 already has kernel):
# No TTBR switch needed! Kernel is always mapped via TTBR1
```

#### 6. Update User Process Creation
**Files**: `kernel/sys_fork.c`, `kernel/sys_execve.c`, `platform/arm64/memory/pmap.c`
- Allocate L1 table for each process (TTBR0)
- Map user code/data/stack in low VA (0x0000...)
- DO NOT map kernel - it's in TTBR1
- Store process's TTBR0 value in thread->context.ttbr0_el1

### VA Layout After Fix
```
0xFFFF000040000000 - 0xFFFF000048000000: Kernel code/data (TTBR1)
0xFFFF000048000000 - 0xFFFFFFFFFFFFFFFF: Kernel heap, stacks (TTBR1)

0x0000000000000000 - 0x0000000000400000: NULL guard page
0x0000000000400000 - 0x0000000000500000: User .text (TTBR0)
0x0000000000500000 - 0x0000000000600000: User .data/.bss (TTBR0)
0x0000007FFF000000 - 0x0000008000000000: User stack (TTBR0)
```

## Testing the Fix

### Verification Steps
1. Boot kernel (should reach console)
2. Verify kernel running at high VA:
   ```
   Kernel addresses should be 0xFFFF000040xxxxxx
   ```
3. Create first userspace process (should spawn)
4. Test fork():
   ```
   fork() should return child PID to parent, 0 to child
   Child should execute correctly without crashing
   ```

### Success Criteria
- ✅ Fork completes without exception
- ✅ Child process executes user code
- ✅ Parent and child have separate address spaces
- ✅ Context switches work without unmapping kernel

## Lessons Learned

1. **Read the architecture manual carefully**: ARM64's TTBR0/TTBR1 split is designed for exactly this use case
2. **"It worked on x86" doesn't mean the design is portable**: x86 has a single CR3, ARM64 has two TTBRs
3. **Debug with checkpoints, not assumptions**: Our initial theories about cache/offsets were completely wrong
4. **Trust the evidence**: When ELR_EL1 is correct until the eret itself, the problem is in the eret
5. **Memory management is architecture-specific**: What works on one ISA may violate fundamental assumptions on another

## References
- ARM Architecture Reference Manual ARMv8, Section D5.2 (MMU)
- ARM Cortex-A Series Programmer's Guide, Chapter 12 (Memory Management)
- Linux kernel ARM64 implementation: `arch/arm64/mm/proc.S` (TTBR handling)
