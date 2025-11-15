# ARM64 Fork X7 Register Corruption Mystery

## Status
**UNRESOLVED** - Extensive investigation conducted, critical exception handler bugs fixed, root cause still unknown

## Problem Description
After fork(), the child process executes with incorrect x7 register value (0x1 instead of expected 0x401308), causing immediate fault when attempting to access string literals.

## What Works
- ✅ TTBR0_EL1 correctly uses physical address (fixed in cbdade1)
- ✅ fork() correctly copies all registers from parent exception frame to child context
- ✅ Child context stored in memory contains correct x7=0x401308 (verified)
- ✅ Scheduler reads correct x7 value from child context before switch
- ✅ Context switch takes correct EL0/ERET path (verified with marker)
- ✅ Page tables (PTEs) created correctly for child process
- ✅ Parent process works correctly with x7=0x401308

## What Fails
- ❌ Child process executes with x7=0x1 instead of x7=0x401308
- ❌ Even hardcoding `mov x7, #0x401308` immediately before ERET doesn't work
- ❌ Child faults at PC=0x400190 when trying to use x7

## Investigation Summary
Systematic debugging revealed:

1. **Fork copies correctly**: `frame->x[7]=0x401308` → `child_thread->context.x7=0x401308`

2. **Memory contains correct value**: Verified at offset +56 in context structure

3. **Scheduler sees correct value**: `next->x7=0x401308` before calling fut_switch_context()

4. **Context switch loads correctly**: Added debug showing `ldr x7, [x1, #56]` loads 0x401308

5. **Hardcoded value still corrupted**: Even `movz x7, #0x4013, lsl #16; movk x7, #0x0308` before ERET results in child executing with x7=0x1

6. **Not a ldp bug**: Tried separate ldr instructions, stack-based restoration - all failed

7. **Correct path taken**: Debug marker confirms EL0/ERET path executes

8. **Correct PC**: Child starts at PC=0x400170 (syscall return address) as expected

## Evidence
- Child's first fault PC=0x400190 is AFTER initial entry point 0x400170
- Child executed instructions from 0x400170 to 0x400190 before faulting
- First use of x7 is at 0x40017c: `add x0, x7, #0x28`
- If x7=0x1, this computes garbage address → fault

- Parent's second fault has CORRECT x7=0x401308 (proving exception path works)
- Both processes use identical code paths, but child gets wrong x7

## Hypotheses Ruled Out
1. ❌ Context pointer wrong - offsets verified with offsetof()
2. ❌ Page tables corrupt - PTEs verified correct
3. ❌ Wrong restoration path - marker confirms EL0 path
4. ❌ ldp instruction bug - separate ldr doesn't help
5. ❌ Stack corruption - verified stack offsets
6. ❌ Register clobbering in assembly - hardcoded value still fails
7. ❌ Debug code interference - removed debug, issue persists

## Possible Causes (Unverified)
1. QEMU bug in ARM64 exception return emulation?
2. ARM64 architectural behavior in specific exception return scenarios?
3. Undocumented register restoration by ERET in certain states?
4. Memory ordering issue between context write and context read?
5. Cache coherency problem between fork() write and context switch read?

## Code Locations
- Fork implementation: `/Users/kelsi/futura/kernel/sys_fork.c:675-695`
- Context switch: `/Users/kelsi/futura/platform/arm64/context_switch.S:244`
- Scheduler: `/Users/kelsi/futura/kernel/scheduler/fut_sched.c:597-608`
- Test binary: `/Users/kelsi/futura/build/bin/arm64/user/forktest`

## Next Steps
1. Test on real ARM64 hardware (if available)
2. Use QEMU GDB stub to trace register values instruction-by-instruction
3. Review ARM ARM documentation for exception return edge cases
4. Check if other registers (x6, x4, x5) also corrupt or just x7
5. Try different QEMU versions or ARM64 CPU models
6. Consider filing QEMU bug report if hardware behaves differently

## Critical Bugs Fixed (November 14, 2025)
Following expert analysis, discovered and fixed severe bugs in asynchronous exception handlers:

### IRQ Handler Bug (arm64_vectors.S:274)
- **Before**: Saved only x0-x3, x29-x30
- **After**: Saves ALL caller-saved registers (x0-x18, x29-x30)
- **Impact**: `arm64_handle_irq()` C function could clobber x4-x18 per ARM64 ABI
- **Fix**: Complete register save/restore in `irq_exception_entry`

### SError Handler Bug (arm64_vectors.S:321)
- **Before**: Saved only x0-x1
- **After**: Saves ALL caller-saved registers (x0-x18, x29-x30)
- **Impact**: `arm64_handle_serror()` C function could clobber x2-x18
- **Fix**: Complete register save/restore in `serror_exception_entry`

These fixes were critical for system stability - ANY C function call from an exception handler can clobber caller-saved registers (x0-x18), so all async exception paths must preserve them.

### Additional Hardening
- Added interrupt masking (daifset) before ERET in context switch
- Added DSB/ISB memory barriers before ERET
- These did not resolve the fork issue but improve robustness

## Fork Issue Persists
Despite fixing the exception handlers, child process after fork() still executes with x7=0x1 instead of expected x7=0x401308. This suggests an even deeper issue - possibly QEMU-specific or undiscovered architectural edge case.

## Workaround
None currently available. Fork cannot work on ARM64 until this is resolved.

## Sessions
- November 14, 2025: Initial investigation, TTBR0 fix, PTE verification
- November 14, 2025 (evening): Exception handler investigation and fixes (commit bb7a42d)
