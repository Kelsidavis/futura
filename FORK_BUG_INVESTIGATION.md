# ARM64 Fork Bug Investigation

## Status: CRITICAL BUG - Fork child crashes immediately

## Symptoms
- Child process created by fork() crashes with undefined instruction exception
- Child should execute at PC=0x400170 but instead crashes at PC=0x400168
- PC=0x400168 is the value of x30 (link register), suggesting context restoration issue

## Investigation Summary (2025-11-15)

### Verified Correct
1. ✅ **Structure offsets** - Verified with offsetof():
   - `fut_cpu_context_t::pc` @ offset 264
   - `fut_cpu_context_t::x30_lr` @ offset 240
   - `fut_interrupt_frame_t::pc` @ offset 256
   - `fut_interrupt_frame_t::x[30]` @ offset 240

2. ✅ **Fork context setup** - Confirmed via logging:
   - Fork sets `child_thread->context.pc = frame->pc` (0x400170) ✓
   - Fork sets `child_thread->context.x30_lr = frame->x[30]` (0x400168) ✓
   - Boot log shows: `Child context: PC=0x400170` ✓

3. ✅ **Exception entry** - Verified assembly code:
   - Saves ELR_EL1 to `frame->pc` at offset 256 ✓
   - Hardware sets ELR_EL1 = PC+4 after SVC instruction ✓

4. ✅ **Context switch** - Verified assembly code:
   - Loads PC from `[context + 264]` into x2 ✓
   - Sets `elr_el1 = x2` ✓
   - Uses ERET to jump to ELR_EL1 ✓

### Issue
- Despite all the above being correct, child jumps to 0x400168 instead of 0x400170
- 0x400168 matches x30_lr value, suggesting ELR_EL1 contains wrong value
- Disassembly shows 0x400168 contains valid instruction (`mov x8, #0x39`)
- But exception handler reports instruction at 0x400168 = 0x00000000 (NULL)
  - This is because exception handler runs with kernel page table
  - User code pages not mapped in kernel page table

## Possible Root Causes (Unconfirmed)

1. **Cache coherency issue**
   - Fork writes child context to memory
   - Context switch reads stale cached data with old PC value
   - Needs: Add explicit DSB/ISB barriers after fork sets context

2. **Compiler optimization bug**
   - Compiler might be reordering context writes
   - Needs: Add volatile qualifiers or memory barriers

3. **Context pointer corruption**
   - Scheduler might pass wrong pointer to fut_switch_context()
   - Needs: Add logging to verify x1 value in context_switch.S

4. **ARM64 ERET behavior**
   - Subtle interaction between ERET, page table switch, and cached state
   - Needs: Review ARM ARM documentation on ERET requirements

## Test Case
```
forktest program:
- 0x400168: mov x8, #0x39  (fork syscall setup)
- 0x40016c: svc #0x0        (execute syscall)
- 0x400170: mov x3, x0      (save return value) <- SHOULD START HERE
```

Child should return to 0x400170 but crashes at 0x400168.

## Next Steps
1. Add DSB/DMB barriers after fork sets child context
2. Add logging in scheduler before calling fut_switch_context()
3. Try disabling compiler optimizations for fork.c
4. Add assembly-level debugging in context_switch.S
5. Test on real ARM64 hardware (not QEMU) to rule out emulation bug

## Files Involved
- `/Users/kelsi/futura/kernel/sys_fork.c` - Fork implementation (line 715)
- `/Users/kelsi/futura/platform/arm64/context_switch.S` - Context restoration (line 193-194)
- `/Users/kelsi/futura/platform/arm64/arm64_exception_entry.S` - Exception entry (line 140-141)
- `/Users/kelsi/futura/include/arch/arm64/regs.h` - Structure definitions

## Build Commands for Testing
```bash
make PLATFORM=arm64
qemu-system-aarch64 -M virt -cpu cortex-a72 -m 512 -kernel build/bin/futura_kernel.bin -nographic -device virtio-gpu-device -device virtio-net-device
```

## References
- ARM Architecture Reference Manual (ARM ARM) - ERET instruction behavior
- ARM Generic Interrupt Controller documentation
- QEMU ARM64 virt machine documentation
