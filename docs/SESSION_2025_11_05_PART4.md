# ARM64 Bring-Up Session - Part 4

> **Note**: Historical session log. Paths and line references reflect the author's environment at the time and may not match the current tree.
## Date: 2025-11-05

### Issue Investigated Today

#### Init Process Execution Failure

**Problem**: Init process thread created successfully but never executes; scheduler returns to kernel_main instead of switching to init thread.

**Investigation Process**:

1. **Initial Discovery**: Found two conflicting scheduler implementations
   - `kernel/sched/arm64_process.c` - ARM64-specific scheduler (NOT compiled/linked)
   - `kernel/scheduler/fut_sched.c` - Main scheduler using per-CPU data structures
   - ARM64 kernel actually uses main scheduler, NOT the ARM64-specific one

2. **Missing Boot Thread**: Discovered `arm64_init_boot_thread()` was never called
   - Function exists in `kernel/arch/arm64/arm64_threading.c`
   - Sets up per-CPU current thread so scheduler has a valid context
   - **Fixed**: Added call in `kernel_main.c` after `fut_sched_init()` (line 1170)
   - **Result**: Boot thread now initializes successfully ✅

3. **Scheduler Debugging**: Added debug logging to trace thread lifecycle
   - `fut_sched_add_thread()`: Logs when threads added to ready queue
   - `select_next_thread()`: Logs ready queue state when selecting next thread
   - **Finding**: Init thread IS being added to scheduler (tid=6)
   - **Finding**: Ready queue HAS threads when spawner exits
   - **Problem**: `fut_schedule()` finds next thread but doesn't switch to it properly

4. **Context Switch Investigation**: Examined `platform/arm64/context_switch.S`
   - `fut_switch_context()` handles both EL0 (user) and EL1 (kernel) threads
   - Uses `eret` for EL0 transitions (line 92)
   - Uses `br x2` for EL1 transitions (line 118)
   - Function should NEVER return, but scheduler panics indicate it does

### Root Cause Identified

**The init process cannot execute due to MMU being disabled.**

Init thread setup:
- Thread created with entry point `0x4001d5ac` (virtual address from ELF)
- PSTATE set to `PSTATE_MODE_EL0t` (user mode)
- Context switch via `eret` to EL0

**Problem**: With MMU disabled, virtual addresses cannot be translated to physical addresses. When `eret` tries to jump to init's entry point (`0x4001d5ac`), the CPU cannot translate this virtual address, causing the context switch to fail or return unexpectedly.

### Files Modified Today

1. **kernel/kernel_main.c** ✅ FIXED
   - Lines 1167-1171: Added ARM64 boot thread initialization
   ```c
   #if defined(__aarch64__)
       /* ARM64: Initialize boot thread so per-CPU has a current thread */
       extern void arm64_init_boot_thread(void);
       arm64_init_boot_thread();
   #endif
   ```

2. **kernel/scheduler/fut_sched.c** (Debug logging - temporary)
   - Lines 455-471: Added debug logging to `select_next_thread()`
   - Lines 269-272: Added debug logging to `fut_sched_add_thread()`

3. **kernel/sched/arm64_process.c** (Debug logging - never used, file not compiled)
   - Lines 354-368: Added debug logging to `fut_scheduler_next()` (unused)

### Current ARM64 Status

#### What Works ✅
- **Boot**: Complete EL3→EL2→EL1 transition
- **Interrupts**: GICv2 initialized and operational
- **Serial Console**: PL011 UART fully functional
- **Memory Management**: Physical allocator working (MMU disabled)
- **Scheduler**: Main scheduler with per-CPU queues operational
- **Per-CPU Data**: Boot thread initialization working
- **Thread Creation**: Kernel and user threads created successfully
- **PCI**: ECAM driver working, devices detected
- **virtio-gpu-pci**: Device initialized successfully
- **virtio-net-pci**: Device initialized successfully
- **virtio-blk-pci**: Device initialized successfully, queue setup working
- **Console**: /dev/console registration and opening works
- **Rust Drivers**: All three drivers built for aarch64-unknown-linux-gnu
- **Init Process**: Binary stages, thread created, added to scheduler ✅ NEW

#### Blocked ❌

##### Init Process Execution
**Status**: Blocked by MMU requirement

**Issue**: User-space processes require MMU for virtual address translation. With MMU disabled:
- Init binary loaded with virtual addresses (ELF format)
- Entry point `0x4001d5ac` is virtual address
- Context switch to EL0 via `eret` fails - cannot translate address
- Scheduler returns instead of switching, causing panic

**Observations**:
```
[THREAD-CREATE] ARM64 thread 6: entry=0x4001d5ac arg=0x41730aa8
[SCHED-ADD] tid=6 cpu=0 ready_count=5
[ARM64-SPAWNER] Init spawner thread exiting.
[SELECT] ready_queue_head=0x402a9600 ready_count=5
[PANIC] ARM64 scheduler returned unexpectedly!
```

- Init thread created and added to scheduler ✅
- Ready queue has threads when spawner exits ✅
- `fut_schedule()` finds next thread ✅
- `fut_switch_context()` fails to switch properly ❌
- Scheduler returns to kernel_main ❌

**Root Cause**: MMU must be enabled for user-space execution

### Testing

#### Test Command
```bash
qemu-system-aarch64 -machine virt -cpu cortex-a72 -m 256 \
  -serial stdio -display none \
  -kernel build/bin/futura_kernel.elf \
  -device virtio-gpu-pci \
  -device virtio-net-pci \
  -device virtio-blk-pci,drive=hd0 \
  -drive file=futura_disk.img,if=none,id=hd0,format=raw \
  -no-reboot -no-shutdown
```

#### Test Results
- ✅ Boot successful
- ✅ All subsystems initialize
- ✅ virtio drivers working
- ✅ **Boot thread initialized** (NEW FIX)
- ✅ **Init thread created and enqueued** (NEW)
- ❌ **Init thread never executes** (MMU required)
- ❌ Scheduler panic and system termination

### Update: MMU is ENABLED ✅

**Discovery**: MMU was already enabled! Boot output shows 'A12345678BC' where:
- 'A' = before MMU
- '12345678' = page table setup progress
- 'B' = after MMU enable ✅
- 'C' = platform init

The issue is **NOT** that MMU is disabled. The issue is **page table permissions**.

### Root Cause: Page Table Permissions Block EL0 Access

**Problem**: Identity-mapped DRAM (0x40000000-0x80000000) has permissions set to **EL1-only access**.

Current page table flags (line 261 in `platform/arm64/boot.S`):
```asm
mov     x2, #0x401    /* Valid | Block | AttrIndx=0 | AF */
```

AP (Access Permission) bits:
- AP[2:1] = 00 (current): Read/write at EL1 only, **no access at EL0** ❌
- AP[2:1] = 01 (needed): Read/write at EL1 and EL0 ✅

**Attempted Fix**: Add bit 6 to set AP[1]=1 for EL0 access
- Changed flags to `0x441` to add AP[1]=1 (bit 6)
- **Result**: MMU enable fails with Prefetch Abort ❌
- QEMU log shows: Exception 3 [Prefetch Abort] at 0x40000a00, ESR 0x8600000e (permission fault)

**Issue**: Setting AP[1]=1 causes kernel code to become non-executable at EL1, triggering prefetch abort during/after MMU enable.

### Recommendations

#### Immediate (Critical Path - BLOCKED)
1. **Fix Page Table Permissions for EL0 Access**:
   - Current identity mapping only allows EL1 access
   - Need to set AP bits correctly to allow both EL1 and EL0 access without breaking EL1 execution
   - May require separate page table entries for kernel code vs. data
   - Alternative: Create per-process page tables with proper permissions for user-space only

#### Alternative Approaches (If MMU Enable Proves Difficult)
1. **Physical Address Execution**:
   - Load init binary at known physical address
   - Set thread entry point to physical address instead of virtual
   - Requires modifications to ELF loader and thread setup
   - Only works for single-process, no memory protection

2. **Identity Mapping**:
   - Set up MMU with identity mapping (VA == PA)
   - Minimal page table setup
   - Provides MMU benefits with simpler setup
   - May be easier to debug than full virtual memory

#### Medium Term
1. **Debug MMU Enable Issue**:
   - Add extensive logging around MMU enable
   - Single-step through MMU enable sequence
   - Verify page table entries are correct
   - Check TCR_EL1, MAIR_EL1, SCTLR_EL1 register values

2. **Full Virtual Memory Support**:
   - Complete MMU implementation
   - Process-specific address spaces
   - Memory protection and isolation
   - Required for multi-process support

### Technical Notes

#### ARM64 Context Switching
- `fut_switch_context()` in `platform/arm64/context_switch.S`:
  - Lines 62-92: EL0 (user) path uses `eret` for exception return
  - Lines 94-122: EL1 (kernel) path uses `br x2` for direct jump
  - Context structure: x0-x1, x19-x30, SP, PC, PSTATE (offsets 0-128)

#### User-Space Requirements
- EL0 (user mode) execution requires valid virtual addresses
- `eret` instruction jumps to address in `ELR_EL1` register
- MMU must translate virtual→physical addresses
- Without MMU: `eret` to virtual address fails or causes exception

#### Per-CPU Boot Thread
- Main scheduler requires `percpu->current_thread` to be set
- `arm64_init_boot_thread()` creates minimal boot task/thread
- Sets `percpu->current_thread = arm64_boot_thread`
- Provides context for VFS operations and scheduler to work

#### Scheduler Queue Management
- Threads added to per-CPU ready queue via `fut_sched_add_thread()`
- `select_next_thread()` removes from head of ready queue
- Ready count increments on add, decrements on select
- Multiple threads can run concurrently (cooperative scheduling)

### Debug Logging Output

```
[SCHED-ADD] tid=1 cpu=0 ready_count=1
[SCHED-ADD] tid=2 cpu=0 ready_count=3
[SCHED-ADD] tid=3 cpu=0 ready_count=3
[SCHED-ADD] tid=4 cpu=0 ready_count=4
[SCHED-ADD] tid=5 cpu=0 ready_count=5
[SELECT] ready_queue_head=0x41750010 ready_count=5
[THREAD-CREATE] ARM64 thread 6: entry=0x4001d5ac arg=0x41730aa8
[SCHED-ADD] tid=6 cpu=0 ready_count=5
[ARM64-SPAWNER] Init spawner thread exiting.
[SELECT] ready_queue_head=0x402a9600 ready_count=5
[PANIC] ARM64 scheduler returned unexpectedly!
```

### References
- Previous sessions:
  - `docs/SESSION_2025_11_05.md` (Part 1 - Basic ARM64 setup)
  - `docs/SESSION_2025_11_05_PART2.md` (Part 2 - virtio-gpu & console fixes)
  - `docs/SESSION_2025_11_05_PART3.md` (Part 3 - virtio-blk MMIO fixes)
- ARM64 status: `docs/ARM64_STATUS.md`
- MMU investigation: `docs/ARM64_MMU_IMPLEMENTATION.md`
- Apple Silicon roadmap: `docs/APPLE_SILICON_ROADMAP.md`
