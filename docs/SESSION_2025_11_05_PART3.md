# ARM64 Bring-Up Session - Part 3

> **Note**: Historical session log. Paths and line references reflect the author's environment at the time and may not match the current tree.
## Date: 2025-11-05

### Issues Investigated Today

#### virtio-blk-pci Queue Register Access ✅ FIXED

**Problem**: virtio-blk queue address registers read back as 0xffffffffffffffff after writing.

**Symptoms (Before Fix)**:
```
[virtio-blk]   desc readback: lo=0xffffffff hi=0xffffffff
[virtio-blk]   avail readback: lo=0xffffffff hi=0xffffffff
[virtio-blk]   used readback: lo=0xffffffff hi=0xffffffff
[virtio-blk] ERROR: desc address mismatch! wrote=0x41610000 read=0xffffffffffffffff
```

**Root Cause**: MMIO access pattern mismatch with working virtio-gpu driver

**Solution Applied**: Refactored virtio-blk to match virtio-gpu MMIO access pattern

1. **Memory Barriers**: Added DSB barriers BEFORE and AFTER each MMIO access
   ```rust
   unsafe fn common_write32(base: *mut u8, offset: usize, value: u32) {
       unsafe { core::arch::asm!("dsb sy"); }  // BEFORE
       unsafe { write_volatile(base.add(offset) as *mut u32, value); }
       unsafe { core::arch::asm!("dsb sy"); }  // AFTER
   }
   ```

2. **Queue Address Writes**: Changed to single 64-bit write operations
   ```rust
   common_write64(self.common, VIRTIO_PCI_COMMON_Q_DESCLO, self.queue.desc_phys);
   common_write64(self.common, VIRTIO_PCI_COMMON_Q_AVAILLO, self.queue.avail_phys);
   common_write64(self.common, VIRTIO_PCI_COMMON_Q_USEDLO, self.queue.used_phys);
   ```

3. **Register Access**: Changed from packed struct to offset-based access
   ```rust
   common: *mut u8  // Raw pointer (changed from *mut VirtioPciCommonCfg)
   // Access: base.add(VIRTIO_PCI_COMMON_Q_DESCLO)
   ```

**Result After Fix**:
```
[virtio-blk] queue addrs: desc=0x41610000 avail=0x41620000 used=0x41630000
[virtio-blk] queue setup complete (notify_off=65535)
```

✅ Queue addresses are now accepted by the device
✅ No more readback errors
✅ virtio-blk driver initializes successfully on ARM64

### Current ARM64 Status

#### What Works ✅
- **Boot**: Complete EL3→EL2→EL1 transition
- **Interrupts**: GICv2 initialized and operational
- **Serial Console**: PL011 UART fully functional
- **Memory Management**: Physical allocator working (no MMU yet)
- **Scheduler**: Thread creation and dispatching functional
- **PCI**: ECAM driver working, devices detected
- **virtio-gpu-pci**: Device detected and initialized successfully
- **virtio-net-pci**: Device detected and initialized successfully
- **virtio-blk-pci**: Device detected, queue setup working, driver initialized ✅ NEW
- **Console**: /dev/console registration and opening works
- **Rust Drivers**: All three drivers (virtio-blk, virtio-net, virtio-gpu) built for aarch64-unknown-linux-gnu
- **Init Process**: Binary stages successfully and spawns

#### In Progress 🚧

##### 2. Init Process Execution
**Status**: Not yet investigated in detail

**Observations**:
- Init binary stages and spawns successfully
- System terminates after spawn
- No error messages

**Possible Causes**:
1. MMU disabled - init process may need virtual memory
2. Exception during user mode transition
3. Missing EL0 (user mode) setup
4. Stack or register initialization issue

### Files Modified Today

1. **drivers/rust/virtio_blk/src/lib.rs** ✅ REFACTORED
   - Added VirtIO PCI Common Config offset constants (lines 291-310)
   - Added MMIO helper functions with ARM64 DSB barriers:
     - `common_read8/16/32()` - read with barriers before/after
     - `common_write8/16/32/64()` - write with barriers before/after
   - Changed `VirtioBlkDevice.common` from `*mut VirtioPciCommonCfg` to `*mut u8`
   - Refactored `negotiate_features()` to use helper functions
   - Refactored `init_queue()` to use 64-bit queue address writes
   - Changed from packed struct field access to offset-based access

2. **drivers/rust/virtio_gpu/src/lib.rs** (Reference - already working)
   - Uses helper functions: `common_read32()`, `common_write32()`, `common_write64()` (lines 194-245)
   - Barriers BEFORE and AFTER each MMIO access
   - Writes queue addresses as single 64-bit operations (line 438, 441, 444)
   - Raw pointer-based access, not packed structs

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

#### Test Results (Before Fix)
- ✅ Boot successful
- ✅ All subsystems initialize
- ✅ virtio-gpu-pci works perfectly
- ✅ virtio-net-pci detected
- ❌ virtio-blk-pci queue setup fails (register writes don't stick)
- ✅ Init process spawns
- ⚠️ System terminates after init spawn

#### Test Results (After Fix)
- ✅ Boot successful
- ✅ All subsystems initialize
- ✅ virtio-gpu-pci works perfectly
- ✅ virtio-net-pci detected and initialized
- ✅ **virtio-blk-pci queue setup succeeds** (addresses accepted by device)
- ✅ **Block device subsystem initialized**
- ✅ Init process spawns
- ⚠️ System terminates after init spawn (separate issue, not investigated yet)

### Recommendations

#### Completed ✅
1. ✅ **Refactored virtio-blk MMIO access**:
   - Created MMIO helper functions with proper DSB barriers
   - Changed to offset-based access like virtio-gpu
   - Added DSB barriers before AND after MMIO operations
   - Changed to 64-bit address writes for queue setup

#### Next Steps (Immediate)
1. **Investigate init process execution issue**:
   - System spawns init but terminates immediately
   - Possible causes: MMU required, exception during EL0 transition, missing user mode setup
   - Add exception debugging to identify failure point

2. **Standardize virtio driver pattern across all drivers**:
   - Consider moving common MMIO helpers to `drivers/rust/common/src/lib.rs`
   - Apply same pattern to any future virtio drivers
   - Document the ARM64 MMIO requirements for driver developers

#### Medium Term
1. **Test virtio block I/O operations**:
   - Now that queue setup works, test actual read/write operations
   - Verify DMA operations work correctly on ARM64
   - Test FuturaFS integration

2. **Enable MMU**:
   - Critical for proper multi-process support
   - Required for user/kernel space separation
   - See docs/ARM64_MMU_IMPLEMENTATION.md

3. **Full driver testing**:
   - virtio-net: test network packet send/receive
   - virtio-gpu: test frame buffer operations
   - virtio-blk: test block device I/O

### Technical Notes

#### ARM64 MMIO Requirements
- DSB (Data Synchronization Barrier) ensures memory access ordering
- Critical for MMIO on ARM64 to prevent reordering
- Must be placed BEFORE and AFTER MMIO operations
- `dsb sy` = full system barrier (strongest ordering guarantee)

#### virtio 1.0 Queue Setup Protocol
1. Select queue (write to queue_select)
2. Read/write queue size
3. Write queue addresses (descriptor, available, used)
4. Enable queue (write to queue_enable)
5. Set DRIVER_OK status

**Important**: Modern virtio uses 64-bit byte addresses for queue pointers

### References
- Previous sessions:
  - docs/SESSION_2025_11_05.md (Part 1 - basic ARM64 setup)
  - docs/SESSION_2025_11_05_PART2.md (Part 2 - virtio-gpu & console fixes)
- ARM64 status: docs/ARM64_STATUS.md
- Apple Silicon roadmap: docs/APPLE_SILICON_ROADMAP.md
- MMU investigation: docs/ARM64_MMU_IMPLEMENTATION.md
