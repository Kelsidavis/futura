# ARM64 Bring-Up Session - Part 3
## Date: 2025-11-05

### Issues Investigated Today

#### virtio-blk-pci Queue Register Access ❌ ONGOING

**Problem**: virtio-blk queue address registers read back as 0xffffffffffffffff after writing.

**Symptoms**:
```
[virtio-blk]   desc readback: lo=0xffffffff hi=0xffffffff
[virtio-blk]   avail readback: lo=0xffffffff hi=0xffffffff
[virtio-blk]   used readback: lo=0xffffffff hi=0xffffffff
[virtio-blk] ERROR: desc address mismatch! wrote=0x41610000 read=0xffffffffffffffff
```

**Root Cause Identified**: MMIO access pattern mismatch with working virtio-gpu driver

**Comparison with working virtio-gpu driver** (drivers/rust/virtio_gpu/src/lib.rs):

1. **Memory Barriers**: virtio-gpu uses DSB barriers BEFORE and AFTER each MMIO access
   ```rust
   unsafe fn common_write32(base: *mut u8, offset: usize, value: u32) {
       core::arch::asm!("dsb sy");  // BEFORE
       write_volatile(base.add(offset) as *mut u32, value);
       core::arch::asm!("dsb sy");  // AFTER
   }
   ```

2. **Queue Address Writes**: virtio-gpu writes 64-bit addresses in single operations
   ```rust
   common_write64(self.common_cfg, VIRTIO_PCI_COMMON_Q_DESCLO, desc_phys);  // One 64-bit write
   ```

   vs. virtio-blk writes lo/hi separately:
   ```rust
   write_volatile(desc_lo_ptr, desc_lo);  // Separate 32-bit writes
   write_volatile(desc_hi_ptr, desc_hi);
   ```

3. **Register Access**: virtio-gpu uses raw pointer + offset, not packed struct fields
   ```rust
   common_cfg: *mut u8  // Raw pointer
   // Access: base.add(offset)
   ```

   vs. virtio-blk:
   ```rust
   common: *mut VirtioPciCommonCfg  // Packed struct
   // Access: (*self.common).queue_desc_lo
   ```

**Attempted Fixes**:
1. ✅ Added ARM64 memory barriers after each write_volatile and read_volatile
2. ❌ Did not fix the issue - still getting 0xffffffff readback

**Next Steps**:
1. Refactor virtio-blk to match virtio-gpu MMIO access pattern:
   - Add DSB barriers BEFORE writes (not just after)
   - Use offset-based access instead of packed struct
   - Write 64-bit queue addresses as single operations
2. Alternative: Use common helper functions shared between all virtio drivers

### Current ARM64 Status

#### What Works ✅
- **Boot**: Complete EL3→EL2→EL1 transition
- **Interrupts**: GICv2 initialized and operational
- **Serial Console**: PL011 UART fully functional
- **Memory Management**: Physical allocator working (no MMU yet)
- **Scheduler**: Thread creation and dispatching functional
- **PCI**: ECAM driver working, devices detected
- **virtio-gpu-pci**: Device detected and initialized successfully
- **virtio-net-pci**: Device detected (not yet tested)
- **Console**: /dev/console registration and opening works
- **Rust Drivers**: All three drivers (virtio-blk, virtio-net, virtio-gpu) built for aarch64-unknown-linux-gnu
- **Init Process**: Binary stages successfully and spawns

#### In Progress 🚧

##### 1. virtio-blk-pci Support
**Status**: Investigating MMIO access pattern differences

**Analysis**:
- virtio-gpu uses helper functions with proper barrier placement
- virtio-blk uses direct struct access with incomplete barriers
- Need to standardize MMIO access across all virtio drivers

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

### Files Analyzed Today

1. **drivers/rust/virtio_blk/src/lib.rs**
   - Added ARM64 DSB barriers after MMIO operations (lines 1338-1391)
   - Uses packed struct for common config access
   - Writes queue addresses as separate 32-bit lo/hi values

2. **drivers/rust/virtio_gpu/src/lib.rs**
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

#### Test Results
- ✅ Boot successful
- ✅ All subsystems initialize
- ✅ virtio-gpu-pci works perfectly
- ✅ virtio-net-pci detected
- ❌ virtio-blk-pci queue setup fails (register writes don't stick)
- ✅ Init process spawns
- ⚠️ System terminates after init spawn

### Recommendations

#### Immediate (Next Session)
1. **Refactor virtio-blk MMIO access**:
   - Create shared helper functions for all virtio drivers
   - Use offset-based access like virtio-gpu
   - Add DSB barriers before AND after MMIO operations
   - Write 64-bit addresses as single operations

2. **Standardize virtio driver pattern**:
   - Move common helpers to `drivers/rust/common/src/lib.rs`
   - All virtio drivers should use same MMIO access pattern
   - Consider removing packed structs in favor of offset-based access

#### Medium Term
1. **Test init process execution**:
   - Add exception debugging
   - Verify user mode entry
   - Check if MMU is required

2. **Test virtio-net**:
   - Apply same MMIO fixes as virtio-blk
   - Network packet send/receive

#### Long Term
1. **Enable MMU**:
   - Critical for proper multi-process support
   - Required for user/kernel space separation
   - See docs/ARM64_MMU_IMPLEMENTATION.md

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
