# VirtIO Status on ARM64

## Current State (November 2025)

### VirtIO-MMIO Transport Layer ✅ **COMPLETE**

The VirtIO-MMIO transport layer is fully implemented and functional:

- **File**: `platform/arm64/drivers/virtio_mmio.c`
- **Detection**: Automatically scans 32 MMIO slots (0x0a000000 + n×0x200)
- **IRQ Mapping**: IRQs 16-47 for MMIO devices
- **Tested**: Successfully detects virtio-net and virtio-gpu devices on QEMU virt machine

#### Test Results
```
[virtio-mmio] Scanning device tree for virtio-mmio devices...
[virtio-mmio] Found virtio-net at 0xa003c00 (IRQ 46)
[virtio-mmio] Found virtio-gpu at 0xa003e00 (IRQ 47)
[virtio-mmio] Found 2 virtio device(s)
```

### VirtIO Rust Drivers ⏳ **PENDING INTEGRATION**

The Rust VirtIO drivers (`drivers/rust/virtio_net/`, `drivers/rust/virtio_blk/`) are currently **PCI-only**:

#### Current Architecture
```
drivers/rust/virtio_net/src/lib.rs:
  └─ find_device() → Scans PCI bus (0x00-0xFF)
      └─ pci_read16() → Reads PCI config space
          └─ Returns None on ARM64 (no PCI bus)
```

#### Issue
- **x86-64**: Uses PCI bus for VirtIO devices → Rust drivers work
- **ARM64**: Uses MMIO for VirtIO devices → Rust drivers don't probe

#### Probe Failure
```
virtio-net: probing for hardware...
virtio-net: probe failed, using loopback fallback
[virtio-net] init failed: -19  # -ENODEV
```

### Integration Path

To enable VirtIO Rust drivers on ARM64, we need to:

1. **Option A: MMIO Backend for Rust Drivers**
   - Add `#[cfg(target_arch = "aarch64")]` conditional compilation
   - Call `virtio_mmio_find_device()` instead of PCI scan
   - Adapt device initialization to use MMIO register access

2. **Option B: Unified Transport Abstraction**
   - Create `VirtioTransport` trait in Rust
   - Implement `PciTransport` and `MmioTransport`
   - Make drivers transport-agnostic

### Files to Modify

1. `drivers/rust/virtio_net/src/lib.rs`
   - Lines 938-954: Replace `find_device()` with platform-conditional logic
   - Lines 956-1062: Adapt `init_device()` for MMIO register access

2. `drivers/rust/virtio_blk/src/lib.rs`
   - Similar changes for block device driver

3. `drivers/rust/common/src/lib.rs`
   - Add MMIO FFI bindings:
     ```rust
     extern "C" {
         fn virtio_mmio_find_device(device_id: u32) -> *const c_void;
         fn virtio_mmio_read32(dev: *const c_void, offset: usize) -> u32;
         fn virtio_mmio_write32(dev: *const c_void, offset: usize, val: u32);
     }
     ```

### Current Workarounds

**Networking**: Uses loopback-only fallback (10.0.2.15 with static ARP)
**Block**: Not available on ARM64 (FuturaFS boot from ramfs only)

### Testing Environment

**QEMU virt Machine**:
- CPU: Cortex-A72
- RAM: 512 MiB
- Devices: `-device virtio-net-device -device virtio-gpu-device`
- MMIO Base: 0x0a000000

### References

- VirtIO 1.2 spec: https://docs.oasis-open.org/virtio/virtio/v1.2/virtio-v1.2.html
- QEMU virt machine: `qemu-system-aarch64 -M virt,dumpdtb=virt.dtb`
- CLAUDE.md: Line 392 "Rust drivers x86-64 only"
- ARM64_STATUS.md: VirtIO-MMIO detection working

### Next Steps

1. Implement `find_device()` for ARM64 in virtio_net
2. Test with `-device virtio-net-device,netdev=net0 -netdev user,id=net0`
3. Verify network stack integration
4. Port changes to virtio_blk
5. Update CLAUDE.md when complete
