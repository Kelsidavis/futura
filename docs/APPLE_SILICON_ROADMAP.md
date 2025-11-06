# Apple Silicon M2 Support Roadmap

**Target Device**: MacBook Pro A2338 (M2)  
**Status**: 🚧 **PLANNING PHASE**  
**Started**: 2025-11-05

## Overview

This document outlines the plan to bring up Futura OS on Apple Silicon M2 MacBook Pro. Apple Silicon requires significant platform-specific drivers and boot infrastructure different from standard ARM64 devices.

## Hardware Architecture

### M2 SoC Components
- **CPU**: ARM64 Avalanche (performance) + Blizzard (efficiency) cores
- **Interrupt Controller**: Apple AIC (not GICv2/GICv3)
- **UART**: Custom Samsung-style UART (apple,s5l-uart compatible)
- **Timer**: ARM Generic Timer (bypasses AIC, wired to FIQ)
- **GPU**: Apple GPU (custom, not virtio-gpu)
- **NVMe**: Apple ANS2 controller
- **USB**: Type-C with custom PD chip
- **Display**: Apple DCP (Display Coprocessor)
- **Boot**: Secure boot chain via iBoot

## Boot Sequence

### Current Challenges
1. **Secure Boot**: Apple Silicon uses iBoot → m1n1 → U-Boot/Linux chain
2. **No Direct Kernel Boot**: Cannot boot kernel directly like QEMU virt
3. **Requires m1n1**: Need m1n1 bootloader as first-stage payload
4. **Device Tree**: m1n1 provides modified device tree to payload
5. **UART Access**: Requires USB-C cable + special activation sequence

### Proposed Boot Flow
```
iBoot (Apple)
    ↓
m1n1 (Asahi Linux bootloader)
    ↓
Futura Kernel (as m1n1 payload)
    ↓
Parse device tree
    ↓
Initialize Apple AIC
    ↓
Initialize UART console
    ↓
Continue kernel init
```

## Required Drivers

### Priority 1: Core Platform (Boot Critical)
- [x] **Device Tree Parser**: Extend existing DTB code for Apple DT ✅
- [x] **Apple AIC**: Interrupt controller driver ✅
- [x] **Apple UART**: Console I/O for debugging ✅
- [ ] **ARM Generic Timer**: Already have, verify compatibility

### Priority 2: Essential I/O
- [x] **Apple NVMe (ANS2)**: Block storage access ✅ (driver structure complete, RTKit TBD)
- [ ] **Apple GPIO**: Pin muxing and control
- [ ] **USB-C PD**: Power delivery and serial console
- [ ] **PCIe Controller**: For NVMe and other devices

### Priority 3: Display & Graphics
- [ ] **Apple DCP**: Display coprocessor interface
- [ ] **Framebuffer**: Basic graphics output
- [ ] **Apple GPU**: Metal acceleration (long-term)

### Priority 4: Advanced Features
- [ ] **Thunderbolt**: External device support
- [ ] **Ethernet (USB-C)**: Network via adapter
- [ ] **WiFi/Bluetooth**: On-board wireless (complex)
- [ ] **Audio**: Apple audio subsystem

## Implementation Plan

### Phase 1: Boot Infrastructure (Week 1-2) 🚧 **IN PROGRESS**
**Goal**: Get console output working

1. ✅ **Add Apple platform detection** (COMPLETE)
   - Extended `kernel/dtb/arm64_dtb.c` with Apple compatible strings
   - Added `PLATFORM_APPLE_M1/M2/M3` to platform types
   - Parse Apple device tree format

2. ✅ **Implement Apple UART driver** (COMPLETE)
   - Created `platform/arm64/drivers/apple_uart.c`
   - Samsung-style UART with Apple specifics
   - 1.2V voltage levels via USB-C
   - Early console support

3. ✅ **Implement Apple AIC** (COMPLETE)
   - Created `platform/arm64/interrupt/apple_aic.c`
   - Register layout matching Asahi Linux docs
   - IPI (Inter-Processor Interrupt) support
   - Hardware IRQ routing
   - SET/CLR register pattern

4. ✅ **Build m1n1 payload** (COMPLETE)
   - Added Linux ARM64 image header to boot.S
   - Created scripts/create-m1n1-payload.sh
   - Makefile target: `make m1n1-payload`
   - Outputs Image.gz (200 KiB, 69% compressed)

### Phase 2: Storage & Boot (Week 3-4) ✅ **COMPLETE**
**Goal**: Access NVMe storage

1. ✅ **Apple NVMe (ANS2) driver** (COMPLETE)
   - Full driver implementation with NVMMU
   - Command submission queues with TCBs
   - Completion queues with phase bit tracking
   - Namespace management via IDENTIFY commands
   - **RTKit integration complete** ⭐

2. **PCIe controller support** (NOT NEEDED)
   - ANS2 is not PCIe-attached (embedded in SoC)
   - Uses RTKit mailbox for communication

3. **Boot from internal SSD** (TODO - Phase 4)
   - Mount Apple APFS (read-only initially)
   - Load kernel modules
   - Enable userland

### Phase 3: Display & Input (Week 5-6)
**Goal**: Basic GUI capability

1. **Display Coprocessor (DCP)**
   - IPC protocol with DCP firmware
   - Mode setting
   - Framebuffer allocation

2. **USB HID input**
   - Keyboard/trackpad via USB-C
   - Event processing

### Phase 4: Networking & Full System (Week 7-8)
**Goal**: Full usable system

1. **USB Ethernet adapter**
   - CDC-ECM/CDC-NCM drivers
   - TCP/IP integration

2. **WiFi support (stretch goal)**
   - Apple WLAN firmware
   - Complex initialization

## Technical References

### Asahi Linux Resources
- **m1n1 GitHub**: https://github.com/AsahiLinux/m1n1
- **AIC Documentation**: https://asahilinux.org/docs/hw/soc/aic/
- **Linux Kernel Patches**: Search LKML for "Apple M1 SoC"
- **Device Tree Bindings**: drivers/*/bindings/arm/apple

### Key Differences from QEMU Virt
| Feature | QEMU Virt | Apple M2 |
|---------|-----------|----------|
| Interrupt Controller | GICv2 | Apple AIC |
| UART | PL011 | Apple s5l-uart |
| Boot | Direct kernel | iBoot → m1n1 |
| PCI | ECAM | Apple custom |
| Storage | virtio-blk | ANS2 NVMe |
| Display | virtio-gpu | Apple DCP |
| Device Tree | Linux standard | Apple extended |

## Development Setup

### Required Hardware
- MacBook Pro A2338 (M2) - Primary test device
- USB-C to USB-C cable - For UART console
- Second Mac (any) - For tethered boot/debugging
- USB-C Ethernet adapter - For networking

### Required Software
- **m1n1**: Asahi Linux bootloader
- **U-Boot (optional)**: If not booting kernel directly
- **pyserial**: For UART communication
- **kmutil**: For working with Apple kernel cache

### Test Environment
```bash
# Build kernel for Apple Silicon
make PLATFORM=arm64 APPLE_SILICON=1

# Create m1n1 payload (future)
scripts/create-m1n1-payload.sh build/bin/futura_kernel.elf

# Boot via m1n1 (tethered boot for development)
m1n1 -w build/bin/futura.macho
```

## Current Status

### Completed ✅
- Device tree infrastructure extended for Apple Silicon
- Apple platform detection (M1/M2/M3)
- Apple AIC interrupt controller driver
- Apple UART driver (s5l-uart) for console I/O
- **Apple ANS2 NVMe driver** - Full driver structure with queue management, TCB programming, linear submission
- **Apple RTKit IPC driver** - Mailbox protocol for co-processor communication
- **Device tree hardware address parsing** - fut_dtb_get_reg() for mailbox + NVMe base addresses
- **RTKit + ANS2 integration** - Complete end-to-end storage stack
- **m1n1 payload infrastructure** - Linux ARM64 image format, compression, build system ⭐ **NEW**
- **Phase 1: Boot Infrastructure ✅ COMPLETE** (4 of 4 items - 100%)
- **Phase 2: Storage infrastructure ✅ COMPLETE** (ANS2 + RTKit + Device Tree)
- ARM64 platform foundation
- virtio drivers (won't work on Apple hw, but good reference)

### In Progress 🚧
- None - Phases 1 & 2 complete, ready for hardware testing

### Ready for Hardware Testing ✅
- **All software infrastructure complete** - Phases 1 & 2 done
- **Tethered boot ready** - Non-destructive testing available
- **No installation required** - Runs entirely from RAM
- **Testing guide available** - See `docs/APPLE_SILICON_TESTING.md`
- **Automated script** - Use `./scripts/test-on-m2.sh` for quick testing

## Next Steps

1. ✅ ~~Extend device tree support for Apple platform detection~~ (COMPLETE)
2. ✅ ~~Implement Apple AIC interrupt controller~~ (COMPLETE)
3. ✅ ~~Implement Apple UART for console output~~ (COMPLETE)
4. ✅ ~~Implement Apple NVMe (ANS2) driver~~ (COMPLETE - Phase 2)
5. ✅ ~~Implement Apple RTKit IPC driver~~ (COMPLETE - Phase 2)
6. ✅ ~~Integrate RTKit + ANS2~~ (COMPLETE - Phase 2)
7. ✅ ~~Device tree hardware address parsing~~ (COMPLETE - Phase 2)
8. **Build m1n1 payload infrastructure** (NEXT - Phase 1 item 4)
9. **Test on real M2 hardware** (BLOCKED - need hardware)

## Resources Needed

- Physical MacBook Pro M2 for testing
- Second Mac for tethered boot setup
- USB-C cables and adapters
- Time to study Asahi Linux implementations

## Long-Term Vision

Successfully running Futura OS natively on Apple Silicon would:
- Demonstrate true cross-platform capability
- Validate ARM64 architecture
- Provide alternative OS for Mac hardware
- Showcase driver portability

---

**Note**: This is an ambitious undertaking. Apple Silicon support requires deep understanding of custom hardware and boot process. We'll iterate and adjust as we learn more.
