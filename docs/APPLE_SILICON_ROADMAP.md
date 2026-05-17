# Apple Silicon M2 Support Roadmap

**Target Device**: MacBook Pro A2338 (M2) (also covers M1 / M3 / M4 SoCs)
**Status**: ✅ **Kernel-side bring-up COMPLETE; real-hardware validation pending**
**Started**: 2025-11-05
**Last Updated**: 2026-05-16

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
- [x] **Device Tree Parser**: Extended for Apple DT + path-aware walker (`578f6fbb`) ✅
- [x] **Apple AIC**: Interrupt controller driver (Rust `apple_aic` + IRQ + FIQ dispatch) ✅
- [x] **Apple UART**: Console I/O (Rust `apple_uart` + pre-MMU MIDR-aware shim) ✅
- [x] **ARM Generic Timer**: FIQ dispatched via `apple_aic_handle_fiq` with `CNTP_CTL.ISTATUS` check ✅

### Priority 2: Essential I/O
- [x] **Apple NVMe (ANS2)**: Driver collapsed to thunk over `rust_ans2` (`634f6d8c`) ✅
- [x] **Apple GPIO**: Rust `apple_gpio` crate present ✅
- [ ] **USB-C PD**: Power delivery / Type-C controller — not yet started
- [x] **Apple PCIe**: `rust_apple_pcie` crate + xHCI controller wired through ECAM ✅

### Priority 3: Display & Graphics
- [x] **Apple DCP**: Rust `apple_dcp` crate + C wrapper (`997e4c06`) ✅
- [x] **Framebuffer**: m1n1 `/chosen/framebuffer` fast-path lights up console before DCP swap-chain (`a103eb48`) ✅
- [ ] **Apple GPU**: Metal acceleration — long-term, requires AGX firmware reverse engineering

### Priority 4: Advanced Features
- [ ] **Thunderbolt**: External device support
- [x] **Ethernet (USB-C)**: CDC-ECM driver wired through `apple_xhci_bulk_transfer` ✅
- [~] **WiFi/Bluetooth**: On-board wireless — Rust `apple_bcm` crate + C wrapper does PCIe discovery, chip classification, FLR via PCIe Capability 0x10, WL_REG_ON/BT_REG_ON GPIO toggle (DT walker populates pin numbers from `apple,bootstrap-gpios`), and BAR-VA accessors; kernel firmware loader (`fut_firmware_load`) wires `apple_bcm` to attempt blob loading but currently fails -ENOENT because no FS provider exists yet.  Outstanding: FS firmware provider, PCIe MSI/MSI-X vector allocation, brcmfmac M2M-DMA firmware upload + msgbuf rings, HCI transport for Bluetooth function
- [x] **Audio**: Rust `apple_mca` MCA I2S + I2C codec wrapper (`f95357b9`) ✅

## Implementation Plan

### Phase 1: Boot Infrastructure (Week 1-2) ✅ **COMPLETE**
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
   - **RTKit IPC scaffolding complete** (protocol coverage WIP)

2. **PCIe controller support** (NOT NEEDED)
   - ANS2 is not PCIe-attached (embedded in SoC)
   - Uses RTKit mailbox for communication

3. **Boot from internal SSD** (TODO - Phase 4)
   - Mount Apple APFS (read-only initially)
   - Load kernel modules
   - Enable userland

### Phase 3: Display & Input ✅ **COMPLETE (kernel-side)**
**Goal**: Basic GUI capability

1. **Display Coprocessor (DCP)** ✅
   - IPC protocol (RTKit message dispatcher in Rust `apple_dcp`)
   - Mode setting (mode getter / setter via Rust FFI)
   - Framebuffer allocation (page alloc + DART map + register with kernel fb)
   - m1n1 framebuffer fast-path for first-light before full DCP boot

2. **USB HID input** ✅
   - Keyboard SPI / trackpad I2C (Rust `apple_hid` parser)
   - Event processing (callbacks + ring buffer)

### Phase 4: Networking & Full System ✅ **COMPLETE (kernel-side)**
**Goal**: Full usable system

1. **USB Ethernet adapter** ✅
   - CDC-ECM driver (`platform/arm64/drivers/usb_cdc_ecm.c`)
   - TCP/IP integration via existing stack

2. **WiFi/Bluetooth support** 🚧 (chip discovery + power-rails + reset wired; radio bring-up pending)
   - Rust `apple_bcm` crate classifies Broadcom WiFi+BT combo chips by PCI vendor/device
   - C wrapper walks Apple PCIe, finds fn 0 (WiFi) + fn 1 (Bluetooth), reads BAR0/BAR2, enables MEM + bus mastering
   - `apple_bcm_chip_power_on` drives WL_REG_ON / BT_REG_ON HIGH via `apple_gpio`; pin numbers populated by DT walker
   - `apple_bcm_chip_reset` issues PCIe Function-Level Reset via the reusable `rust_apple_pcie_find_cap` capability walker
   - Kernel-level `fut_firmware_load` request-firmware API + apple_bcm integration (logs missing-firmware names cleanly)
   - 10 unit tests for the firmware loader in `make test-arm64`
   - **Deferred to subsequent slices**: FS-backed firmware provider, brcmfmac M2M DMA upload, NVRAM parse, MSI wiring, HCI Bluetooth transport

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
- Device tree infrastructure extended for Apple Silicon (path-aware walker + Asahi `/soc/<type>@<addr>` fallbacks)
- Apple platform detection (M1 / M2 / M3 / M4 via MIDR + DT compatible)
- Every `platform/arm64/drivers/apple_*.c` migrated to a Rust crate under `drivers/rust/apple_*` (aic, uart, hid, audio/mca, xhci, rtkit, ans2, dcp, smc/power)
- MMU / boot blockers: PA-relocatable + 48-bit VA + runtime `KERN_PA_BASE` + Image-header relocatable flag
- IRQ + FIQ dispatch (timer FIQ via `CNTP_CTL.ISTATUS` check, DAIF.F unmasked)
- Apple peripheral PA→VA mapping window (`kernel_l1_table[8..511]`, 504 GiB device-nGnRE)
- DMA address correctness across xhci / ans2 / dcp / dart (physical addresses where the controller DMAs, not kernel VAs)
- m1n1 framebuffer first-light fast-path (kernel paints into `/chosen/framebuffer` before DCP swap-chain bring-up)
- `make m1n1-payload` produces a valid m1n1-compatible `Image.gz` with relocatable flag
- ARM64 platform foundation + virtio drivers (won't run on Apple HW but kept as QEMU virt reference)

### In Progress 🚧
- None on the kernel side — Phases 1-4 closed.

### Ready for Hardware Testing ✅
- **Kernel-side bring-up complete** — every blocker identified is fixed
- **Tethered boot ready** — `python3 -m m1n1.run m1n1.macho -b Image.gz kernel.macho`
- **No installation required** — runs entirely from RAM
- **Testing guide** — `docs/APPLE_SILICON_TESTING.md`
- **Automated script** — `./scripts/test-on-m2.sh`

## Next Steps

The kernel-side roadmap items are all checked.  Remaining work is
either real-hardware validation territory (which can't be done from
this environment) or post-first-light features:

1. ✅ ~~Phase 1 boot infrastructure~~ — boot.S MMU + UART + AIC dispatch
2. ✅ ~~Phase 2 storage~~ — ANS2 + RTKit + DTB hardware-address parsing
3. ✅ ~~Phase 3 display + input~~ — DCP + HID
4. ✅ ~~Phase 4 networking~~ — USB CDC-ECM
5. **Real-hardware validation on M1 / M2 / M3 / M4** — needs physical device
6. **pmgr support** — Apple SoC clock gating; m1n1 leaves most enabled but a few peripherals (DCP power-on, ANS reset deassert) likely need pmgr writes
7. **Full DCP swap-chain protocol** — currently m1n1's FB is the first-light path; DCP-driven mode changes / hot-plug come later
8. **WiFi/Bluetooth firmware load + radio bring-up** — discovery, power rails, FLR, and request-firmware plumbing all in place.  Outstanding pieces: (a) FS-backed firmware provider so `fut_firmware_load` returns the blob bytes, (b) PCIe MSI vector allocation for the BCM chip's command/event/RX/TX rings, (c) brcmfmac msgbuf protocol — M2M DMA firmware upload, ring init, scan/associate, (d) HCI transport for the BT function

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
