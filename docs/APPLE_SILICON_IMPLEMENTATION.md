# Apple Silicon M2 Implementation Summary

**Target Device**: MacBook Pro A2338 (M2) — also covers M1 / M3 / M4
**Status**: ✅ **All kernel-side phases complete** (boot + storage + display/input + networking)
**Last Updated**: 2026-05-16

## Overview

This document summarizes the implementation work to bring Futura OS to
Apple Silicon Macs (M1 / M2 / M3 / M4).  Every C wrapper in
`platform/arm64/drivers/apple_*.c` is now backed by a Rust crate
under `drivers/rust/apple_*`; the eleven bring-up blockers tracked in
[`docs/APPLE_SILICON_BRINGUP_PLAN.md`](APPLE_SILICON_BRINGUP_PLAN.md)
are all closed.  Real-hardware validation is the only remaining piece.

## Completed Components ✅

### 1. Device Tree Support for Apple Silicon


**Files Modified**:
- `include/platform/arm64/dtb.h`
- `kernel/dtb/arm64_dtb.c`

**Implementation Details**:
- Added platform type enums: `PLATFORM_APPLE_M1`, `PLATFORM_APPLE_M2`, `PLATFORM_APPLE_M3`
- Extended `fut_platform_info_t` structure with:
  - `uint64_t aic_base` - Apple Interrupt Controller base address
  - `bool has_aic` - Flag for Apple AIC presence
- Implemented Apple platform detection via device tree compatible strings:
  - M1: `apple,t8103`, `apple,j274` (Mac mini M1)
  - M2: `apple,t8112`, `apple,j413` (MacBook Air M2), `apple,j493` (MacBook Pro 13" M2 A2338)
  - M3: `apple,t8103`
- Platform-specific initialization in `fut_dtb_parse()`:
  - CPU frequency: 24 MHz (timer)
  - UART base: 0x235200000
  - AIC base: 0x23B100000
  - Flags: `has_aic = true`, `has_generic_timer = true`

**Testing**:
- ✅ Compiles cleanly on ARM64
- ⏸️ Runtime testing blocked (no M2 hardware)

### 2. Apple AIC (Apple Interrupt Controller)

**Files Created**:
- `include/platform/arm64/apple_aic.h`
- `platform/arm64/interrupt/apple_aic.c`

**Implementation Details**:
- Complete Apple Interrupt Controller driver based on Asahi Linux documentation
- Register layout:
  - `AIC_INFO (0x0004)`: Version and configuration
  - `AIC_EVENT (0x2000)`: Event status (read-only)
  - `AIC_MASK_SET/CLR (0x4000/0x4080)`: Interrupt mask control
  - `AIC_IPI_SEND (0x6000)`: Inter-processor interrupts
  - `AIC_WHOAMI (0x2000)`: Current CPU ID
- Features:
  - Support for up to 896 hardware IRQs
  - 32 IPI sources for multi-core communication
  - SET/CLR register pattern for mask control
  - Event bitmap scanning for pending interrupts
- Functions implemented:
  - `fut_apple_aic_init()`: Initialize AIC, mask all IRQs, enable IPIs
  - `fut_apple_aic_enable_irq()` / `fut_apple_aic_disable_irq()`: IRQ control
  - `fut_apple_aic_is_pending()`: Check IRQ status
  - `fut_apple_aic_send_ipi()` / `fut_apple_aic_ack_ipi()`: IPI support
  - `apple_aic_handle_irq()`: Main IRQ dispatcher (called from exception vector)
  - `fut_apple_irq_init()`: High-level platform integration

**Key Differences from GICv2**:
- SET/CLR pattern instead of distributor enable registers
- Event bitmap for pending interrupts
- No CPU interface - direct register access
- IPI mechanism different from GIC SGI

**Testing**:
- ✅ Compiles cleanly on ARM64
- ⏸️ Runtime testing blocked (no M2 hardware)

### 3. Apple UART (s5l-uart)

**Files Created**:
- `include/platform/arm64/apple_uart.h`
- `platform/arm64/drivers/apple_uart.c`

**Implementation Details**:
- Samsung S5L-style UART driver with Apple modifications
- Register layout (Samsung-compatible):
  - `ULCON (0x00)`: Line control (8N1)
  - `UCON (0x04)`: Control (interrupt modes)
  - `UFCON (0x08)`: FIFO control
  - `UTRSTAT (0x10)`: TX/RX status
  - `UTXH (0x20)` / `URXH (0x24)`: Transmit/receive buffers
  - `UBRDIV (0x28)` / `UFRACVAL (0x2C)`: Baud rate divisors
  - `UINTP/UINTS/UINTM (0x30/0x34/0x38)`: Interrupt control
- Configuration:
  - 8 data bits, no parity, 1 stop bit (8N1)
  - 115200 baud rate (configurable)
  - 24 MHz UART clock (from device tree)
  - FIFO enabled with 8-byte trigger levels
- Features:
  - Blocking character output (`fut_apple_uart_putc()`)
  - Non-blocking character input (`fut_apple_uart_getc()`)
  - String output (`fut_apple_uart_puts()`)
  - Interrupt support (RX/TX/error)
  - TX/RX ready status checks
- Automatic line ending conversion: `\n` → `\r\n`

**Key Differences from PL011**:
- Samsung register layout vs. ARM PL011
- Different baud rate calculation (fractional divisor)
- Separate interrupt pending/source/mask registers
- FIFO status in dedicated register

**Testing**:
- ✅ Compiles cleanly on ARM64
- ⏸️ Runtime testing blocked (no M2 hardware)

### 4. Apple RTKit IPC

**Files Created**:
- `include/platform/arm64/apple_rtkit.h`
- `platform/arm64/drivers/apple_rtkit.c`

**Implementation Details**:
- Mailbox-based RTKit IPC scaffolding (HELLO/EPMAP handshake)
- Endpoint registration + message dispatch for ANS2 and future coprocessors
- Simplified register map placeholders (device-tree offsets still evolving)

**Testing**:
- ✅ Compiles cleanly on ARM64
- ⏸️ Runtime testing blocked (no M2 hardware)

### 5. Apple ANS2 NVMe Driver

**Files Created**:
- `include/platform/arm64/apple_ans2.h`
- `platform/arm64/drivers/apple_ans2.c`

**Implementation Details**:
- Full NVMe driver for Apple's custom ANS2 controller
- **NVMMU (NVMe MMU)** management with TCB arrays
- **TCB (Translation Control Block)** structure (128 bytes per command):
  - Duplicates PRPs from submission queue (Apple requirement)
  - DMA direction flags (TO_DEVICE/FROM_DEVICE)
  - Reserved space for AES-IV (64 bytes)
- **Linear submission**: Commands triggered via MMIO doorbell writes, not queue tail updates
- **Tag-based addressing**: 64 total tags shared between admin + I/O queues
  - Admin queue: 2 tags
  - I/O queue: 62 tags
- Queue management:
  - Single admin queue with admin/completion queues
  - Single I/O queue with submission/completion queues
  - Phase bit tracking for completion queue polling
- Operations:
  - Controller reset and enable
  - IDENTIFY controller/namespace commands
  - Read/write operations (single-page transfers)
  - Polled I/O (no interrupts yet)

**Key Differences from Standard NVMe**:
- Not PCIe-attached (embedded in SoC)
- Requires TCB programming alongside SQ entries
- Linear submission via tag writes, not SQ tail pointer
- Limited to 64 combined tags (vs. 64K in standard NVMe)
- Single queue pair (vs. multiple queue pairs)
- No async event support
- **RTKit co-processor** required for power management (not yet implemented)

**Current Limitations**:
- RTKit IPC uses simplified mailbox offsets; protocol coverage is incomplete
- Single-page transfers only (no PRP2 lists yet)
- Polled I/O only (interrupt handling TBD)

**Testing**:
- ✅ Compiles cleanly on ARM64
- ⏸️ Runtime testing blocked (no M2 hardware + RTKit required)

### 5. Apple RTKit IPC Driver ⭐ **NEW**

**Files Created**:
- `include/platform/arm64/apple_rtkit.h`
- `platform/arm64/drivers/apple_rtkit.c`

**Implementation Details**:
- Complete mailbox-based IPC protocol for Apple co-processors
- **Message format**: 64-bit messages with type [59:52] and payload [51:0]
- **Endpoint system**:
  - System endpoints (0-31): Management, crashlog, syslog, debug, ioreport
  - Application endpoints (32-255): Client-specific (ANS2 uses 0x20)
- **Boot sequence**:
  1. HELLO/HELLO_REPLY - Version negotiation (v11-v12 supported)
  2. EPMAP/EPMAP_REPLY - Endpoint discovery (256-endpoint bitmap)
  3. STARTEP - System endpoint activation (syslog, crashlog, debug, ioreport required)
  4. Power state management - IOP → ON, AP → ON
- **Mailbox operations**:
  - TX/RX FIFO with status polling
  - Endpoint-tagged messages (endpoint in bits [63:56])
  - Message routing to registered handlers
- **Management protocol**: 13 message types for co-processor control
- **Callback system**: Register per-endpoint handlers for async messages

**RTKit + ANS2 Integration**:
- ANS2 driver initializes RTKit context
- RTKit boots co-processor before NVMe initialization
- ANS2 registers endpoint 0x20 for NVMe-specific messages
- Power management handled via RTKit protocol
- ✅ **Hardware addresses parsed from device tree** (mailbox + NVMe base)

**Testing**:
- ✅ Compiles cleanly on ARM64
- ✅ Integrates with ANS2 driver successfully
- ⏸️ Runtime testing blocked (no M2 hardware)

### 6. Device Tree Hardware Address Parsing ⭐ **NEW**

**Files Modified**:
- `include/platform/arm64/dtb.h`
- `kernel/dtb/arm64_dtb.c`
- `platform/arm64/drivers/apple_ans2.c`

**Implementation Details**:
- **New fields in `fut_platform_info_t`**:
  - `uint64_t ans_mailbox_base` - RTKit mailbox MMIO base address
  - `uint64_t ans_nvme_base` - ANS2 NVMe controller MMIO base address
- **New function `fut_dtb_get_reg()`**:
  - Parses "reg" property from device tree nodes
  - Extracts base address and size (address/size pairs)
  - Handles big-endian to CPU conversion
  - Returns true if property found, false otherwise
- **Device tree node parsing**:
  - `/arm-io/ans` → NVMe controller base address
  - `/arm-io/ans/mailbox` → RTKit mailbox base address
  - Automatic fallback to hardcoded values if DT parsing fails
- **ANS2 driver integration**:
  - `ctrl->mmio_phys = info->ans_nvme_base` (NVMe registers)
  - `ctrl->mailbox_phys = info->ans_mailbox_base` (RTKit IPC)
  - No more placeholder 0 values or TODO comments

**Code Example**:
```c
/* In fut_dtb_parse() for PLATFORM_APPLE_M2 */
uint64_t ans_mailbox_m2, ans_nvme_m2;
if (fut_dtb_get_reg(dtb_ptr, "/arm-io/ans", &ans_nvme_m2, NULL)) {
    info.ans_nvme_base = ans_nvme_m2;
}
if (fut_dtb_get_reg(dtb_ptr, "/arm-io/ans/mailbox", &ans_mailbox_m2, NULL)) {
    info.ans_mailbox_base = ans_mailbox_m2;
}
```

**Testing**:
- ✅ Compiles cleanly on ARM64
- ✅ ANS2 driver updated to use parsed addresses
- ⏸️ Runtime testing pending actual device tree from m1n1

## Build System Integration

**Makefile Changes**:
- Added `platform/arm64/interrupt/apple_aic.c` to ARM64 sources
- Added `platform/arm64/drivers/apple_uart.c` to ARM64 sources
- Added `platform/arm64/drivers/apple_rtkit.c` to ARM64 sources
- Added `platform/arm64/drivers/apple_ans2.c` to ARM64 sources

**Build Verification**:
```bash
make PLATFORM=arm64 kernel
# Result: ✅ Successful build with no errors
# All 5 Apple Silicon drivers compile cleanly
# RTKit + ANS2 integration verified
# Device tree parsing integrated with ANS2 driver
```

## Architecture Decisions

### 1. Driver Modularity
All Apple Silicon drivers are self-contained and co-exist with existing drivers:
- GICv2 driver remains for RPi4/5 and QEMU virt
- PL011 UART driver remains for RPi and QEMU
- Platform detection at runtime via device tree selects appropriate drivers

### 2. Register Access Pattern
Using volatile pointer arithmetic for MMIO:
```c
static volatile uint8_t *base_addr = NULL;
#define REG_READ32(offset)  (*((volatile uint32_t *)(base_addr + (offset))))
#define REG_WRITE32(offset, val) (*((volatile uint32_t *)(base_addr + (offset))) = (val))
```

This pattern:
- Works without MMU enabled (uses physical addresses)
- Compatible with future MMU enablement
- Matches existing ARM64 driver patterns

### 3. Interrupt Handling
ARM Generic Timer on Apple Silicon:
- Bypasses AIC (wired directly to FIQ)
- Uses same timer infrastructure as GICv2 platforms
- No AIC-specific timer handling needed

### 4. Early Console Output
UART driver designed for early boot:
- No dynamic memory allocation
- Works before scheduler initialization
- Compatible with existing `fut_printf()` infrastructure

## Completed Work (Phase 1 - Final Item)

### 7. m1n1 Payload Infrastructure ⭐ **NEW - COMPLETE**

**Files Modified/Created**:
- `platform/arm64/boot.S` - Added Linux ARM64 image header
- `scripts/create-m1n1-payload.sh` - Payload builder script
- `Makefile` - Added `m1n1-payload` target

**Implementation Details**:

**ARM64 Linux Image Header** (64 bytes):
- Offset 0x00: Branch instruction to kernel entry point
- Offset 0x08: text_offset (0 = load anywhere)
- Offset 0x10: image_size (kernel size in bytes)
- Offset 0x18: flags (little-endian, 4K pages)
- Offset 0x38: magic (0x644d5241 = "ARM\x64")

**Build Process**:
1. Extract raw binary from ELF: `objcopy -O binary kernel.elf Image`
2. Verify ARM64 header magic at offset 0x38
3. Compress to Image.gz: `gzip -9 Image` (69% reduction)
4. Generate usage instructions in README.txt

**Makefile Integration**:
```bash
make m1n1-payload    # Build ARM64 kernel + create m1n1 payload
make m1n1-clean      # Clean m1n1 artifacts
```

**Output Files** (in `build/m1n1/`):
- `Image` - Raw kernel binary with ARM64 Linux header (650 KiB)
- `Image.gz` - Gzipped kernel image (200 KiB) **← Use this with m1n1**
- `README.txt` - Detailed usage instructions

**Loading with m1n1**:

Method 1 - Tethered Boot (Development):
```bash
python3 -m m1n1.run m1n1.macho -b build/m1n1/Image.gz kernel.macho
```

Method 2 - Concatenated Payload (Production):
```bash
cat m1n1.macho build/m1n1/Image.gz > m1n1-payload.macho
sudo kmutil configure-boot -c m1n1-payload.macho -v /Volumes/BOOTVOLUME
```

**Device Tree**: m1n1 passes Apple device tree in X0, parsed by `fut_dtb_parse()`

**Testing**:
- ✅ ARM64 Linux header verified (magic: 0x644d5241)
- ✅ Build system integration complete
- ✅ Script tested with compression (69% reduction)
- ⏸️ Tethered boot pending M2 hardware availability

**Phase 1 Status**: ✅ **100% COMPLETE** - All 4 items done (DTB, AIC, UART, m1n1)

## Testing Strategy

### Current Testing (QEMU virt)
All existing ARM64 functionality continues to work:
- ✅ QEMU virt machine boots successfully
- ✅ GICv2 interrupt controller functional
- ✅ PL011 UART console working
- ✅ virtio-gpu, virtio-net, virtio-blk drivers operational

### Future Testing (M2 Hardware)
When M2 MacBook Pro becomes available:

1. **Phase 1 Testing**:
   - Boot via m1n1 tethered boot
   - Verify console output (Apple UART)
   - Confirm AIC initialization
   - Test interrupt handling (timer ticks)

2. **Phase 2 Testing** (after NVMe driver):
   - Access internal SSD
   - Boot from storage
   - Persistent filesystem

3. **Phase 3 Testing** (after display driver):
   - Framebuffer output
   - Display Coprocessor (DCP) communication
   - Basic GUI

## Documentation

**Primary Documents**:
- `docs/APPLE_SILICON_ROADMAP.md`: 8-week implementation plan
- `docs/APPLE_SILICON_IMPLEMENTATION.md`: This document
- `docs/ARM64_STATUS.md`: Overall ARM64 status (includes QEMU virt)

**Code Documentation**:
All driver files include comprehensive comments:
- Register layout documentation
- Function-level comments
- Implementation notes

## Hardware Reference

### MacBook Pro A2338 (M2) Specifications
- **SoC**: Apple M2 (t8112)
- **CPU**: 8 cores (4 Avalanche + 4 Blizzard)
- **Interrupt Controller**: Apple AIC (not GICv2)
- **UART**: Samsung s5l-uart @ 0x235200000
- **AIC Base**: 0x23B100000
- **Timer**: ARM Generic Timer (24 MHz, bypasses AIC)
- **Boot**: iBoot → m1n1 → kernel

### Key Differences from QEMU virt

| Component | QEMU virt | Apple M2 |
|-----------|-----------|----------|
| Interrupt Controller | GICv2 @ 0x08000000 | Apple AIC @ 0x23B100000 |
| UART | PL011 @ 0x09000000 | s5l-uart @ 0x235200000 |
| Boot | Direct kernel (-kernel) | iBoot → m1n1 → kernel |
| Timer | ARM Generic Timer | ARM Generic Timer (24 MHz) |
| PCI | ECAM @ 0x10000000 | Custom Apple PCIe |
| Storage | virtio-blk | Apple ANS2 NVMe |
| Display | virtio-gpu | Apple DCP |

## Success Criteria

### Phase 1 (Boot Infrastructure) — ✅ Complete (HW validation pending)
- [x] Device tree detects M1 / M2 / M3 / M4 platform
- [x] AIC driver implemented + dispatch backend wired
- [x] UART console driver (post-MMU putc + pre-MMU MIDR-aware shim)
- [x] m1n1 payload builds (Image header flags = 0xA, relocatable)

### Phase 2 (Storage & Boot) — ✅ Complete (HW validation pending)
- [x] ANS2 NVMe driver — collapsed to thunk over Rust crate
- [x] RTKit IPC (full FFI: boot / endpoint / power state / shutdown)
- [x] Read/write path — DMA addresses now correctly PA-side
- [x] pmgr wired: `apple_pmgr_enable_domains_for(dtb, "/soc/ans...")` runs before NVMe init
- [ ] Boot from storage — future (needs filesystem mount on a Real APFS / ext4 partition)

### Phase 3 (Display & Input) — ✅ Complete (HW validation pending)
- [x] DCP driver wrapped via Rust `apple_dcp` crate
- [x] Framebuffer via m1n1 `/chosen/framebuffer` first-light path
- [x] Keyboard / trackpad via Rust `apple_hid` (SPI + I2C HID parser)

### Phase 4 (Networking & Full System) — ✅ Complete (HW validation pending)
- [x] USB CDC-ECM via xHCI bulk transfers
- [x] xHCI controller wrapped via Rust `apple_xhci` (PCIe-side)
- [ ] WiFi / Bluetooth — long-term, requires Apple WLAN firmware loader

## Conclusion

Apple Silicon support has reached kernel-side feature completeness:

**Phase 1 — Boot Infrastructure: ✅ COMPLETE**
  - Device tree platform detection (M1 / M2 / M3 / M4)
  - Apple AIC interrupt controller (IRQ + FIQ dispatch, timer-via-FIQ)
  - Apple UART (s5l-uart) console with MIDR-aware pre-MMU shim
  - m1n1 payload (ARM64 Linux Image, header flags 0xA, runtime-relocatable)

**Phase 2 — Storage: ✅ COMPLETE**
  - Apple RTKit IPC (HELLO / EPMAP / STARTEP / power state + FFI)
  - Apple ANS2 NVMe (TCB programming, linear submission, DMA PAs)
  - RTKit + ANS2 integration

**Phase 3 — Display + Input: ✅ COMPLETE**
  - Apple DCP wrapper (page alloc + DART map + surface table + RTKit msg builders)
  - m1n1 framebuffer first-light fast-path
  - Apple HID (keyboard SPI / trackpad I2C decoder)

**Phase 4 — Networking: ✅ COMPLETE**
  - USB CDC-ECM driver feeds through `apple_xhci_bulk_transfer`
  - Apple xHCI (full controller bring-up + transfer engine in Rust)

**Driver modularity**:
  - Every `apple_*.c` is a thin Rust thunk over `drivers/rust/apple_*`
  - Runtime platform selection via DTB detection (`info->has_aic`, `info->type == PLATFORM_APPLE_*`)
  - QEMU virt + RPi paths untouched

**Bring-up correctness rounds** (post-driver migration):
  - PA-relocatable boot.S + 48-bit VA + runtime KERN_PA_BASE
  - DAIF.F unmask + critical-section symmetry for FIQ-delivered timer
  - 504 GiB peripheral mapping window covers every Apple Mac SoC SKU
  - DMA address correctness (xhci / ans2 / dcp / dart all feed PAs)
  - Asahi `/soc/<type>@<addr>` DT path fallbacks + walker fix
  - ARM64 Image header relocatable flag

The complete boot-to-storage-to-display sequence is implemented and
QEMU virt selftests pass 2855/2855 across every step — including
201 pre-hardware guard tests covering every public function in 18
Apple driver subsystems (see `docs/APPLE_SILICON_TESTING.md` for
the per-subsystem breakdown).  Real-hardware validation on an
M-series Mac is the next concrete step:

```bash
make m1n1-payload
python3 -m m1n1.run m1n1.macho -b build/m1n1/Image.gz kernel.macho
```

## References

- **Asahi Linux Project**: https://asahilinux.org/
- **m1n1 Bootloader**: https://github.com/AsahiLinux/m1n1
- **Apple AIC Documentation**: https://asahilinux.org/docs/hw/soc/aic/
- **Apple ANS2 NVMe Driver**: Linux kernel `drivers/nvme/host/apple.c` (since 5.19)
- **Device Tree Bindings**: Linux kernel `drivers/*/bindings/arm/apple`
- **Linux Kernel Patches**: LKML archives for "Apple M1 SoC"

---

**Next Action**: Validate on real M-series hardware via `make m1n1-payload`
+ tethered boot.  Triage first divergence from QEMU virt boot log.
