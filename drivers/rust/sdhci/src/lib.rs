// SPDX-License-Identifier: MPL-2.0
//
// sdhci.rs — Polled-mode SDHCI host-controller driver, phase 1.
//
// Target: Intel Apollo Lake / Gemini Lake on-board SD card controller
// (PCI vendor 0x8086, device 0x5ACC / 0x5AC2 / 0x31CC / 0x318C, class
// 08-05-01 = "SD host controller").
//
// Phase 1 scope (this file):
//   - PCI scan for SDHCI controllers (class 08:05:01 OR known device IDs)
//   - Map BAR0 (the SDHCI MMIO register block, 256 bytes)
//   - Read controller version + capability register and log
//   - Software-reset the controller (CMD + DATA lines)
//
// Phase 2 (next round):
//   - Card init sequence (CMD0 / CMD8 / ACMD41 / CMD2 / CMD3 / CMD9 / CMD7)
//   - Single-block PIO write (CMD24)
//   - C-callable sdhci_log_write(buf, len) for the trampoline diagnostic
//
// The driver is polled-mode and IRQ-free so it can be safely called from
// any kernel context — including the post-CR3 trampoline path where
// fb_console output is suspect and we need an alternative log channel.
//
// References:
//   - SD Host Controller Specification 3.00
//   - Intel Apollo Lake / Gemini Lake EDS (LPSS / SDIO host)
//   - Linux drivers/mmc/host/sdhci-pci-core.c

#![no_std]
#![forbid(unsafe_op_in_unsafe_fn)]
#![allow(unexpected_cfgs)]

use core::cell::UnsafeCell;
use core::ffi::c_void;
use common::{log, map_mmio_region, MMIO_DEFAULT_FLAGS};

unsafe extern "C" {
    fn fut_printf(fmt: *const u8, ...);
}

// ── PCI configuration space I/O ──

const PCI_CONFIG_ADDR: u16 = 0x0CF8;
const PCI_CONFIG_DATA: u16 = 0x0CFC;

fn pci_config_addr(bus: u8, dev: u8, func: u8, offset: u8) -> u32 {
    (1u32 << 31)
        | ((bus as u32) << 16)
        | ((dev as u32) << 11)
        | ((func as u32) << 8)
        | ((offset as u32) & 0xFC)
}

fn pci_read32(bus: u8, dev: u8, func: u8, offset: u8) -> u32 {
    let addr = pci_config_addr(bus, dev, func, offset);
    unsafe {
        core::arch::asm!("out dx, eax", in("dx") PCI_CONFIG_ADDR, in("eax") addr);
        let val: u32;
        core::arch::asm!("in eax, dx", in("dx") PCI_CONFIG_DATA, out("eax") val);
        val
    }
}

fn pci_write32(bus: u8, dev: u8, func: u8, offset: u8, val: u32) {
    let addr = pci_config_addr(bus, dev, func, offset);
    unsafe {
        core::arch::asm!("out dx, eax", in("dx") PCI_CONFIG_ADDR, in("eax") addr);
        core::arch::asm!("out dx, eax", in("dx") PCI_CONFIG_DATA, in("eax") val);
    }
}

// ── PCI config-space offsets ──
const PCI_CFG_VENDOR_DEVICE: u8 = 0x00;
const PCI_CFG_COMMAND:       u8 = 0x04;
const PCI_CFG_REVCLASS:      u8 = 0x08;  /* Revision (8) | ClassCode (24) */
const PCI_CFG_HEADER_TYPE:   u8 = 0x0C;  /* upper byte of dword: header type */
const PCI_CFG_BAR0_LO:       u8 = 0x10;
const PCI_CFG_BAR0_HI:       u8 = 0x14;

const PCI_VENDOR_INTEL: u16 = 0x8086;
const PCI_CLASS_SD_HOST: u32 = 0x080501;
const PCI_CLASS_EMMC:    u32 = 0x080500;

// ── SDHCI register offsets (SD Host Controller Spec 3.00) ──
const SDHCI_DMA_ADDRESS:        u32 = 0x00;
const SDHCI_BLOCK_SIZE:         u32 = 0x04;
const SDHCI_BLOCK_COUNT:        u32 = 0x06;
const SDHCI_ARGUMENT:           u32 = 0x08;
const SDHCI_TRANSFER_MODE:      u32 = 0x0C;
const SDHCI_COMMAND:            u32 = 0x0E;
const SDHCI_RESPONSE:           u32 = 0x10;  /* 16 bytes */
const SDHCI_BUFFER:             u32 = 0x20;
const SDHCI_PRESENT_STATE:      u32 = 0x24;
const SDHCI_HOST_CONTROL:       u32 = 0x28;
const SDHCI_POWER_CONTROL:      u32 = 0x29;
const SDHCI_CLOCK_CONTROL:      u32 = 0x2C;
const SDHCI_TIMEOUT_CONTROL:    u32 = 0x2E;
const SDHCI_SOFTWARE_RESET:     u32 = 0x2F;
const SDHCI_INT_STATUS:         u32 = 0x30;
const SDHCI_INT_ENABLE:         u32 = 0x34;
const SDHCI_SIGNAL_ENABLE:      u32 = 0x38;
const SDHCI_CAPABILITIES:       u32 = 0x40;
const SDHCI_HOST_VERSION:       u32 = 0xFE;

const SDHCI_RESET_ALL:  u8 = 0x01;
const SDHCI_RESET_CMD:  u8 = 0x02;
const SDHCI_RESET_DATA: u8 = 0x04;

const SDHCI_PRESENT_CARD_INSERTED:    u32 = 1 << 16;
const SDHCI_PRESENT_CARD_STATE_STABLE: u32 = 1 << 17;

// ── Driver state ──

#[repr(C)]
struct SdhciState {
    pub initialized:   bool,
    pub bus:           u8,
    pub dev:           u8,
    pub func:          u8,
    pub vendor_id:     u16,
    pub device_id:     u16,
    pub bar0_phys:     u64,
    pub mmio_base:     *mut u8,
    pub mmio_size:     usize,
    pub host_version:  u16,
    pub capabilities:  u64,
    pub card_inserted: bool,
}

struct StaticCell<T>(UnsafeCell<T>);
unsafe impl<T> Sync for StaticCell<T> {}
impl<T> StaticCell<T> {
    const fn new(v: T) -> Self { Self(UnsafeCell::new(v)) }
    fn get(&self) -> *mut T { self.0.get() }
}

unsafe impl Send for SdhciState {}
unsafe impl Sync for SdhciState {}

static STATE: StaticCell<SdhciState> = StaticCell::new(SdhciState {
    initialized:   false,
    bus:           0,
    dev:           0,
    func:          0,
    vendor_id:     0,
    device_id:     0,
    bar0_phys:     0,
    mmio_base:     core::ptr::null_mut(),
    mmio_size:     0,
    host_version:  0,
    capabilities:  0,
    card_inserted: false,
});

#[inline(always)]
unsafe fn r8(base: *const u8, offset: u32) -> u8 {
    unsafe { core::ptr::read_volatile(base.add(offset as usize)) }
}
#[inline(always)]
unsafe fn r16(base: *const u8, offset: u32) -> u16 {
    unsafe { core::ptr::read_volatile(base.add(offset as usize) as *const u16) }
}
#[inline(always)]
unsafe fn r32(base: *const u8, offset: u32) -> u32 {
    unsafe { core::ptr::read_volatile(base.add(offset as usize) as *const u32) }
}
#[inline(always)]
unsafe fn r64(base: *const u8, offset: u32) -> u64 {
    unsafe { core::ptr::read_volatile(base.add(offset as usize) as *const u64) }
}
#[inline(always)]
unsafe fn w8(base: *mut u8, offset: u32, val: u8) {
    unsafe { core::ptr::write_volatile(base.add(offset as usize), val) }
}

// ── PCI scan ──

/// Find a candidate SDHCI controller by class code (preferred) or
/// known Intel device ID. Scans bus 0 only — multi-bus systems would
/// need to walk PCI bridges, but the on-SoC SD controllers we care
/// about live on bus 0.
fn find_sdhci() -> Option<(u8, u8, u8, u16, u16, u32)> {
    for dev in 0u8..32 {
        for func in 0u8..8 {
            let vendor_device = pci_read32(0, dev, func, PCI_CFG_VENDOR_DEVICE);
            let vendor = (vendor_device & 0xFFFF) as u16;
            if vendor == 0xFFFF || vendor == 0x0000 {
                if func == 0 { break; } else { continue; }
            }
            let device = (vendor_device >> 16) as u16;
            let revclass = pci_read32(0, dev, func, PCI_CFG_REVCLASS);
            let class = revclass >> 8;  /* class:subclass:progif */

            let class_match = class == PCI_CLASS_SD_HOST
                           || class == PCI_CLASS_EMMC;
            let intel_sdhci = vendor == PCI_VENDOR_INTEL
                           && (device == 0x5ACC || device == 0x5AC2
                               || device == 0x31CC || device == 0x318C
                               || device == 0x9D2B || device == 0x9D2D);

            if class_match || intel_sdhci {
                return Some((0, dev, func, vendor, device, class));
            }

            /* Stop probing functions on a single-function device. */
            if func == 0 {
                let header = pci_read32(0, dev, func, PCI_CFG_HEADER_TYPE);
                let multi_func = ((header >> 16) & 0x80) != 0;
                if !multi_func { break; }
            }
        }
    }
    None
}

// ── Public C API ──

/// Probe the SDHCI controller, map BAR0, log version + capabilities,
/// and software-reset the controller. Phase 1: no card is initialized
/// here. Returns 0 on success, negative on failure.
#[unsafe(no_mangle)]
pub extern "C" fn sdhci_init() -> i32 {
    log("sdhci: scanning PCI bus 0 for SD/MMC controller");

    let (bus, dev, func, vendor, device, class) = match find_sdhci() {
        Some(v) => v,
        None => {
            log("sdhci: no SD/MMC controller found on PCI bus 0");
            return -1;
        }
    };

    unsafe {
        fut_printf(
            b"sdhci: found controller at %02x:%02x.%x vendor=0x%04x device=0x%04x class=0x%06x\n\0".as_ptr(),
            bus as u32, dev as u32, func as u32,
            vendor as u32, device as u32, class,
        );
    }

    // Read BAR0 — SDHCI MMIO is a 32-bit or 64-bit memory BAR. The
    // SDHCI register set is only 256 bytes; we map a page for safety.
    let bar0_lo = pci_read32(bus, dev, func, PCI_CFG_BAR0_LO);
    let bar0_phys: u64 = if (bar0_lo & 0x07) & 0x04 != 0 {
        let bar0_hi = pci_read32(bus, dev, func, PCI_CFG_BAR0_HI);
        ((bar0_hi as u64) << 32) | ((bar0_lo as u64) & !0x0Fu64)
    } else {
        (bar0_lo as u64) & !0x0Fu64
    };

    if bar0_phys == 0 {
        log("sdhci: BAR0 not programmed by firmware — skipping");
        return -2;
    }

    unsafe {
        fut_printf(
            b"sdhci: BAR0 phys=0x%llx (%s)\n\0".as_ptr(),
            bar0_phys,
            if bar0_lo & 0x04 != 0 { b"64-bit\0".as_ptr() } else { b"32-bit\0".as_ptr() },
        );
    }

    // Enable PCI memory-space decoding + bus master, in case the firmware
    // left them disabled.
    let mut cmd = pci_read32(bus, dev, func, PCI_CFG_COMMAND) & 0xFFFF;
    if (cmd & 0x0006) != 0x0006 {
        cmd |= 0x0006;
        pci_write32(bus, dev, func, PCI_CFG_COMMAND, cmd);
        unsafe {
            fut_printf(
                b"sdhci: enabled PCI memory + bus-master (cmd now 0x%04x)\n\0".as_ptr(),
                cmd,
            );
        }
    }

    const SDHCI_MMIO_SIZE: usize = 4096;
    let mmio = unsafe { map_mmio_region(bar0_phys, SDHCI_MMIO_SIZE, MMIO_DEFAULT_FLAGS) };
    if mmio.is_null() {
        log("sdhci: failed to map BAR0");
        return -3;
    }

    let host_version = unsafe { r16(mmio, SDHCI_HOST_VERSION) };
    let capabilities = unsafe { r64(mmio, SDHCI_CAPABILITIES) };
    let present = unsafe { r32(mmio, SDHCI_PRESENT_STATE) };
    let card_inserted = (present & SDHCI_PRESENT_CARD_INSERTED) != 0;

    let spec_ver = host_version & 0xFF;
    let vendor_ver = (host_version >> 8) & 0xFF;
    unsafe {
        fut_printf(
            b"sdhci: host_version=0x%04x (spec=%u vendor=%u) capabilities=0x%llx\n\0".as_ptr(),
            host_version as u32, spec_ver as u32, vendor_ver as u32,
            capabilities,
        );
        fut_printf(
            b"sdhci: present_state=0x%08x card_%s\n\0".as_ptr(),
            present,
            if card_inserted {
                b"INSERTED\0".as_ptr()
            } else {
                b"absent\0".as_ptr()
            },
        );
    }

    // Software-reset CMD + DATA lines (not the full ALL reset, which
    // also tosses host-controller state we'd then need to re-program).
    // Phase 2 will do RESET_ALL when it sets up clocks/power for card
    // init. For phase 1 we only want to prove we can drive the regs.
    let reset_mask = SDHCI_RESET_CMD | SDHCI_RESET_DATA;
    unsafe { w8(mmio, SDHCI_SOFTWARE_RESET, reset_mask) };

    let mut drained = false;
    for _ in 0..1_000_000 {
        let r = unsafe { r8(mmio, SDHCI_SOFTWARE_RESET) };
        if (r & reset_mask) == 0 {
            drained = true;
            break;
        }
    }
    if !drained {
        log("sdhci: CMD/DATA reset did not clear within 1M polls");
        return -4;
    }

    let st = STATE.get();
    unsafe {
        (*st).bus = bus;
        (*st).dev = dev;
        (*st).func = func;
        (*st).vendor_id = vendor;
        (*st).device_id = device;
        (*st).bar0_phys = bar0_phys;
        (*st).mmio_base = mmio;
        (*st).mmio_size = SDHCI_MMIO_SIZE;
        (*st).host_version = host_version;
        (*st).capabilities = capabilities;
        (*st).card_inserted = card_inserted;
        (*st).initialized = true;
    }

    log("sdhci: phase 1 complete (PCI detect + BAR map + CMD/DATA reset)");
    0
}

/// Returns true once sdhci_init has detected and mapped the controller.
#[unsafe(no_mangle)]
pub extern "C" fn sdhci_is_initialized() -> bool {
    let st = STATE.get();
    unsafe { (*st).initialized }
}

/// Returns true if a card is present according to the controller's
/// PRESENT_STATE register. Re-read on each call since hot-insert can
/// change this.
#[unsafe(no_mangle)]
pub extern "C" fn sdhci_card_present() -> bool {
    let st = STATE.get();
    if !unsafe { (*st).initialized } {
        return false;
    }
    let mmio = unsafe { (*st).mmio_base };
    if mmio.is_null() {
        return false;
    }
    let present = unsafe { r32(mmio, SDHCI_PRESENT_STATE) };
    (present & SDHCI_PRESENT_CARD_INSERTED) != 0
}

// ── Phase 2: Card init + single-block PIO write + log API ──

#[inline(always)]
unsafe fn w16(base: *mut u8, offset: u32, val: u16) {
    unsafe { core::ptr::write_volatile(base.add(offset as usize) as *mut u16, val) }
}
#[inline(always)]
unsafe fn w32(base: *mut u8, offset: u32, val: u32) {
    unsafe { core::ptr::write_volatile(base.add(offset as usize) as *mut u32, val) }
}

// Clock-control register fields (offset 0x2C, 16-bit)
const SDHCI_CLOCK_INT_EN:     u16 = 1 << 0;
const SDHCI_CLOCK_INT_STABLE: u16 = 1 << 1;
const SDHCI_CLOCK_SD_EN:      u16 = 1 << 2;

// Power-control register (offset 0x29, 8-bit)
const SDHCI_POWER_ON:         u8 = 1 << 0;
const SDHCI_POWER_330:        u8 = 0b111 << 1;  /* 3.3V */

// Command-register fields (offset 0x0E, 16-bit). Format:
//   [15:8] command index, [5:0] flags + response type
const SDHCI_CMD_RESP_NONE:    u16 = 0;
const SDHCI_CMD_RESP_R136:    u16 = 1;  /* 136-bit (CMD2, CMD9) */
const SDHCI_CMD_RESP_R48:     u16 = 2;
const SDHCI_CMD_RESP_R48_BUSY: u16 = 3;
const SDHCI_CMD_CRC_CHECK:    u16 = 1 << 3;
const SDHCI_CMD_INDEX_CHECK:  u16 = 1 << 4;
const SDHCI_CMD_DATA:         u16 = 1 << 5;

// Transfer-mode register (offset 0x0C, 16-bit)
const SDHCI_TM_READ:          u16 = 1 << 4;
const SDHCI_TM_BLOCK_COUNT_EN: u16 = 1 << 1;

// Interrupt status bits (offset 0x30, 32-bit)
const SDHCI_INT_CMD_COMPLETE: u32 = 1 << 0;
const SDHCI_INT_XFER_COMPLETE: u32 = 1 << 1;
const SDHCI_INT_BUF_WR_READY: u32 = 1 << 4;
const SDHCI_INT_ERROR:        u32 = 1 << 15;

// Present-state bits we use (offset 0x24, 32-bit)
const SDHCI_PS_CMD_INHIBIT:    u32 = 1 << 0;
const SDHCI_PS_DAT_INHIBIT:    u32 = 1 << 1;

// Encode the upper byte (cmd index) + lower flags into one 16-bit word.
fn make_cmd(index: u32, flags: u16) -> u16 {
    ((index & 0x3F) as u16) << 8 | (flags & 0x3F)
}

/// Wait for CMD_INHIBIT to clear so we can issue a new command.
fn wait_cmd_ready(mmio: *const u8) -> bool {
    for _ in 0..2_000_000 {
        let ps = unsafe { r32(mmio, SDHCI_PRESENT_STATE) };
        if ps & SDHCI_PS_CMD_INHIBIT == 0 {
            return true;
        }
    }
    false
}

/// Wait for both CMD and DAT inhibit to clear (needed before a data
/// command).
fn wait_cmd_dat_ready(mmio: *const u8) -> bool {
    for _ in 0..2_000_000 {
        let ps = unsafe { r32(mmio, SDHCI_PRESENT_STATE) };
        if ps & (SDHCI_PS_CMD_INHIBIT | SDHCI_PS_DAT_INHIBIT) == 0 {
            return true;
        }
    }
    false
}

/// Issue a command and wait for CMD_COMPLETE. Caller is responsible
/// for setting BLOCK_SIZE/COUNT and TRANSFER_MODE before this for
/// data commands. Returns the lower 32 bits of the response (R1/R3/
/// R6/R7) on success, or i64::MIN on error/timeout.
fn issue_cmd(mmio_ro: *const u8, mmio_rw: *mut u8,
             index: u32, arg: u32,
             flags: u16, is_data: bool) -> i64 {
    let ready = if is_data {
        wait_cmd_dat_ready(mmio_ro)
    } else {
        wait_cmd_ready(mmio_ro)
    };
    if !ready {
        return i64::MIN;
    }

    // Clear interrupt status first.
    unsafe { w32(mmio_rw, SDHCI_INT_STATUS, 0xFFFFFFFF) };

    unsafe {
        w32(mmio_rw, SDHCI_ARGUMENT, arg);
        w16(mmio_rw, SDHCI_COMMAND, make_cmd(index, flags));
    }

    // Poll INT_STATUS for CMD_COMPLETE or ERROR.
    let mut status = 0u32;
    let mut done = false;
    for _ in 0..2_000_000 {
        status = unsafe { r32(mmio_ro, SDHCI_INT_STATUS) };
        if status & (SDHCI_INT_CMD_COMPLETE | SDHCI_INT_ERROR) != 0 {
            done = true;
            break;
        }
    }
    if !done || (status & SDHCI_INT_ERROR) != 0 {
        return i64::MIN;
    }

    // Ack CMD_COMPLETE.
    unsafe { w32(mmio_rw, SDHCI_INT_STATUS, SDHCI_INT_CMD_COMPLETE) };

    unsafe { r32(mmio_ro, SDHCI_RESPONSE) as i64 }
}

/// Configure clock divider for ~400 kHz initial-state clock. The base
/// clock comes from CAPABILITIES bits [13:8]. We divide by N (placed
/// in CLOCK_CONTROL bits [15:8] for 10-bit divider; 8-bit on v2.0).
/// Then enable internal clock, wait stable, enable SD clock to card.
fn setup_clock(mmio_ro: *const u8, mmio_rw: *mut u8, caps: u64) {
    let base_clock_mhz = ((caps >> 8) & 0xFF) as u32;
    let base_clock_hz = base_clock_mhz * 1_000_000;
    let target_hz = 400_000u32;

    // Divisor: floor(base / (2 * target)). Clamped to 1..=0x80.
    let mut div: u32 = if base_clock_hz > 0 && target_hz > 0 {
        base_clock_hz / (target_hz * 2)
    } else {
        1
    };
    if div == 0 { div = 1; }
    if div > 0x80 { div = 0x80; }

    // Encode divisor in CLOCK_CONTROL bits [15:8] (8-bit SDHCI 2.0
    // encoding is "div / 2 in bits [15:8]"; we use the simpler form).
    let div_byte = (div & 0xFF) as u16;
    let clk = (div_byte << 8) | SDHCI_CLOCK_INT_EN;
    unsafe { w16(mmio_rw, SDHCI_CLOCK_CONTROL, clk) };

    // Wait for internal clock stable.
    for _ in 0..1_000_000 {
        let r = unsafe { r16(mmio_ro, SDHCI_CLOCK_CONTROL) };
        if r & SDHCI_CLOCK_INT_STABLE != 0 { break; }
    }

    // Enable SD clock output to the card.
    let clk2 = clk | SDHCI_CLOCK_SD_EN;
    unsafe { w16(mmio_rw, SDHCI_CLOCK_CONTROL, clk2) };
}

/// Power up the SD card at 3.3 V.
fn setup_power(mmio_rw: *mut u8) {
    unsafe { w8(mmio_rw, SDHCI_POWER_CONTROL, SDHCI_POWER_330) };
    // Tiny settle delay (just MMIO reads, no IRQ involvement).
    for _ in 0..10_000 {
        let _ = unsafe { core::ptr::read_volatile(mmio_rw.add(SDHCI_POWER_CONTROL as usize)) };
    }
    unsafe { w8(mmio_rw, SDHCI_POWER_CONTROL, SDHCI_POWER_330 | SDHCI_POWER_ON) };
}

/// SD card init: CMD0 / CMD8 / ACMD41 / CMD2 / CMD3 / CMD7. Stores
/// the assigned RCA in I915State.rca_unused (we add a new field).
/// Returns 0 on success, negative on failure.
fn sd_card_init(mmio_ro: *const u8, mmio_rw: *mut u8) -> Result<u32, i32> {
    // CMD0: GO_IDLE_STATE. No response.
    let _ = issue_cmd(mmio_ro, mmio_rw, 0, 0, SDHCI_CMD_RESP_NONE, false);

    // CMD8: SEND_IF_COND. Voltage 2.7-3.6V (0x100), check pattern 0xAA.
    let cmd8_arg = 0x1AAu32;
    let r = issue_cmd(mmio_ro, mmio_rw, 8, cmd8_arg,
                      SDHCI_CMD_RESP_R48 | SDHCI_CMD_CRC_CHECK | SDHCI_CMD_INDEX_CHECK,
                      false);
    let is_sdv2 = r != i64::MIN && (r as u32 & 0xFF) == 0xAA;

    // ACMD41 loop: CMD55 + ACMD41 until card returns ready.
    let acmd41_arg = if is_sdv2 { 0x4030_0000u32 } else { 0x0030_0000u32 };
    let mut ocr: u32 = 0;
    let mut ok = false;
    for _ in 0..1000 {
        let _ = issue_cmd(mmio_ro, mmio_rw, 55, 0,
                          SDHCI_CMD_RESP_R48 | SDHCI_CMD_CRC_CHECK | SDHCI_CMD_INDEX_CHECK,
                          false);
        let r = issue_cmd(mmio_ro, mmio_rw, 41, acmd41_arg,
                          SDHCI_CMD_RESP_R48, false);
        if r == i64::MIN { continue; }
        ocr = r as u32;
        if ocr & 0x8000_0000 != 0 { ok = true; break; }
        for _ in 0..50_000 {
            let _ = unsafe { r32(mmio_ro, SDHCI_PRESENT_STATE) };
        }
    }
    if !ok { return Err(-101); }

    // CMD2: ALL_SEND_CID. R2 (136-bit).
    let _ = issue_cmd(mmio_ro, mmio_rw, 2, 0,
                      SDHCI_CMD_RESP_R136 | SDHCI_CMD_CRC_CHECK,
                      false);

    // CMD3: SEND_RELATIVE_ADDR. R6 returns RCA in upper 16 bits.
    let r = issue_cmd(mmio_ro, mmio_rw, 3, 0,
                      SDHCI_CMD_RESP_R48 | SDHCI_CMD_CRC_CHECK | SDHCI_CMD_INDEX_CHECK,
                      false);
    if r == i64::MIN { return Err(-103); }
    let rca = ((r as u32) >> 16) & 0xFFFF;

    // CMD9: SEND_CSD with RCA. R2 (136-bit). We skip parsing for now.
    let _ = issue_cmd(mmio_ro, mmio_rw, 9, rca << 16,
                      SDHCI_CMD_RESP_R136 | SDHCI_CMD_CRC_CHECK,
                      false);

    // CMD7: SELECT_CARD with RCA. R1b (with busy).
    let r = issue_cmd(mmio_ro, mmio_rw, 7, rca << 16,
                      SDHCI_CMD_RESP_R48_BUSY | SDHCI_CMD_CRC_CHECK | SDHCI_CMD_INDEX_CHECK,
                      false);
    if r == i64::MIN { return Err(-107); }

    Ok(rca)
}

static mut SDHCI_RCA: u32 = 0;
static mut SDHCI_CARD_READY: bool = false;

/// Phase 2 entry point: power+clock the controller, run SD card init,
/// stash the RCA. Returns 0 on success. Call after sdhci_init.
#[unsafe(no_mangle)]
pub extern "C" fn sdhci_card_init() -> i32 {
    let st = STATE.get();
    if !unsafe { (*st).initialized } {
        log("sdhci_card_init: controller not initialized");
        return -1;
    }
    let mmio = unsafe { (*st).mmio_base };
    if mmio.is_null() { return -2; }
    if !unsafe { (*st).card_inserted } {
        log("sdhci_card_init: no card present at probe");
        return -3;
    }

    let caps = unsafe { (*st).capabilities };
    setup_power(mmio);
    setup_clock(mmio, mmio, caps);

    match sd_card_init(mmio, mmio) {
        Ok(rca) => {
            unsafe { fut_printf(b"sdhci: SD card initialized; RCA=0x%04x\n\0".as_ptr(), rca); }
            unsafe {
                core::ptr::write(core::ptr::addr_of_mut!(SDHCI_RCA), rca);
                core::ptr::write(core::ptr::addr_of_mut!(SDHCI_CARD_READY), true);
            }
            0
        }
        Err(rc) => {
            unsafe { fut_printf(b"sdhci: SD card init failed: %d\n\0".as_ptr(), rc); }
            rc
        }
    }
}

/// Single-block PIO write to LBA `lba` from a 512-byte buffer.
/// CMD24 (WRITE_BLOCK). Returns 0 on success.
#[unsafe(no_mangle)]
pub extern "C" fn sdhci_write_block(lba: u32, buf: *const u8) -> i32 {
    if !unsafe { core::ptr::read(core::ptr::addr_of!(SDHCI_CARD_READY)) } { return -1; }
    if buf.is_null() { return -2; }
    let st = STATE.get();
    let mmio = unsafe { (*st).mmio_base };
    if mmio.is_null() { return -3; }

    // BLOCK_SIZE = 512, BLOCK_COUNT = 1, TRANSFER_MODE = write (READ=0).
    unsafe {
        w16(mmio, SDHCI_BLOCK_SIZE, 512);
        w16(mmio, SDHCI_BLOCK_COUNT, 1);
        w16(mmio, SDHCI_TRANSFER_MODE, 0);  /* write, no-DMA */
    }

    let r = issue_cmd(mmio, mmio, 24, lba,
                      SDHCI_CMD_RESP_R48 | SDHCI_CMD_CRC_CHECK |
                      SDHCI_CMD_INDEX_CHECK | SDHCI_CMD_DATA,
                      true);
    if r == i64::MIN { return -4; }

    // Wait for BUFFER_WRITE_READY then PIO-write 512 bytes as DWORDs.
    let mut ready = false;
    for _ in 0..2_000_000 {
        let status = unsafe { r32(mmio, SDHCI_INT_STATUS) };
        if status & SDHCI_INT_ERROR != 0 { return -5; }
        if status & SDHCI_INT_BUF_WR_READY != 0 { ready = true; break; }
    }
    if !ready { return -6; }
    unsafe { w32(mmio, SDHCI_INT_STATUS, SDHCI_INT_BUF_WR_READY) };

    for i in 0..128 {  /* 128 DWORDs = 512 bytes */
        let off = i * 4;
        let dw = unsafe {
            (*buf.add(off) as u32)
            | ((*buf.add(off + 1) as u32) << 8)
            | ((*buf.add(off + 2) as u32) << 16)
            | ((*buf.add(off + 3) as u32) << 24)
        };
        unsafe { w32(mmio, SDHCI_BUFFER, dw) };
    }

    // Wait for XFER_COMPLETE.
    let mut done = false;
    for _ in 0..2_000_000 {
        let status = unsafe { r32(mmio, SDHCI_INT_STATUS) };
        if status & SDHCI_INT_ERROR != 0 { return -7; }
        if status & SDHCI_INT_XFER_COMPLETE != 0 { done = true; break; }
    }
    if !done { return -8; }
    unsafe { w32(mmio, SDHCI_INT_STATUS, SDHCI_INT_XFER_COMPLETE) };

    0
}

/// Append a message to the SD-card log block. We reserve LBA `lba_base`
/// for the log; each call rewrites the entire block with the prior
/// content plus the new message, NUL-padded. ~1 KB total log capacity
/// (we use 2 blocks). Crude but enough for post-CR3 breadcrumbs.
static mut LOG_LBA_BASE: u32 = 8192;  /* 4 MiB into card; far from FS metadata */
static mut LOG_BUF: [u8; 1024] = [0; 1024];
static mut LOG_USED: usize = 0;

#[unsafe(no_mangle)]
pub extern "C" fn sdhci_log_set_lba(lba: u32) {
    unsafe { core::ptr::write(core::ptr::addr_of_mut!(LOG_LBA_BASE), lba); }
}

#[unsafe(no_mangle)]
pub extern "C" fn sdhci_log_write(msg: *const u8, len: usize) -> i32 {
    if !unsafe { core::ptr::read(core::ptr::addr_of!(SDHCI_CARD_READY)) } { return -1; }
    if msg.is_null() || len == 0 { return 0; }

    let buf_ptr: *mut u8 = unsafe { core::ptr::addr_of_mut!(LOG_BUF) as *mut u8 };
    let buf_cap: usize = unsafe { (*core::ptr::addr_of!(LOG_BUF)).len() };
    let used: usize = unsafe { core::ptr::read(core::ptr::addr_of!(LOG_USED)) };
    let space = buf_cap.saturating_sub(used);
    let copy_len = if len > space { space } else { len };

    unsafe {
        for i in 0..copy_len {
            core::ptr::write(buf_ptr.add(used + i), *msg.add(i));
        }
        core::ptr::write(core::ptr::addr_of_mut!(LOG_USED), used + copy_len);
    }

    // Flush both 512-byte halves back to the card on every call.
    // Slow but reliable; trampoline only logs a handful of times.
    let lba_base = unsafe { core::ptr::read(core::ptr::addr_of!(LOG_LBA_BASE)) };
    unsafe {
        let rc = sdhci_write_block(lba_base,     buf_ptr);
        if rc != 0 { return rc; }
        let rc = sdhci_write_block(lba_base + 1, buf_ptr.add(512));
        if rc != 0 { return rc; }
    }
    0
}
