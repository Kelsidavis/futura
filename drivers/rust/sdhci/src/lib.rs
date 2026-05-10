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
