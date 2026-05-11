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
const PCI_CFG_STATUS_HI:     u8 = 0x06;  /* status (16) — bit 4 = caps list */
const PCI_CFG_REVCLASS:      u8 = 0x08;  /* Revision (8) | ClassCode (24) */
const PCI_CFG_HEADER_TYPE:   u8 = 0x0C;  /* upper byte of dword: header type */
const PCI_CFG_BAR0_LO:       u8 = 0x10;
const PCI_CFG_BAR0_HI:       u8 = 0x14;
const PCI_CFG_CAP_PTR:       u8 = 0x34;  /* pointer to PCI capability list */
const PCI_CAP_ID_PM:         u8 = 0x01;  /* Power Management capability */

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

/// Class-08 (mass storage) PCI hits seen during sdhci_init's scan.
/// Used by sdhci_dump_status to re-emit the scan results right above
/// the trampoline cliff (without this the scan output scrolls past
/// before the user can see it).
#[derive(Copy, Clone)]
#[repr(C)]
struct PciHit {
    dev: u8, func: u8, vendor: u16, device: u16, class: u32,
}
static MASS_STORAGE_HITS: StaticCell<[PciHit; 8]> = StaticCell::new(
    [PciHit { dev: 0, func: 0, vendor: 0, device: 0, class: 0 }; 8]);
static MASS_STORAGE_COUNT: StaticCell<u32> = StaticCell::new(0);

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

/// Find a candidate SDHCI controller by PCI class code 08:05:xx
/// (mass storage / SD host). We deliberately do NOT match on Intel
/// device IDs — many similar-looking Intel LPSS device IDs (I2C,
/// SPI, UART) accidentally collided with previous device-ID lists
/// and we'd "initialize" the wrong chip. Class code is authoritative.
///
/// As a side-effect, prints every class-08 (mass storage) device
/// found on bus 0, so when nothing matches the user can see what
/// IS actually on the SoC.
fn find_sdhci() -> Option<(u8, u8, u8, u16, u16, u32)> {
    let mut found_any = false;
    let mut hit: Option<(u8, u8, u8, u16, u16, u32)> = None;
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

            // Log every mass-storage class device for diagnostics.
            if (class >> 16) == 0x08 {
                found_any = true;
                unsafe {
                    fut_printf(
                        b"sdhci-scan: %02x:%02x.%x vendor=0x%04x device=0x%04x class=0x%06x\n\0".as_ptr(),
                        0u32, dev as u32, func as u32,
                        vendor as u32, device as u32, class,
                    );
                }
                // Also stash for sdhci_dump_status to re-emit later.
                let count_p = MASS_STORAGE_COUNT.get();
                unsafe {
                    let n = *count_p as usize;
                    if n < 8 {
                        let hits = MASS_STORAGE_HITS.get();
                        (*hits)[n] = PciHit { dev, func, vendor, device, class };
                        *count_p = (n + 1) as u32;
                    }
                }
            }

            // Strict match: SD host or eMMC class only.
            if hit.is_none() && (class == PCI_CLASS_SD_HOST || class == PCI_CLASS_EMMC) {
                hit = Some((0, dev, func, vendor, device, class));
            }

            /* Stop probing functions on a single-function device. */
            if func == 0 {
                let header = pci_read32(0, dev, func, PCI_CFG_HEADER_TYPE);
                let multi_func = ((header >> 16) & 0x80) != 0;
                if !multi_func { break; }
            }
        }
    }
    if !found_any {
        log("sdhci-scan: no class-0x08 (mass storage) devices on bus 0");
    }
    hit
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

    // Walk the PCI capability list and force the device to D0 power
    // state. Apollo Lake / Gemini Lake LPSS SD controllers may have
    // been left in D3hot by firmware; in that state MMIO registers
    // read back as zero (which is exactly what iter-61 showed).
    let status = (pci_read32(bus, dev, func, PCI_CFG_STATUS_HI & !3) >> 16) as u16;
    if status & (1 << 4) != 0 {
        let mut cap = (pci_read32(bus, dev, func, PCI_CFG_CAP_PTR) & 0xFC) as u8;
        for _ in 0..32 {  /* bound the walk */
            if cap == 0 { break; }
            let cap_dw = pci_read32(bus, dev, func, cap & !3);
            let id = (cap_dw & 0xFF) as u8;
            let next = ((cap_dw >> 8) & 0xFC) as u8;
            if id == PCI_CAP_ID_PM {
                let pmcsr_off = cap.wrapping_add(4);
                let mut pmcsr = pci_read32(bus, dev, func, pmcsr_off & !3);
                let cur_state = pmcsr & 0x3;
                if cur_state != 0 {
                    pmcsr = (pmcsr & !0x3) | 0;  /* D0 */
                    pci_write32(bus, dev, func, pmcsr_off & !3, pmcsr);
                    unsafe {
                        fut_printf(
                            b"sdhci: forced PCI power state D%u -> D0\n\0".as_ptr(),
                            cur_state,
                        );
                    }
                } else {
                    unsafe {
                        fut_printf(b"sdhci: PCI already in D0\n\0".as_ptr());
                    }
                }
                break;
            }
            cap = next;
        }
    }

    const SDHCI_MMIO_SIZE: usize = 4096;
    let mmio = unsafe { map_mmio_region(bar0_phys, SDHCI_MMIO_SIZE, MMIO_DEFAULT_FLAGS) };
    if mmio.is_null() {
        log("sdhci: failed to map BAR0");
        return -3;
    }

    // Intel LPSS controllers (Apollo/Gemini Lake) have private
    // registers at BAR0 offsets 0x800+ that gate the standard SDHCI
    // register block. The PRV_RESET register at 0x804 holds three
    // reset bits (DMA, controller, IDMAC); set all three to 1 to
    // release reset and bring the standard SDHCI registers online.
    // Without this, HOST_VERSION / CAPABILITIES / PRESENT_STATE all
    // read as zero (which is what iter-61 actually showed).
    if vendor == PCI_VENDOR_INTEL {
        const LPSS_PRV_RESET: u32 = 0x804;
        const LPSS_PRV_RESET_RELEASE_ALL: u32 = 0x07;
        let prev = unsafe { r32(mmio, LPSS_PRV_RESET) };
        unsafe { core::ptr::write_volatile(
            mmio.add(LPSS_PRV_RESET as usize) as *mut u32,
            LPSS_PRV_RESET_RELEASE_ALL,
        ) };
        for _ in 0..100_000 {
            let _ = unsafe { r32(mmio, LPSS_PRV_RESET) };
        }
        let after = unsafe { r32(mmio, LPSS_PRV_RESET) };
        unsafe {
            fut_printf(
                b"sdhci: LPSS PRV_RESET 0x%x -> wrote 0x%x -> 0x%x\n\0".as_ptr(),
                prev, LPSS_PRV_RESET_RELEASE_ALL, after,
            );
        }
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
/// 100K-read cap = ~10 ms on real MMIO; plenty of headroom for a
/// well-behaved controller, fast-fail otherwise.
fn wait_cmd_ready(mmio: *const u8) -> bool {
    for _ in 0..100_000 {
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
    for _ in 0..100_000 {
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

    // Poll INT_STATUS for CMD_COMPLETE or ERROR. Tight cap; if the
    // controller doesn't respond within 100K reads (~10 ms) something
    // is wrong with this command, not our overall protocol.
    let mut status = 0u32;
    let mut done = false;
    for _ in 0..100_000 {
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

/// Configure clock divider for ~400 kHz initial-state clock.
///
/// SDHCI 2.00 SDCLK Frequency Select (bits 15:8 of CLOCK_CONTROL)
/// is *exponential*: at most ONE bit may be set, and the resulting
/// SDCLK = base / (2 * reg_value). Legal register values:
///   0x00  = no divide   (= base)
///   0x01  = /2
///   0x02  = /4
///   0x04  = /8
///   0x08  = /16
///   0x10  = /32
///   0x20  = /64
///   0x40  = /128
///   0x80  = /256
/// Writing a linear value like 10 (0x0A = bits 1+3) violates the
/// "one bit set" rule and the controller silently emits no SDCLK,
/// which leaves the card powered but unclocked → ACMD41 never sees
/// the ready bit (exactly what iter-65 hit).
///
/// Pick the smallest legal register value that drops SDCLK below
/// 400 kHz, capped at 0x80 (the slowest divide). Then enable the
/// internal clock, wait for INT_STABLE, enable the SDCLK output, and
/// hold for at least 74 SDCLK cycles before the caller issues CMD0
/// (SDHCI 2.00 §3.3 "Bus Power-On Sequence").
fn setup_clock(mmio_ro: *const u8, mmio_rw: *mut u8, caps: u64) {
    // For SDHCI 2.0, base clock freq lives in CAPS[13:8] (6 bits, max
    // 63 MHz). For SDHCI 3.0 it would be CAPS[15:8] (8 bits). Use the
    // 6-bit field — the host_version on this hw is 0x1002 (spec=2).
    let base_clock_mhz = ((caps >> 8) & 0x3F) as u32;
    let base_clock_hz = base_clock_mhz.saturating_mul(1_000_000);
    let target_hz = 400_000u32;

    let mut reg_v: u32 = 0;
    if base_clock_hz > target_hz {
        reg_v = 1;
        while reg_v < 0x80 && (base_clock_hz / (2 * reg_v)) > target_hz {
            reg_v <<= 1;
        }
    }
    let actual_hz = if reg_v == 0 { base_clock_hz } else { base_clock_hz / (2 * reg_v) };
    unsafe {
        fut_printf(
            b"sdhci: base=%u MHz, target=400 kHz, reg_v=0x%02x, actual=%u Hz\n\0".as_ptr(),
            base_clock_mhz, reg_v, actual_hz,
        );
    }

    let div_byte = (reg_v & 0xFF) as u16;
    let clk = (div_byte << 8) | SDHCI_CLOCK_INT_EN;
    unsafe { w16(mmio_rw, SDHCI_CLOCK_CONTROL, clk) };

    // Wait for internal clock stable.
    let mut stable = false;
    for _ in 0..1_000_000 {
        let r = unsafe { r16(mmio_ro, SDHCI_CLOCK_CONTROL) };
        if r & SDHCI_CLOCK_INT_STABLE != 0 { stable = true; break; }
    }
    unsafe {
        fut_printf(b"sdhci: internal clock stable=%d\n\0".as_ptr(), stable as i32);
    }

    // Enable SD clock output to the card.
    let clk2 = clk | SDHCI_CLOCK_SD_EN;
    unsafe { w16(mmio_rw, SDHCI_CLOCK_CONTROL, clk2) };

    // Hold for at least 74 SDCLK cycles before the first CMD per
    // SDHCI 2.00 §3.3. At ~250 kHz that's ~296 µs; at our worst-case
    // 781 kHz it's ~95 µs. 100K MMIO reads at ~100 ns each ≈ 10 ms,
    // comfortable above both.
    for _ in 0..100_000 {
        let _ = unsafe { r16(mmio_ro, SDHCI_CLOCK_CONTROL) };
    }
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

/// SD card init: CMD0 / CMD8 / ACMD41 / CMD2 / CMD3 / CMD9 / CMD7.
/// Tight timeouts + step-by-step diagnostics so we can tell which
/// command stalls. Returns 0 on success, negative on failure.
fn sd_card_init(mmio_ro: *const u8, mmio_rw: *mut u8) -> Result<u32, i32> {
    let step_p = core::ptr::addr_of_mut!(SDHCI_LAST_STEP);
    unsafe { core::ptr::write(step_p, 0); fut_printf(b"sdhci: CMD0 (GO_IDLE)\n\0".as_ptr()); }
    let _ = issue_cmd(mmio_ro, mmio_rw, 0, 0, SDHCI_CMD_RESP_NONE, false);

    unsafe { core::ptr::write(step_p, 8); fut_printf(b"sdhci: CMD8 (SEND_IF_COND)\n\0".as_ptr()); }
    let r = issue_cmd(mmio_ro, mmio_rw, 8, 0x1AA,
                      SDHCI_CMD_RESP_R48 | SDHCI_CMD_CRC_CHECK | SDHCI_CMD_INDEX_CHECK,
                      false);
    let is_sdv2 = r != i64::MIN && (r as u32 & 0xFF) == 0xAA;
    unsafe {
        fut_printf(b"sdhci: CMD8 r=0x%llx sdv2=%d\n\0".as_ptr(),
                   r as u64, is_sdv2 as i32);
    }

    // ACMD41: 100-iteration outer cap (vs 1000), 1000-read inner
    // delay (vs 50K). At ~100 ns/read this is at most 10 ms × 100 ≈
    // 1 sec of total wait — fast enough that a misbehaving card
    // surfaces immediately instead of looking like a kernel hang.
    let acmd41_arg = if is_sdv2 { 0x4030_0000u32 } else { 0x0030_0000u32 };
    unsafe { core::ptr::write(step_p, 41); fut_printf(b"sdhci: ACMD41 loop arg=0x%x\n\0".as_ptr(), acmd41_arg); }
    let mut ocr: u32 = 0;
    let mut ok = false;
    let mut iter = 0u32;
    for i in 0..100u32 {
        iter = i;
        let _ = issue_cmd(mmio_ro, mmio_rw, 55, 0,
                          SDHCI_CMD_RESP_R48 | SDHCI_CMD_CRC_CHECK | SDHCI_CMD_INDEX_CHECK,
                          false);
        let r = issue_cmd(mmio_ro, mmio_rw, 41, acmd41_arg,
                          SDHCI_CMD_RESP_R48, false);
        if r == i64::MIN { continue; }
        ocr = r as u32;
        if ocr & 0x8000_0000 != 0 { ok = true; break; }
        for _ in 0..1000 {
            let _ = unsafe { r32(mmio_ro, SDHCI_PRESENT_STATE) };
        }
    }
    unsafe {
        fut_printf(b"sdhci: ACMD41 done iter=%u ocr=0x%x ok=%d\n\0".as_ptr(),
                   iter, ocr, ok as i32);
    }
    if !ok { return Err(-101); }

    unsafe { core::ptr::write(step_p, 2); fut_printf(b"sdhci: CMD2 (ALL_SEND_CID)\n\0".as_ptr()); }
    let _ = issue_cmd(mmio_ro, mmio_rw, 2, 0,
                      SDHCI_CMD_RESP_R136 | SDHCI_CMD_CRC_CHECK,
                      false);

    unsafe { core::ptr::write(step_p, 3); fut_printf(b"sdhci: CMD3 (SEND_RELATIVE_ADDR)\n\0".as_ptr()); }
    let r = issue_cmd(mmio_ro, mmio_rw, 3, 0,
                      SDHCI_CMD_RESP_R48 | SDHCI_CMD_CRC_CHECK | SDHCI_CMD_INDEX_CHECK,
                      false);
    if r == i64::MIN { return Err(-103); }
    let rca = ((r as u32) >> 16) & 0xFFFF;
    unsafe { fut_printf(b"sdhci: CMD3 RCA=0x%x\n\0".as_ptr(), rca); }

    unsafe { core::ptr::write(step_p, 9); fut_printf(b"sdhci: CMD9 (SEND_CSD)\n\0".as_ptr()); }
    let _ = issue_cmd(mmio_ro, mmio_rw, 9, rca << 16,
                      SDHCI_CMD_RESP_R136 | SDHCI_CMD_CRC_CHECK,
                      false);

    unsafe { core::ptr::write(step_p, 7); fut_printf(b"sdhci: CMD7 (SELECT_CARD)\n\0".as_ptr()); }
    let r = issue_cmd(mmio_ro, mmio_rw, 7, rca << 16,
                      SDHCI_CMD_RESP_R48_BUSY | SDHCI_CMD_CRC_CHECK | SDHCI_CMD_INDEX_CHECK,
                      false);
    if r == i64::MIN { return Err(-107); }

    unsafe { core::ptr::write(step_p, 999); }
    Ok(rca)
}

static mut SDHCI_RCA: u32 = 0;
static mut SDHCI_CARD_READY: bool = false;
/// Last value returned by sd_card_init: 0 on success, negative
/// error code on failure, or i32::MIN if init was never attempted.
/// Cached so sdhci_dump_status can re-emit it near the trampoline
/// cliff (the per-CMD trace lines scroll past visible area).
static mut SDHCI_LAST_INIT_RC: i32 = i32::MIN;
/// Last sd_card_init step that printed something useful. Set by
/// sd_card_init right before each command; sdhci_dump_status emits
/// it so we know which command stalled.
static mut SDHCI_LAST_STEP: u32 = 0;

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

    let rc = match sd_card_init(mmio, mmio) {
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
    };
    unsafe { core::ptr::write(core::ptr::addr_of_mut!(SDHCI_LAST_INIT_RC), rc); }
    rc
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

/// Re-print the full controller status. Designed to be called near
/// the trampoline cliff so the user sees SDHCI state on the bottom
/// of the visible screen instead of having to scroll up through the
/// boot log. Also re-emits every class-08 PCI hit seen during
/// sdhci_init's scan so the user can identify the actual SD/eMMC
/// controller (if any) without scrolling back.
#[unsafe(no_mangle)]
pub extern "C" fn sdhci_dump_status() {
    // Re-emit the PCI scan first.
    let count = unsafe { *MASS_STORAGE_COUNT.get() };
    if count == 0 {
        unsafe { fut_printf(b"[SDHCI-SCAN] no class-08 devices on bus 0\n\0".as_ptr()); }
    } else {
        for i in 0..count as usize {
            let h = unsafe { (*MASS_STORAGE_HITS.get())[i] };
            unsafe {
                fut_printf(
                    b"[SDHCI-SCAN] 00:%02x.%x vendor=0x%04x device=0x%04x class=0x%06x\n\0".as_ptr(),
                    h.dev as u32, h.func as u32,
                    h.vendor as u32, h.device as u32, h.class,
                );
            }
        }
    }

    let st = STATE.get();
    let inited = unsafe { (*st).initialized };
    let ready  = unsafe { core::ptr::read(core::ptr::addr_of!(SDHCI_CARD_READY)) };
    if !inited {
        unsafe { fut_printf(b"[SDHCI-STATUS] no SD/eMMC class-08:05 controller bound\n\0".as_ptr()); }
        return;
    }
    let mmio = unsafe { (*st).mmio_base };
    let present = if mmio.is_null() { 0 } else { unsafe { r32(mmio, SDHCI_PRESENT_STATE) } };
    let card_inserted = (present & SDHCI_PRESENT_CARD_INSERTED) != 0;
    unsafe {
        fut_printf(
            b"[SDHCI-STATUS] vendor=0x%04x device=0x%04x version=0x%04x caps=0x%llx card_%s ready=%d\n\0".as_ptr(),
            (*st).vendor_id as u32,
            (*st).device_id as u32,
            (*st).host_version as u32,
            (*st).capabilities,
            if card_inserted { b"INSERTED\0".as_ptr() } else { b"absent\0".as_ptr() },
            ready as u32,
        );
    }
    let last_rc = unsafe { core::ptr::read(core::ptr::addr_of!(SDHCI_LAST_INIT_RC)) };
    let last_step = unsafe { core::ptr::read(core::ptr::addr_of!(SDHCI_LAST_STEP)) };
    unsafe {
        fut_printf(
            b"[SDHCI-STATUS] last_init_rc=%d last_step=CMD%u (999=done)\n\0".as_ptr(),
            last_rc, last_step,
        );
    }
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
