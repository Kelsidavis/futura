// SPDX-License-Identifier: MPL-2.0
//
// Intel iTCO (TCO) Watchdog Timer Driver for Futura OS
//
// Implements the Intel Total Cost of Ownership watchdog timer found in
// Intel PCH (Platform Controller Hub) on Gen 10+ platforms (iTCO v4).
//
// Architecture:
//   - I/O port-based register access via TCOBASE
//   - TCOBASE discovery from LPC/eSPI bridge (PCI 00:1F.0) config space
//   - Two-stage timeout: first timeout sets status, second causes reset
//   - 1-second tick resolution (v4), 10-bit timer (max 1023 seconds)
//   - Pet/kick by writing TCO_RLD and clearing TIMEOUT status
//
// The TCO watchdog is part of the Intel PCH and is accessed through I/O
// ports derived from TCOBASE. The LPC/eSPI bridge at PCI 00:1F.0 holds
// the ACPI base address (config 0x40) and TCO control (config 0x54).
// TCOBASE = ACPI_BASE + 0x60.
//
// Two-stage timeout mechanism:
//   1. First timeout: TCO1_STS.TIMEOUT is set, timer reloads automatically
//   2. Second timeout: system reset (unless NO_REBOOT is set)
//   To prevent reset: reload timer (write TCO_RLD) and clear TIMEOUT bit
//     before the second timeout occurs.

#![no_std]
#![forbid(unsafe_op_in_unsafe_fn)]
#![allow(unexpected_cfgs)]

use core::cell::UnsafeCell;
use core::sync::atomic::{fence, Ordering};

use common::{log, map_mmio_region, MMIO_DEFAULT_FLAGS};

unsafe extern "C" {
    fn fut_printf(fmt: *const u8, ...);
    fn pci_device_count() -> i32;
    fn pci_get_device(index: i32) -> *const PciDevice;
}

// -- PCI device structure (mirrors kernel/pci.h) --

#[repr(C)]
struct PciDevice {
    bus: u8,
    dev: u8,
    func: u8,
    vendor_id: u16,
    device_id: u16,
    class_code: u8,
    subclass: u8,
    prog_if: u8,
    revision: u8,
    header_type: u8,
    subsys_vendor: u16,
    subsys_id: u16,
    irq_line: u8,
}

// -- PCI configuration space I/O --

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

// -- x86 I/O port helpers --

fn io_outw(port: u16, val: u16) {
    unsafe {
        core::arch::asm!("out dx, ax", in("dx") port, in("ax") val);
    }
}

fn io_inw(port: u16) -> u16 {
    let val: u16;
    unsafe {
        core::arch::asm!("in ax, dx", in("dx") port, out("ax") val);
    }
    val
}

#[allow(dead_code)]
fn io_outb(port: u16, val: u8) {
    unsafe {
        core::arch::asm!("out dx, al", in("dx") port, in("al") val);
    }
}

#[allow(dead_code)]
fn io_inb(port: u16) -> u8 {
    let val: u8;
    unsafe {
        core::arch::asm!("in al, dx", in("dx") port, out("al") val);
    }
    val
}

// -- Intel PCH identification --

/// Intel vendor ID.
const INTEL_VENDOR_ID: u16 = 0x8086;

/// PCI class: ISA/LPC/eSPI bridge.
const PCI_CLASS_BRIDGE: u8 = 0x06;
/// PCI subclass: ISA bridge.
const PCI_SUBCLASS_ISA: u8 = 0x01;

// -- LPC/eSPI bridge PCI config offsets --

/// ACPI Base Address register (ABASE) in LPC bridge config space.
/// Bits [15:7] contain the ACPI I/O base address (128-byte aligned).
/// The low bit is the I/O space indicator.
const LPC_ACPI_BASE: u8 = 0x40;

/// ACPI Control register - bit 7 enables ACPI I/O decode.
const LPC_ACPI_CTRL: u8 = 0x44;

/// TCOBASE register in LPC bridge config space (Gen 10+ / Series 300+).
/// Bits [15:5] contain the TCO I/O base address (32-byte aligned).
const LPC_TCOBASE: u8 = 0x50;

/// TCO Control register in LPC bridge config space.
/// Bit 8 (TCO_BASE_EN): enable TCOBASE I/O decode.
/// Bit 13 (TCO_EN): enable TCO function.
const LPC_TCOCTL: u8 = 0x54;

// -- TCO Control (TCOCTL) bits --

/// TCO base I/O decode enable.
const TCOCTL_TCO_BASE_EN: u32 = 1 << 8;
/// TCO function enable.
#[allow(dead_code)]
const TCOCTL_TCO_EN: u32 = 1 << 13;

// -- TCO I/O register offsets (from TCOBASE) --

/// TCO Timer Reload / Current Value (16-bit).
/// Write: reload the timer. Read: current countdown value.
const TCO_RLD: u16 = 0x00;

/// TCO Data In register (8-bit) - NMI data.
#[allow(dead_code)]
const TCO_DAT_IN: u16 = 0x02;

/// TCO Data Out register (8-bit).
#[allow(dead_code)]
const TCO_DAT_OUT: u16 = 0x03;

/// TCO1 Status register (16-bit).
/// bit 3: TIMEOUT - first timeout occurred (write 1 to clear).
/// bit 8: NEWCENTURY
const TCO1_STS: u16 = 0x04;

/// TCO2 Status register (16-bit).
/// bit 1: SECOND_TO_STS - second timeout occurred (v4).
/// bit 2: BOOT_STS - previous boot was from watchdog reset.
const TCO2_STS: u16 = 0x06;

/// TCO1 Control register (16-bit).
/// bit 0: TCO_LOCK - lock TCO config (write-once, sticky until reset).
/// bit 11: TCO_TMR_HLT - halt timer (1 = stopped, 0 = running).
const TCO1_CNT: u16 = 0x08;

/// TCO2 Control register (16-bit).
#[allow(dead_code)]
const TCO2_CNT: u16 = 0x0A;

/// TCO Timer Initial Value register (16-bit).
/// Bits [9:0] contain the timer value in tick units.
/// v4: 1-second ticks, so max = 1023 seconds.
const TCO_TMR: u16 = 0x12;

// -- TCO1_STS bits --

/// First timeout status (write 1 to clear).
const TCO1_STS_TIMEOUT: u16 = 1 << 3;

// -- TCO2_STS bits --

/// Second timeout status (v4+).
const TCO2_STS_SECOND_TO: u16 = 1 << 1;
/// Boot status - previous boot was from watchdog reset.
const TCO2_STS_BOOT: u16 = 1 << 2;

// -- TCO1_CNT bits --

/// Lock TCO configuration (write-once, cleared on reset).
#[allow(dead_code)]
const TCO1_CNT_LOCK: u16 = 1 << 0;
/// Halt the TCO timer (1 = halted/stopped, 0 = running).
const TCO1_CNT_TMR_HLT: u16 = 1 << 11;

// -- TCO_TMR bits --

/// Timer value mask (bits [9:0]).
const TCO_TMR_MASK: u16 = 0x03FF;

// -- TCOBASE offset from ACPI base --

/// On platforms where TCOBASE is derived from ACPI base.
const ACPI_TCO_OFFSET: u16 = 0x60;

// -- PMC (Power Management Controller) NO_REBOOT bit --

/// PWRMBASE PCI config register in PMC device (PCI 00:1F.2).
/// Bits [31:12] contain the PWRM base address (4 KiB aligned).
const PMC_PWRMBASE: u8 = 0x48;

/// Offset of GCS (General Control and Status) within PMC MMIO.
/// On Gen 10+ PCH: PWRMBASE + 0x3400 + 0x08 = ETR3/GCS.
const PMC_GCS_OFFSET: usize = 0x3400 + 0x08;

/// NO_REBOOT bit in GCS register (bit 4).
/// When set, the TCO second timeout will NOT cause a system reset.
/// Must be cleared for watchdog reset to function.
const GCS_NO_REBOOT: u32 = 1 << 4;

/// Size of PMC MMIO mapping needed (must cover GCS at 0x3408).
const PMC_MMIO_SIZE: usize = 0x4000;

// -- Timer limits (iTCO v4) --

/// Maximum timer value: 10-bit field, 1-second ticks.
const TCO_MAX_TIMEOUT: u32 = 1023;
/// Minimum timer value.
const TCO_MIN_TIMEOUT: u32 = 1;

// -- Static state wrapper --

/// Wrapper to allow `UnsafeCell` in a `static` (requires `Sync`).
/// Safety: all access is single-threaded or externally synchronised by the caller.
struct StaticCell<T>(UnsafeCell<T>);
unsafe impl<T> Sync for StaticCell<T> {}
impl<T> StaticCell<T> {
    const fn new(val: T) -> Self { Self(UnsafeCell::new(val)) }
    fn get(&self) -> *mut T { self.0.get() }
}

// -- Driver state --

struct IntelTcoWdt {
    /// TCO I/O base address.
    tcobase: u16,
    /// Currently configured timeout in seconds.
    timeout_secs: u32,
    /// PCI location of the LPC/eSPI bridge (retained for future use).
    #[allow(dead_code)]
    bridge_bus: u8,
    #[allow(dead_code)]
    bridge_dev: u8,
    #[allow(dead_code)]
    bridge_func: u8,
    /// Virtual address of PMC MMIO mapping (for NO_REBOOT access).
    pmc_mmio: *mut u8,
    /// Whether we successfully cleared NO_REBOOT.
    no_reboot_cleared: bool,
    /// Boot status captured at init (whether last reset was from WDT).
    boot_from_wdt: bool,
}

static WDT: StaticCell<Option<IntelTcoWdt>> = StaticCell::new(None);

// -- TCO I/O register access --

impl IntelTcoWdt {
    /// Read a 16-bit TCO register.
    fn tco_read16(&self, offset: u16) -> u16 {
        fence(Ordering::SeqCst);
        io_inw(self.tcobase + offset)
    }

    /// Write a 16-bit TCO register.
    fn tco_write16(&self, offset: u16, val: u16) {
        io_outw(self.tcobase + offset, val);
        fence(Ordering::SeqCst);
    }

    /// Reload the TCO timer (prevents second timeout).
    /// Write any value to TCO_RLD to reload from TCO_TMR initial value.
    fn reload(&self) {
        self.tco_write16(TCO_RLD, 0x0001);
    }

    /// Clear the first timeout status bit in TCO1_STS.
    fn clear_timeout_status(&self) {
        // Write 1 to bit 3 to clear TIMEOUT.
        self.tco_write16(TCO1_STS, TCO1_STS_TIMEOUT);
    }

    /// Clear the second timeout status bit in TCO2_STS.
    fn clear_second_timeout_status(&self) {
        // Write 1 to bit 1 to clear SECOND_TO_STS.
        self.tco_write16(TCO2_STS, TCO2_STS_SECOND_TO);
    }

    /// Set the timer initial value (in seconds for v4).
    /// Clamps to [1, 1023].
    fn set_timer_value(&self, secs: u32) -> u32 {
        let clamped = if secs < TCO_MIN_TIMEOUT {
            TCO_MIN_TIMEOUT
        } else if secs > TCO_MAX_TIMEOUT {
            TCO_MAX_TIMEOUT
        } else {
            secs
        };

        let cur = self.tco_read16(TCO_TMR);
        // Preserve upper bits, write new value into [9:0].
        let new_val = (cur & !TCO_TMR_MASK) | ((clamped as u16) & TCO_TMR_MASK);
        self.tco_write16(TCO_TMR, new_val);

        // Verify the write.
        let readback = self.tco_read16(TCO_TMR) & TCO_TMR_MASK;
        if readback != (clamped as u16) & TCO_TMR_MASK {
            unsafe {
                fut_printf(
                    b"intel_wdt: timer value readback mismatch (wrote %u, read %u)\n\0".as_ptr(),
                    clamped,
                    readback as u32,
                );
            }
        }

        clamped
    }

    /// Start the TCO timer (clear TCO_TMR_HLT bit).
    fn start(&self) {
        let cnt = self.tco_read16(TCO1_CNT);
        self.tco_write16(TCO1_CNT, cnt & !TCO1_CNT_TMR_HLT);
    }

    /// Stop the TCO timer (set TCO_TMR_HLT bit).
    fn stop(&self) {
        let cnt = self.tco_read16(TCO1_CNT);
        self.tco_write16(TCO1_CNT, cnt | TCO1_CNT_TMR_HLT);
    }

    /// Check if the timer is currently running (TCO_TMR_HLT = 0 means running).
    fn is_running(&self) -> bool {
        (self.tco_read16(TCO1_CNT) & TCO1_CNT_TMR_HLT) == 0
    }

    /// Get the current countdown value from TCO_RLD (read gives current value).
    fn get_current_count(&self) -> u16 {
        self.tco_read16(TCO_RLD) & TCO_TMR_MASK
    }

    /// Check if a first timeout has occurred.
    fn has_timed_out(&self) -> bool {
        (self.tco_read16(TCO1_STS) & TCO1_STS_TIMEOUT) != 0
    }

    /// Check TCO2_STS BOOT_STS bit (previous boot from watchdog reset).
    fn boot_status(&self) -> bool {
        (self.tco_read16(TCO2_STS) & TCO2_STS_BOOT) != 0
    }

    /// Clear the NO_REBOOT bit in PMC GCS register.
    /// Returns true if successfully cleared.
    fn clear_no_reboot(&self) -> bool {
        if self.pmc_mmio.is_null() {
            return false;
        }

        let gcs_ptr = unsafe { self.pmc_mmio.add(PMC_GCS_OFFSET) as *mut u32 };
        fence(Ordering::SeqCst);
        let gcs = unsafe { core::ptr::read_volatile(gcs_ptr) };

        if gcs & GCS_NO_REBOOT != 0 {
            unsafe {
                core::ptr::write_volatile(gcs_ptr, gcs & !GCS_NO_REBOOT);
            }
            fence(Ordering::SeqCst);

            // Verify it was cleared.
            let verify = unsafe { core::ptr::read_volatile(gcs_ptr) };
            if verify & GCS_NO_REBOOT != 0 {
                log("intel_wdt: WARNING - failed to clear NO_REBOOT bit (may be locked)");
                return false;
            }

            log("intel_wdt: cleared NO_REBOOT bit in PMC GCS");
        }

        true
    }
}

// -- PCI discovery --

/// Find the Intel LPC/eSPI bridge at PCI 00:1F.0.
/// Returns (bus, dev, func, device_id) if found.
fn find_lpc_bridge() -> Option<(u8, u8, u8, u16)> {
    let count = unsafe { pci_device_count() };
    for i in 0..count {
        let dev = unsafe { &*pci_get_device(i) };
        if dev.vendor_id == INTEL_VENDOR_ID
            && dev.class_code == PCI_CLASS_BRIDGE
            && dev.subclass == PCI_SUBCLASS_ISA
            && dev.bus == 0
            && dev.dev == 31
            && dev.func == 0
        {
            return Some((dev.bus, dev.dev, dev.func, dev.device_id));
        }
    }
    None
}

/// Discover TCOBASE from the LPC/eSPI bridge.
///
/// Strategy 1: Read TCOBASE directly from config offset 0x50 (Gen 10+).
/// Strategy 2: Derive from ACPI base (config 0x40) + 0x60.
fn discover_tcobase(bus: u8, dev: u8, func: u8) -> Option<u16> {
    // Strategy 1: Direct TCOBASE register (Gen 10+, Series 300+).
    let tcoctl = pci_read32(bus, dev, func, LPC_TCOCTL);

    // Check if TCO base decode is enabled (bit 8 of TCOCTL).
    if tcoctl & TCOCTL_TCO_BASE_EN != 0 {
        let tcobase_reg = pci_read32(bus, dev, func, LPC_TCOBASE);
        // Bits [15:5] = TCOBASE (32-byte aligned), bit 0 = I/O indicator.
        let base = (tcobase_reg & 0xFFE0) as u16;
        if base != 0 && base != 0xFFE0 {
            unsafe {
                fut_printf(
                    b"intel_wdt: TCOBASE from config 0x50: 0x%04x (TCOCTL=0x%08x)\n\0".as_ptr(),
                    base as u32,
                    tcoctl,
                );
            }
            return Some(base);
        }
    }

    // Strategy 2: Derive from ACPI base address.
    let abase_reg = pci_read32(bus, dev, func, LPC_ACPI_BASE);
    // Bits [15:7] = ACPI I/O base (128-byte aligned).
    let acpi_base = (abase_reg & 0xFF80) as u16;

    if acpi_base == 0 || acpi_base == 0xFF80 {
        log("intel_wdt: ACPI base address not configured");
        return None;
    }

    // Check ACPI I/O decode enable (bit 7 of ACPI control at offset 0x44).
    let acpi_ctrl = pci_read32(bus, dev, func, LPC_ACPI_CTRL);
    if acpi_ctrl & (1 << 7) == 0 {
        log("intel_wdt: ACPI I/O decode not enabled");
        // Continue anyway - the base may still be usable.
    }

    let tcobase = acpi_base + ACPI_TCO_OFFSET;

    unsafe {
        fut_printf(
            b"intel_wdt: TCOBASE from ACPI base: 0x%04x (ABASE=0x%04x)\n\0".as_ptr(),
            tcobase as u32,
            acpi_base as u32,
        );
    }

    Some(tcobase)
}

/// Enable TCO base decode in TCOCTL if not already enabled.
fn enable_tco_base_decode(bus: u8, dev: u8, func: u8) {
    let tcoctl = pci_read32(bus, dev, func, LPC_TCOCTL);
    if tcoctl & TCOCTL_TCO_BASE_EN == 0 {
        pci_write32(bus, dev, func, LPC_TCOCTL, tcoctl | TCOCTL_TCO_BASE_EN);
        log("intel_wdt: enabled TCO base I/O decode");
    }
}

/// Discover and map the PMC MMIO region for NO_REBOOT access.
/// PMC is at PCI 00:1F.2, PWRMBASE at config 0x48.
fn map_pmc_mmio() -> *mut u8 {
    // PMC is function 2 of device 31 on bus 0.
    let pwrmbase_reg = pci_read32(0, 31, 2, PMC_PWRMBASE);
    // Bits [31:12] = PWRM base (4 KiB aligned).
    let pwrmbase = (pwrmbase_reg & 0xFFFFF000) as u64;

    if pwrmbase == 0 || pwrmbase == 0xFFFFF000 {
        log("intel_wdt: PWRMBASE not configured in PMC");
        return core::ptr::null_mut();
    }

    unsafe {
        fut_printf(
            b"intel_wdt: PMC PWRMBASE = 0x%08lx\n\0".as_ptr(),
            pwrmbase,
        );
    }

    let mmio = unsafe { map_mmio_region(pwrmbase, PMC_MMIO_SIZE, MMIO_DEFAULT_FLAGS) };
    if mmio.is_null() {
        log("intel_wdt: failed to map PMC MMIO region");
    }

    mmio
}

/// Verify TCO hardware is responsive by reading TCO_RLD.
/// All-ones typically indicates unmapped/non-existent hardware.
fn verify_tco_io(tcobase: u16) -> bool {
    let rld = io_inw(tcobase + TCO_RLD);
    let cnt = io_inw(tcobase + TCO1_CNT);
    // If both read as 0xFFFF, hardware is likely not present.
    !(rld == 0xFFFF && cnt == 0xFFFF)
}

// -- FFI exports --

/// Initialise the Intel iTCO Watchdog Timer driver.
///
/// Discovers the LPC/eSPI bridge, reads TCOBASE, maps PMC for NO_REBOOT
/// control, and verifies hardware accessibility.
///
/// Returns 0 on success, negative error on failure.
#[unsafe(no_mangle)]
pub extern "C" fn intel_wdt_init() -> i32 {
    log("intel_wdt: scanning PCI for Intel LPC/eSPI bridge...");

    let (bus, dev, func, device_id) = match find_lpc_bridge() {
        Some(bdf) => bdf,
        None => {
            log("intel_wdt: no Intel LPC/eSPI bridge found at 00:1F.0");
            return -1;
        }
    };

    unsafe {
        fut_printf(
            b"intel_wdt: found LPC/eSPI bridge (device %04x) at PCI %02x:%02x.%x\n\0".as_ptr(),
            device_id as u32,
            bus as u32,
            dev as u32,
            func as u32,
        );
    }

    // Enable TCO base decode.
    enable_tco_base_decode(bus, dev, func);

    // Discover TCOBASE.
    let tcobase = match discover_tcobase(bus, dev, func) {
        Some(base) => base,
        None => {
            log("intel_wdt: failed to discover TCOBASE");
            return -2;
        }
    };

    // Verify TCO hardware is responsive.
    if !verify_tco_io(tcobase) {
        log("intel_wdt: TCO I/O ports not responding (all-ones read)");
        return -3;
    }

    // Map PMC MMIO for NO_REBOOT bit access.
    let pmc_mmio = map_pmc_mmio();

    // Build driver state.
    let mut wdt = IntelTcoWdt {
        tcobase,
        timeout_secs: 0,
        bridge_bus: bus,
        bridge_dev: dev,
        bridge_func: func,
        pmc_mmio,
        no_reboot_cleared: false,
        boot_from_wdt: false,
    };

    // Read current status for diagnostics.
    let tco1_sts = wdt.tco_read16(TCO1_STS);
    let tco2_sts = wdt.tco_read16(TCO2_STS);
    let tco1_cnt = wdt.tco_read16(TCO1_CNT);
    let tco_tmr = wdt.tco_read16(TCO_TMR);

    unsafe {
        fut_printf(
            b"intel_wdt: TCO1_STS=0x%04x TCO2_STS=0x%04x TCO1_CNT=0x%04x TCO_TMR=0x%04x\n\0"
                .as_ptr(),
            tco1_sts as u32,
            tco2_sts as u32,
            tco1_cnt as u32,
            tco_tmr as u32,
        );
    }

    // Check if the previous boot was caused by a watchdog reset.
    if wdt.boot_status() {
        log("intel_wdt: WARNING - previous boot was from watchdog reset (BOOT_STS set)");
        wdt.boot_from_wdt = true;
        // Clear BOOT_STS by writing 1 to it.
        wdt.tco_write16(TCO2_STS, TCO2_STS_BOOT);
    }

    // Check for first timeout status from previous run.
    if tco1_sts & TCO1_STS_TIMEOUT != 0 {
        log("intel_wdt: clearing stale TIMEOUT status from previous run");
        wdt.clear_timeout_status();
    }

    // Check for second timeout status.
    if tco2_sts & TCO2_STS_SECOND_TO != 0 {
        log("intel_wdt: clearing stale SECOND_TO_STS from previous run");
        wdt.clear_second_timeout_status();
    }

    // Ensure the timer is halted during init.
    wdt.stop();

    // Try to clear the NO_REBOOT bit so the watchdog can actually reset the system.
    wdt.no_reboot_cleared = wdt.clear_no_reboot();
    if !wdt.no_reboot_cleared && !pmc_mmio.is_null() {
        log("intel_wdt: WARNING - NO_REBOOT bit could not be cleared");
        log("intel_wdt: watchdog timeout will NOT cause system reset");
    }

    // Store the driver state.
    unsafe {
        (*WDT.get()) = Some(wdt);
    }

    log("intel_wdt: driver initialised successfully");
    0
}

/// Enable the Intel iTCO watchdog with the specified timeout in seconds.
///
/// `timeout_secs` - Countdown duration (1 to 1023 seconds for v4).
///
/// The two-stage timeout means the actual time to system reset is
/// approximately 2x the configured timeout (first timeout + reload +
/// second timeout). We configure for the specified timeout per stage.
///
/// Returns 0 on success, negative error on failure.
#[unsafe(no_mangle)]
pub extern "C" fn intel_wdt_enable(timeout_secs: u32) -> i32 {
    let wdt = match unsafe { (*WDT.get()).as_mut() } {
        Some(w) => w,
        None => return -19, // ENODEV
    };

    if timeout_secs < TCO_MIN_TIMEOUT || timeout_secs > TCO_MAX_TIMEOUT {
        unsafe {
            fut_printf(
                b"intel_wdt: invalid timeout %u (must be %u-%u seconds)\n\0".as_ptr(),
                timeout_secs,
                TCO_MIN_TIMEOUT,
                TCO_MAX_TIMEOUT,
            );
        }
        return -22; // EINVAL
    }

    // Ensure NO_REBOOT is cleared.
    if !wdt.no_reboot_cleared {
        wdt.no_reboot_cleared = wdt.clear_no_reboot();
        if !wdt.no_reboot_cleared {
            log("intel_wdt: WARNING - enabling watchdog but NO_REBOOT is set");
        }
    }

    // Set the timer initial value.
    let actual = wdt.set_timer_value(timeout_secs);
    wdt.timeout_secs = actual;

    // Clear any stale timeout status bits.
    wdt.clear_timeout_status();
    wdt.clear_second_timeout_status();

    // Reload the timer to start from the configured value.
    wdt.reload();

    // Start the timer (clear TCO_TMR_HLT).
    wdt.start();

    unsafe {
        fut_printf(
            b"intel_wdt: enabled with %u second timeout\n\0".as_ptr(),
            actual,
        );
    }
    0
}

/// Disable the Intel iTCO watchdog timer.
///
/// Halts the timer by setting TCO_TMR_HLT. Does NOT lock the configuration.
///
/// Returns 0 on success, negative error on failure.
#[unsafe(no_mangle)]
pub extern "C" fn intel_wdt_disable() -> i32 {
    let wdt = match unsafe { (*WDT.get()).as_ref() } {
        Some(w) => w,
        None => return -19, // ENODEV
    };

    wdt.stop();

    // Clear any pending timeout status.
    wdt.clear_timeout_status();
    wdt.clear_second_timeout_status();

    log("intel_wdt: watchdog disabled");
    0
}

/// Pet (kick) the Intel iTCO watchdog to prevent timeout.
///
/// Reloads the timer countdown by writing to TCO_RLD and clears the
/// first timeout status bit to prevent progression to second timeout.
///
/// Returns 0 on success, negative error on failure.
#[unsafe(no_mangle)]
pub extern "C" fn intel_wdt_pet() -> i32 {
    let wdt = match unsafe { (*WDT.get()).as_ref() } {
        Some(w) => w,
        None => return -19, // ENODEV
    };

    // Clear the TIMEOUT status to prevent second timeout.
    wdt.clear_timeout_status();

    // Reload the timer from the initial value.
    wdt.reload();

    0
}

/// Set a new timeout value in seconds.
///
/// If the watchdog is currently running, the new value takes effect
/// on the next reload (pet). Clamps to [1, 1023].
///
/// Returns 0 on success, negative error on failure.
#[unsafe(no_mangle)]
pub extern "C" fn intel_wdt_set_timeout(secs: u32) -> i32 {
    let wdt = match unsafe { (*WDT.get()).as_mut() } {
        Some(w) => w,
        None => return -19, // ENODEV
    };

    if secs < TCO_MIN_TIMEOUT || secs > TCO_MAX_TIMEOUT {
        return -22; // EINVAL
    }

    let actual = wdt.set_timer_value(secs);
    wdt.timeout_secs = actual;

    // If the timer is running, reload to pick up the new value.
    if wdt.is_running() {
        wdt.clear_timeout_status();
        wdt.reload();
    }

    unsafe {
        fut_printf(
            b"intel_wdt: timeout set to %u seconds\n\0".as_ptr(),
            actual,
        );
    }
    0
}

/// Get the remaining time before timeout, in seconds.
///
/// Returns the current countdown value from TCO_RLD, or 0 if the
/// driver is not initialised or the timer is not running.
#[unsafe(no_mangle)]
pub extern "C" fn intel_wdt_get_timeleft() -> u32 {
    let wdt = match unsafe { (*WDT.get()).as_ref() } {
        Some(w) => w,
        None => return 0,
    };

    if !wdt.is_running() {
        return 0;
    }

    wdt.get_current_count() as u32
}

/// Query the current watchdog status as a bitmask.
///
/// Returns:
///   bit 0: watchdog is enabled/running
///   bit 1: first timeout has occurred (TIMEOUT in TCO1_STS)
///   bit 2: previous boot was from watchdog reset (BOOT_STS)
///
/// Returns 0 if the driver is not initialised.
#[unsafe(no_mangle)]
pub extern "C" fn intel_wdt_status() -> u32 {
    let wdt = match unsafe { (*WDT.get()).as_ref() } {
        Some(w) => w,
        None => return 0,
    };

    let mut result: u32 = 0;

    // Bit 0: enabled/running (TCO_TMR_HLT = 0 means running).
    if wdt.is_running() {
        result |= 1 << 0;
    }

    // Bit 1: first timeout occurred.
    if wdt.has_timed_out() {
        result |= 1 << 1;
    }

    // Bit 2: previous boot from watchdog reset.
    if wdt.boot_from_wdt {
        result |= 1 << 2;
    }

    result
}

/// Check if the last system reboot was caused by the watchdog timer.
///
/// Returns true if the TCO2_STS BOOT_STS bit was set at driver init,
/// indicating the previous boot was triggered by a watchdog second timeout.
#[unsafe(no_mangle)]
pub extern "C" fn intel_wdt_caused_last_reboot() -> bool {
    let wdt = match unsafe { (*WDT.get()).as_ref() } {
        Some(w) => w,
        None => return false,
    };

    wdt.boot_from_wdt
}
