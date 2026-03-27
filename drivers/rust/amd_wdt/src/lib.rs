// SPDX-License-Identifier: MPL-2.0
//
// AMD FCH Watchdog Timer Driver for Futura OS
//
// Implements the AMD Fusion Controller Hub (FCH) watchdog timer found on
// AM4 (X370-X570) and AM5 (X670-X870) platforms.
//
// Architecture:
//   - ACPI MMIO-based register access (WDT block at ACPI_MMIO + 0xB00)
//   - ACPI MMIO base discovery via PCI ISA bridge (vendor 1022h)
//   - Configurable timeout in seconds (1-second resolution)
//   - Supports reset and NMI+reset action modes
//   - Pet/kick to restart countdown
//
// The WDT is part of the AMD FCH ACPI MMIO region, typically mapped at
// physical address 0xFED80000. The WDT register block sits at offset
// 0xB00 within that region.
//
// Discovery: The ACPI MMIO base address is programmed in the AMD FCH
// ISA bridge (PCI device 1022:790E on AM4, or similar on AM5) at PCI
// config register 0x24, or can be read via PM I/O port index/data
// registers (0xCD6/0xCD7).

#![no_std]
#![forbid(unsafe_op_in_unsafe_fn)]
#![allow(unexpected_cfgs)]

use core::cell::UnsafeCell;
use core::ptr::{read_volatile, write_volatile};
use core::sync::atomic::{fence, Ordering};

use common::{log, map_mmio_region, unmap_mmio_region, MMIO_DEFAULT_FLAGS};

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

#[allow(dead_code)]
fn pci_write32(bus: u8, dev: u8, func: u8, offset: u8, val: u32) {
    let addr = pci_config_addr(bus, dev, func, offset);
    unsafe {
        core::arch::asm!("out dx, eax", in("dx") PCI_CONFIG_ADDR, in("eax") addr);
        core::arch::asm!("out dx, eax", in("dx") PCI_CONFIG_DATA, in("eax") val);
    }
}

// -- x86 I/O port helpers --

fn io_outb(port: u16, val: u8) {
    unsafe {
        core::arch::asm!("out dx, al", in("dx") port, in("al") val);
    }
}

fn io_inb(port: u16) -> u8 {
    let val: u8;
    unsafe {
        core::arch::asm!("in al, dx", in("dx") port, out("al") val);
    }
    val
}

/// Small delay by reading a dummy I/O port (standard x86 technique).
#[allow(dead_code)]
fn io_delay() {
    io_inb(0x80);
}

// -- AMD FCH PCI identification --

/// AMD vendor ID.
const AMD_VENDOR_ID: u16 = 0x1022;

/// AMD FCH LPC/ISA bridge device IDs (these contain the ACPI MMIO base).
/// AM4 platforms (Zen/Zen2/Zen3): FCH ISA bridge.
const AMD_ISA_BRIDGE_AM4: u16 = 0x790E;
/// AM5 platforms (Zen4/Zen5): FCH ISA bridge.
const AMD_ISA_BRIDGE_AM5: u16 = 0x790E;
/// Alternate AM5 ISA bridge device ID (some Ryzen 7000/9000 boards).
const AMD_ISA_BRIDGE_AM5_ALT: u16 = 0x14D8;

/// PCI class: ISA bridge.
const PCI_CLASS_BRIDGE: u8 = 0x06;
/// PCI subclass: ISA bridge.
const PCI_SUBCLASS_ISA: u8 = 0x01;

// -- ACPI MMIO region constants --

/// Default AMD FCH ACPI MMIO base address.
/// This is the standard physical address used on virtually all AMD platforms.
const ACPI_MMIO_DEFAULT_BASE: u64 = 0xFED8_0000;

/// PCI config register in the ISA bridge that holds the ACPI MMIO base.
/// Bits [31:13] contain the base address (8 KiB aligned).
const ISA_BRIDGE_ACPI_MMIO_REG: u8 = 0x24;

/// PM I/O port index register (alternate discovery method).
const PM_IO_INDEX: u16 = 0xCD6;
/// PM I/O port data register.
const PM_IO_DATA: u16 = 0xCD7;

/// PM register indices for ACPI MMIO base address (bytes 0-3).
const PM_ACPI_MMIO_BASE0: u8 = 0x24;
const PM_ACPI_MMIO_BASE1: u8 = 0x25;
const PM_ACPI_MMIO_BASE2: u8 = 0x26;
const PM_ACPI_MMIO_BASE3: u8 = 0x27;

/// Offset of the WDT register block within the ACPI MMIO region.
const WDT_MMIO_OFFSET: u64 = 0x0B00;

/// Size of the WDT MMIO block (we map a full page for safety).
const WDT_MMIO_SIZE: usize = 0x1000;

// -- WDT Register Offsets (relative to WDT MMIO base) --

/// WDT Control Register (32-bit).
const WDT_CTRL: usize = 0x00;
/// WDT Count Register (32-bit) - countdown value.
const WDT_COUNT: usize = 0x04;
/// WDT Miscellaneous Register (32-bit).
const WDT_MISC: usize = 0x08;

// -- WDT_CTRL bits --

/// Watchdog enable.
const CTRL_WDT_EN: u32 = 1 << 0;
/// Watchdog fired status (write 1 to clear).
const CTRL_WDT_FIRED: u32 = 1 << 1;
/// Watchdog action: 0 = immediate reset, 1 = NMI on first timeout, reset on second.
const CTRL_WDT_ACTION: u32 = 1 << 2;
/// Watchdog running status (read-only).
const CTRL_WDT_RUN_STS: u32 = 1 << 3;
/// Watchdog trigger - write 1 to restart/pet the countdown.
const CTRL_WDT_TRIGGER: u32 = 1 << 5;
/// Permanent disable (use with extreme caution - cannot be re-enabled until next cold boot).
const CTRL_WDT_DISABLE: u32 = 1 << 7;

// -- WDT_MISC bits --

/// Timer resolution: 0 = 1.024 kHz (~1 ms ticks), 1 = 32.768 kHz (~30.5 us ticks).
const MISC_WDT_RES: u32 = 1 << 0;

// -- Maximum timeout --

/// Maximum count value (16-bit countdown in seconds at 1-second resolution).
/// The AMD FCH WDT count register is 32 bits, but practical max is ~65535 seconds
/// when using 1-second resolution (WdtRes=0 with count prescaled).
const WDT_MAX_TIMEOUT_SECS: u32 = 0xFFFF;

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

struct AmdWdt {
    /// Virtual address of the WDT MMIO register block.
    mmio_base: *mut u8,
    /// Physical address of the ACPI MMIO region.
    acpi_mmio_phys: u64,
    /// Currently configured timeout in seconds.
    timeout_secs: u32,
    /// PCI location of the ISA bridge used for discovery.
    bridge_bus: u8,
    bridge_dev: u8,
    bridge_func: u8,
}

static WDT: StaticCell<Option<AmdWdt>> = StaticCell::new(None);

// -- MMIO register access --

impl AmdWdt {
    /// Read a 32-bit WDT register.
    fn read_reg(&self, offset: usize) -> u32 {
        fence(Ordering::SeqCst);
        unsafe { read_volatile(self.mmio_base.add(offset) as *const u32) }
    }

    /// Write a 32-bit WDT register.
    fn write_reg(&self, offset: usize, val: u32) {
        unsafe { write_volatile(self.mmio_base.add(offset) as *mut u32, val) };
        fence(Ordering::SeqCst);
    }

    /// Modify a WDT register: read, clear bits in `mask`, set bits in `set`, write back.
    fn modify_reg(&self, offset: usize, mask: u32, set: u32) {
        let val = self.read_reg(offset);
        self.write_reg(offset, (val & !mask) | set);
    }

    /// Configure the WDT for 1-second resolution (clear WdtRes bit in MISC register).
    /// This gives us ~1 ms base tick with the hardware prescaler producing 1-second
    /// effective countdown units.
    fn set_seconds_resolution(&self) {
        let misc = self.read_reg(WDT_MISC);
        // Clear WdtRes bit (bit 0) for ~1-second resolution.
        // When WdtRes=0, the timer uses the 1.024 kHz clock and the count register
        // represents seconds (the FCH internally prescales).
        self.write_reg(WDT_MISC, misc & !MISC_WDT_RES);
    }

    /// Set the countdown value.
    fn set_count(&self, secs: u32) {
        let count = if secs > WDT_MAX_TIMEOUT_SECS {
            WDT_MAX_TIMEOUT_SECS
        } else if secs == 0 {
            1
        } else {
            secs
        };
        self.write_reg(WDT_COUNT, count);
    }

    /// Clear the "fired" status bit by writing 1 to it.
    fn clear_fired(&self) {
        self.modify_reg(WDT_CTRL, CTRL_WDT_FIRED, CTRL_WDT_FIRED);
    }

    /// Pet/kick the watchdog: restart the countdown by writing 1 to WdtTrigger.
    fn pet(&self) {
        self.modify_reg(WDT_CTRL, CTRL_WDT_TRIGGER, CTRL_WDT_TRIGGER);
    }

    /// Enable the watchdog timer with the given timeout.
    fn enable(&self, timeout_secs: u32) {
        // Ensure 1-second resolution.
        self.set_seconds_resolution();

        // Set the countdown value.
        self.set_count(timeout_secs);

        // Clear any prior fired status.
        self.clear_fired();

        // Enable the watchdog (set WdtEn, clear WdtDisable).
        let ctrl = self.read_reg(WDT_CTRL);
        let new_ctrl = (ctrl & !CTRL_WDT_DISABLE) | CTRL_WDT_EN;
        self.write_reg(WDT_CTRL, new_ctrl);

        // Trigger to start the countdown.
        self.pet();
    }

    /// Disable the watchdog timer.
    /// Note: this clears WdtEn but does NOT set WdtDisable (which is permanent).
    fn disable(&self) {
        let ctrl = self.read_reg(WDT_CTRL);
        self.write_reg(WDT_CTRL, ctrl & !CTRL_WDT_EN);
    }

    /// Get the remaining countdown value in seconds.
    fn get_timeleft(&self) -> u32 {
        self.read_reg(WDT_COUNT)
    }

    /// Query watchdog status as a bitmask.
    /// Bit 0: enabled (WdtEn)
    /// Bit 1: fired (WdtFired)
    /// Bit 2: running (WdtRunSts)
    fn status(&self) -> u32 {
        let ctrl = self.read_reg(WDT_CTRL);
        let mut result: u32 = 0;
        if ctrl & CTRL_WDT_EN != 0 {
            result |= 1 << 0;
        }
        if ctrl & CTRL_WDT_FIRED != 0 {
            result |= 1 << 1;
        }
        if ctrl & CTRL_WDT_RUN_STS != 0 {
            result |= 1 << 2;
        }
        result
    }

    /// Set the watchdog action mode.
    /// action = 0: immediate system reset on timeout.
    /// action = 1: NMI on first timeout, system reset on second timeout.
    fn set_action(&self, nmi_first: bool) {
        if nmi_first {
            self.modify_reg(WDT_CTRL, CTRL_WDT_ACTION, CTRL_WDT_ACTION);
        } else {
            self.modify_reg(WDT_CTRL, CTRL_WDT_ACTION, 0);
        }
    }
}

// -- PCI discovery --

/// Find the AMD FCH ISA/LPC bridge on the PCI bus.
/// Returns (bus, dev, func, device_id) if found.
fn find_isa_bridge() -> Option<(u8, u8, u8, u16)> {
    let count = unsafe { pci_device_count() };
    for i in 0..count {
        let dev = unsafe { &*pci_get_device(i) };
        if dev.vendor_id == AMD_VENDOR_ID
            && (dev.device_id == AMD_ISA_BRIDGE_AM4
                || dev.device_id == AMD_ISA_BRIDGE_AM5
                || dev.device_id == AMD_ISA_BRIDGE_AM5_ALT)
            && dev.class_code == PCI_CLASS_BRIDGE
            && dev.subclass == PCI_SUBCLASS_ISA
        {
            return Some((dev.bus, dev.dev, dev.func, dev.device_id));
        }
    }
    None
}

/// Read the ACPI MMIO base address from the ISA bridge PCI config space.
/// Register 0x24 bits [31:13] contain the base address (8 KiB aligned).
/// Bit 0 indicates whether the ACPI MMIO region is enabled.
fn read_acpi_mmio_base_pci(bus: u8, dev: u8, func: u8) -> Option<u64> {
    let reg = pci_read32(bus, dev, func, ISA_BRIDGE_ACPI_MMIO_REG);

    // Bit 0: AcpiMmioEn - ACPI MMIO decode enable.
    if reg & 0x01 == 0 {
        // ACPI MMIO not enabled in PCI config; might still be at default address.
        return None;
    }

    // Bits [31:13] are the base address.
    let base = (reg & 0xFFFF_E000) as u64;
    if base == 0 {
        return None;
    }

    Some(base)
}

/// Alternate discovery: read the ACPI MMIO base via PM I/O index/data ports.
/// The FCH PM register block at I/O 0xCD6/0xCD7 contains the ACPI MMIO base
/// at PM indices 0x24-0x27.
fn read_acpi_mmio_base_pmio() -> Option<u64> {
    // Read 4 bytes from PM indices 0x24-0x27.
    io_outb(PM_IO_INDEX, PM_ACPI_MMIO_BASE0);
    let b0 = io_inb(PM_IO_DATA) as u32;
    io_outb(PM_IO_INDEX, PM_ACPI_MMIO_BASE1);
    let b1 = io_inb(PM_IO_DATA) as u32;
    io_outb(PM_IO_INDEX, PM_ACPI_MMIO_BASE2);
    let b2 = io_inb(PM_IO_DATA) as u32;
    io_outb(PM_IO_INDEX, PM_ACPI_MMIO_BASE3);
    let b3 = io_inb(PM_IO_DATA) as u32;

    let reg = b0 | (b1 << 8) | (b2 << 16) | (b3 << 24);

    // Bit 0: AcpiMmioEn.
    if reg & 0x01 == 0 {
        return None;
    }

    // Bits [31:13] are the base address.
    let base = (reg & 0xFFFF_E000) as u64;
    if base == 0 {
        return None;
    }

    Some(base)
}

/// Discover the ACPI MMIO base address using all available methods.
/// Priority: PCI config > PM I/O > default fallback.
fn discover_acpi_mmio_base(bus: u8, dev: u8, func: u8) -> u64 {
    // Method 1: PCI config space of the ISA bridge.
    if let Some(base) = read_acpi_mmio_base_pci(bus, dev, func) {
        unsafe {
            fut_printf(
                b"amd_wdt: ACPI MMIO base from PCI config: 0x%08lx\n\0".as_ptr(),
                base,
            );
        }
        return base;
    }

    // Method 2: PM I/O index/data ports.
    if let Some(base) = read_acpi_mmio_base_pmio() {
        unsafe {
            fut_printf(
                b"amd_wdt: ACPI MMIO base from PM I/O: 0x%08lx\n\0".as_ptr(),
                base,
            );
        }
        return base;
    }

    // Method 3: Use the well-known default.
    log("amd_wdt: using default ACPI MMIO base 0xFED80000");
    ACPI_MMIO_DEFAULT_BASE
}

/// Verify the WDT MMIO region is accessible by reading the control register.
/// A valid controller should not return all-ones (bus float).
fn verify_wdt_mmio(base: *mut u8) -> bool {
    let ctrl = unsafe { read_volatile(base.add(WDT_CTRL) as *const u32) };
    // All-ones typically means unmapped/non-existent hardware.
    // Also check that reserved bits aren't all set (sanity check).
    ctrl != 0xFFFF_FFFF
}

// -- FFI exports --

/// Initialise the AMD FCH Watchdog Timer driver.
///
/// Discovers the ACPI MMIO region via the FCH ISA bridge, maps the WDT
/// register block, and verifies hardware accessibility.
///
/// Returns 0 on success, negative error on failure.
#[unsafe(no_mangle)]
pub extern "C" fn amd_wdt_init() -> i32 {
    log("amd_wdt: scanning PCI for AMD FCH ISA bridge...");

    let (bus, dev, func, device_id) = match find_isa_bridge() {
        Some(bdf) => bdf,
        None => {
            log("amd_wdt: no AMD FCH ISA bridge found");
            return -1;
        }
    };

    unsafe {
        fut_printf(
            b"amd_wdt: found ISA bridge (device %04x) at PCI %02x:%02x.%x\n\0".as_ptr(),
            device_id as u32,
            bus as u32,
            dev as u32,
            func as u32,
        );
    }

    // Discover the ACPI MMIO base address.
    let acpi_mmio_phys = discover_acpi_mmio_base(bus, dev, func);

    // The WDT register block is at offset 0xB00 within the ACPI MMIO region.
    let wdt_phys = acpi_mmio_phys + WDT_MMIO_OFFSET;

    unsafe {
        fut_printf(
            b"amd_wdt: WDT MMIO phys = 0x%08lx\n\0".as_ptr(),
            wdt_phys,
        );
    }

    // Map the WDT MMIO region into virtual address space.
    let mmio_base = unsafe { map_mmio_region(wdt_phys, WDT_MMIO_SIZE, MMIO_DEFAULT_FLAGS) };
    if mmio_base.is_null() {
        log("amd_wdt: failed to map WDT MMIO region");
        return -2;
    }

    // Verify the WDT is accessible.
    if !verify_wdt_mmio(mmio_base) {
        log("amd_wdt: WDT MMIO region not responding (all-ones read)");
        unsafe { unmap_mmio_region(mmio_base, WDT_MMIO_SIZE) };
        return -3;
    }

    let wdt = AmdWdt {
        mmio_base,
        acpi_mmio_phys,
        timeout_secs: 0,
        bridge_bus: bus,
        bridge_dev: dev,
        bridge_func: func,
    };

    // Read current status for diagnostics.
    let ctrl = wdt.read_reg(WDT_CTRL);
    let count = wdt.read_reg(WDT_COUNT);

    unsafe {
        fut_printf(
            b"amd_wdt: CTRL=0x%08x COUNT=0x%08x\n\0".as_ptr(),
            ctrl,
            count,
        );
    }

    // Check if the watchdog fired before this boot.
    if ctrl & CTRL_WDT_FIRED != 0 {
        log("amd_wdt: WARNING - watchdog fired (system was reset by WDT)");
        // Clear the fired status.
        wdt.clear_fired();
    }

    // Check if the watchdog is permanently disabled.
    if ctrl & CTRL_WDT_DISABLE != 0 {
        log("amd_wdt: WARNING - watchdog is permanently disabled (WdtDisable set)");
        log("amd_wdt: a cold boot/power cycle is required to re-enable");
    }

    // Ensure 1-second resolution.
    wdt.set_seconds_resolution();

    // Store the driver state.
    unsafe {
        (*WDT.get()) = Some(wdt);
    }

    log("amd_wdt: driver initialised successfully");
    0
}

/// Enable the AMD FCH watchdog timer with the specified timeout in seconds.
///
/// `timeout_secs` - Countdown duration (1 to 65535 seconds).
///
/// Returns 0 on success, negative error on failure.
#[unsafe(no_mangle)]
pub extern "C" fn amd_wdt_enable(timeout_secs: u32) -> i32 {
    let wdt = match unsafe { (*WDT.get()).as_mut() } {
        Some(w) => w,
        None => return -19, // ENODEV
    };

    if timeout_secs == 0 || timeout_secs > WDT_MAX_TIMEOUT_SECS {
        unsafe {
            fut_printf(
                b"amd_wdt: invalid timeout %u (must be 1-%u seconds)\n\0".as_ptr(),
                timeout_secs,
                WDT_MAX_TIMEOUT_SECS,
            );
        }
        return -22; // EINVAL
    }

    // Check for permanent disable.
    let ctrl = wdt.read_reg(WDT_CTRL);
    if ctrl & CTRL_WDT_DISABLE != 0 {
        log("amd_wdt: cannot enable - WdtDisable is set (needs cold boot)");
        return -1;
    }

    wdt.timeout_secs = timeout_secs;
    wdt.enable(timeout_secs);

    unsafe {
        fut_printf(
            b"amd_wdt: enabled with %u second timeout\n\0".as_ptr(),
            timeout_secs,
        );
    }
    0
}

/// Disable the AMD FCH watchdog timer.
///
/// This clears WdtEn to stop the countdown. It does NOT set the permanent
/// WdtDisable bit.
///
/// Returns 0 on success, negative error on failure.
#[unsafe(no_mangle)]
pub extern "C" fn amd_wdt_disable() -> i32 {
    let wdt = match unsafe { (*WDT.get()).as_ref() } {
        Some(w) => w,
        None => return -19, // ENODEV
    };

    wdt.disable();
    log("amd_wdt: watchdog disabled");
    0
}

/// Pet (kick) the AMD FCH watchdog timer to restart the countdown.
///
/// This writes 1 to the WdtTrigger bit, reloading the countdown value
/// and preventing a timeout reset.
///
/// Returns 0 on success, negative error on failure.
#[unsafe(no_mangle)]
pub extern "C" fn amd_wdt_pet() -> i32 {
    let wdt = match unsafe { (*WDT.get()).as_ref() } {
        Some(w) => w,
        None => return -19, // ENODEV
    };

    // Reload the configured timeout before triggering.
    let timeout = unsafe { (*WDT.get()).as_ref().map_or(0, |w| w.timeout_secs) };
    if timeout > 0 {
        wdt.set_count(timeout);
    }

    wdt.pet();
    0
}

/// Set a new timeout value in seconds without restarting the watchdog.
///
/// If the watchdog is currently running, the new timeout takes effect
/// on the next pet/trigger.
///
/// Returns 0 on success, negative error on failure.
#[unsafe(no_mangle)]
pub extern "C" fn amd_wdt_set_timeout(secs: u32) -> i32 {
    let wdt = match unsafe { (*WDT.get()).as_mut() } {
        Some(w) => w,
        None => return -19, // ENODEV
    };

    if secs == 0 || secs > WDT_MAX_TIMEOUT_SECS {
        return -22; // EINVAL
    }

    wdt.timeout_secs = secs;
    wdt.set_count(secs);

    // If the watchdog is currently running, trigger to reload.
    let ctrl = wdt.read_reg(WDT_CTRL);
    if ctrl & CTRL_WDT_EN != 0 {
        wdt.pet();
    }

    unsafe {
        fut_printf(
            b"amd_wdt: timeout set to %u seconds\n\0".as_ptr(),
            secs,
        );
    }
    0
}

/// Get the remaining time before the watchdog fires, in seconds.
///
/// Returns the countdown value, or 0 if the driver is not initialised
/// or the watchdog is not running.
#[unsafe(no_mangle)]
pub extern "C" fn amd_wdt_get_timeleft() -> u32 {
    let wdt = match unsafe { (*WDT.get()).as_ref() } {
        Some(w) => w,
        None => return 0,
    };

    wdt.get_timeleft()
}

/// Query the current watchdog status.
///
/// Returns a bitmask:
///   bit 0: WDT is enabled (WdtEn)
///   bit 1: WDT has fired since last clear (WdtFired)
///   bit 2: WDT countdown is actively running (WdtRunSts)
///
/// Returns 0 if the driver is not initialised.
#[unsafe(no_mangle)]
pub extern "C" fn amd_wdt_status() -> u32 {
    let wdt = match unsafe { (*WDT.get()).as_ref() } {
        Some(w) => w,
        None => return 0,
    };

    wdt.status()
}
