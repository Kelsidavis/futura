// SPDX-License-Identifier: MPL-2.0
//
// AMD Platform Security Processor (PSP) Driver for Futura OS
//
// Interfaces with the AMD PSP / AMD Secure Technology co-processor
// found on Ryzen AM4/AM5 CPUs (Zen through Zen4 families).
//
// Architecture:
//   - Shares PCI device with the CCP: vendor 1022h, device 1456h/1468h/15DFh
//   - PSP communicates via a mailbox interface in BAR2 MMIO space
//   - Mailbox registers at BAR2 + PSP offset (typically 0x10570)
//   - CPU-to-PSP (C2P) and PSP-to-CPU (P2C) message registers
//   - Doorbell mechanism to signal the PSP and receive notifications
//
// Mailbox protocol:
//   1. Write command parameters to C2P_MSG_1..15
//   2. Write command ID to C2P_MSG_0
//   3. Ring doorbell (write 1 to C2P_DOORBELL)
//   4. Poll P2C_MSG_0 for response (bit 31 = ready)
//   5. Read results from P2C_MSG_1..15
//
// Supported commands:
//   - GET_FW_VERSION (0x05): retrieve PSP firmware version
//   - GET_BOOT_STATUS (0x14): query PSP boot status
//   - QUERY_CAPS (0x119): query PSP capabilities
//   - PSP_FEATURE_STATUS (0x10): check enabled PSP features
//   - Generic command send/receive for arbitrary PSP commands

#![no_std]
#![forbid(unsafe_op_in_unsafe_fn)]
#![allow(unexpected_cfgs)]

use core::cell::UnsafeCell;
use core::ffi::c_void;
use core::ptr::{read_volatile, write_volatile};
use core::sync::atomic::{fence, Ordering};

use common::{log, map_mmio_region, unmap_mmio_region, MMIO_DEFAULT_FLAGS};

unsafe extern "C" {
    fn fut_printf(fmt: *const u8, ...);
    fn pci_device_count() -> i32;
    fn pci_get_device(index: i32) -> *const PciDevice;
    fn rust_virt_to_phys(vaddr: *const c_void) -> u64;
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

// -- Static state wrapper --

/// Wrapper to allow `UnsafeCell` in a `static` (requires `Sync`).
/// Safety: all access is single-threaded or externally synchronised by the caller.
struct StaticCell<T>(UnsafeCell<T>);
unsafe impl<T> Sync for StaticCell<T> {}
impl<T> StaticCell<T> {
    const fn new(val: T) -> Self { Self(UnsafeCell::new(val)) }
    fn get(&self) -> *mut T { self.0.get() }
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

fn pci_read16(bus: u8, dev: u8, func: u8, offset: u8) -> u16 {
    let val32 = pci_read32(bus, dev, func, offset & 0xFC);
    ((val32 >> ((offset & 2) * 8)) & 0xFFFF) as u16
}

fn pci_write16(bus: u8, dev: u8, func: u8, offset: u8, val: u16) {
    let aligned = offset & 0xFC;
    let shift = (offset & 2) * 8;
    let mut val32 = pci_read32(bus, dev, func, aligned);
    val32 &= !(0xFFFF << shift);
    val32 |= (val as u32) << shift;
    pci_write32(bus, dev, func, aligned, val32);
}

// -- AMD PSP PCI identification --

/// AMD vendor ID.
const AMD_VENDOR_ID: u16 = 0x1022;

/// CCP/PSP device IDs across Ryzen generations (PSP shares the PCI device).
/// Ryzen 1000/2000 (Zen/Zen+).
const PSP_DEVICE_ZEN: u16 = 0x1456;
/// Ryzen 3000 (Zen2).
const PSP_DEVICE_ZEN2: u16 = 0x1468;
/// Ryzen 5000/7000 (Zen3/Zen4).
const PSP_DEVICE_ZEN3: u16 = 0x15DF;

/// PCI class for CCP/PSP: Encryption/Decryption controller.
const PSP_CLASS: u8 = 0x10;
/// PCI subclass: other crypto device.
const PSP_SUBCLASS: u8 = 0x80;

fn is_psp_device(dev: &PciDevice) -> bool {
    dev.vendor_id == AMD_VENDOR_ID
        && (dev.device_id == PSP_DEVICE_ZEN
            || dev.device_id == PSP_DEVICE_ZEN2
            || dev.device_id == PSP_DEVICE_ZEN3)
        && dev.class_code == PSP_CLASS
        && dev.subclass == PSP_SUBCLASS
}

// -- PSP mailbox register offsets (relative to BAR2 + PSP_MBOX_OFFSET) --

/// Base offset of PSP mailbox registers from BAR2.
const PSP_MBOX_OFFSET: usize = 0x10570;

/// C2P_MSG_0: command register (CPU writes command ID here).
const C2P_MSG_0: usize = 0x00;
/// C2P_MSG_1 through C2P_MSG_15: command parameter registers.
/// Each register is at offset 0x04 * (register number).
const C2P_MSG_BASE: usize = 0x04;

/// P2C_MSG_0: response/status register (PSP writes response here).
const P2C_MSG_0: usize = 0x40;
/// P2C_MSG_1 through P2C_MSG_15: response data registers.
const P2C_MSG_BASE: usize = 0x44;

/// C2P_DOORBELL: write bit 0 to signal PSP.
const C2P_DOORBELL: usize = 0x80;
/// P2C_DOORBELL: PSP signals CPU.
const P2C_DOORBELL: usize = 0x84;

/// Number of C2P/P2C parameter registers (MSG_1 through MSG_15).
const MAX_MSG_PARAMS: u32 = 15;

/// Bit 31 of P2C_MSG_0 indicates the response is ready.
const P2C_RESP_READY: u32 = 1 << 31;

// -- PSP command IDs --

/// Trusted Execution Environment initialisation.
const CMD_TEE_INIT: u32 = 0x01;
/// Get PSP firmware version.
const CMD_GET_FW_VERSION: u32 = 0x05;
/// Load a trusted application.
const CMD_LOAD_TRUSTED_APP: u32 = 0x07;
/// PSP feature status.
const CMD_PSP_FEATURE_STATUS: u32 = 0x10;
/// Get PSP boot status.
const CMD_GET_BOOT_STATUS: u32 = 0x14;
/// Ring 3 interrupt configuration.
const CMD_RING3_INTR_CONFIG: u32 = 0x83;
/// Query PSP capabilities.
const CMD_QUERY_CAPS: u32 = 0x119;

// -- BAR2 MMIO size --

/// We map 128 KiB for the BAR2 region to cover CCP and PSP mailbox space.
/// PSP mailbox is at offset 0x10570, so we need at least ~0x10600 bytes.
const BAR2_MMIO_SIZE: usize = 0x20000;

// -- Polling timeout --

/// Maximum number of iterations to wait for PSP mailbox response.
const POLL_TIMEOUT: u32 = 2_000_000;

// -- Driver state --

struct AmdPsp {
    /// Virtual address of BAR2 MMIO base.
    bar2_base: *mut u8,
    /// Physical address of BAR2.
    bar2_phys: u64,
    /// Computed mailbox base: bar2_base + PSP_MBOX_OFFSET.
    mbox_base: *mut u8,
    /// PCI BDF for the device.
    pci_bus: u8,
    pci_dev: u8,
    pci_func: u8,
    /// Device ID (for logging).
    device_id: u16,
    /// Cached firmware version (major, minor), populated after first query.
    fw_major: u32,
    fw_minor: u32,
    /// Whether firmware version has been queried.
    fw_version_valid: bool,
}

static PSP: StaticCell<Option<AmdPsp>> = StaticCell::new(None);

// -- MMIO register helpers --

impl AmdPsp {
    /// Read a 32-bit mailbox register at the given offset from mailbox base.
    fn mbox_read(&self, offset: usize) -> u32 {
        fence(Ordering::SeqCst);
        unsafe { read_volatile(self.mbox_base.add(offset) as *const u32) }
    }

    /// Write a 32-bit mailbox register at the given offset from mailbox base.
    fn mbox_write(&self, offset: usize, val: u32) {
        unsafe { write_volatile(self.mbox_base.add(offset) as *mut u32, val) };
        fence(Ordering::SeqCst);
    }

    /// Send a command to the PSP and wait for a response.
    ///
    /// `cmd`   - Command ID to write to C2P_MSG_0.
    /// `args`  - Slice of up to 15 parameters to write to C2P_MSG_1..15.
    /// `resp`  - Mutable slice of up to 15 entries to receive P2C_MSG_1..15.
    ///
    /// Returns the value of P2C_MSG_0 (status/response) on success,
    /// or a negative error code on timeout.
    fn send_command(&self, cmd: u32, args: &[u32], resp: &mut [u32]) -> i32 {
        // Clear the response ready bit by reading P2C_MSG_0.
        let _ = self.mbox_read(P2C_MSG_0);

        // Write command parameters to C2P_MSG_1..15.
        let nargs = if args.len() > MAX_MSG_PARAMS as usize {
            MAX_MSG_PARAMS as usize
        } else {
            args.len()
        };
        for i in 0..nargs {
            self.mbox_write(C2P_MSG_BASE + i * 4, args[i]);
        }

        // Write the command ID to C2P_MSG_0.
        self.mbox_write(C2P_MSG_0, cmd);

        // Ring the doorbell to signal the PSP.
        self.mbox_write(C2P_DOORBELL, 1);

        // Poll P2C_MSG_0 until bit 31 (response ready) is set.
        let mut timeout = POLL_TIMEOUT;
        loop {
            let status = self.mbox_read(P2C_MSG_0);
            if status & P2C_RESP_READY != 0 {
                // Response is ready. Read result registers.
                let nresp = if resp.len() > MAX_MSG_PARAMS as usize {
                    MAX_MSG_PARAMS as usize
                } else {
                    resp.len()
                };
                for i in 0..nresp {
                    resp[i] = self.mbox_read(P2C_MSG_BASE + i * 4);
                }

                // Return the full status word (caller can inspect error bits).
                return status as i32;
            }

            timeout -= 1;
            if timeout == 0 {
                log("amd_psp: mailbox command timed out");
                return -110; // ETIMEDOUT
            }

            // Yield periodically to avoid monopolising the CPU.
            if timeout % 1000 == 0 {
                common::thread_yield();
            }
        }
    }

    /// Query firmware version from the PSP and cache the result.
    fn query_fw_version(&mut self) -> i32 {
        let mut resp = [0u32; 2];
        let status = self.send_command(CMD_GET_FW_VERSION, &[], &mut resp);
        if status < 0 {
            return status;
        }

        // Response: P2C_MSG_1 = major version, P2C_MSG_2 = minor version.
        self.fw_major = resp[0];
        self.fw_minor = resp[1];
        self.fw_version_valid = true;

        unsafe {
            fut_printf(
                b"amd_psp: firmware version %u.%u\n\0".as_ptr(),
                self.fw_major,
                self.fw_minor,
            );
        }

        0
    }
}

// -- PCI BAR2 reading --

/// Read BAR2 (64-bit MMIO) from PCI config space.
/// BAR2 is at PCI config offset 0x18 (BAR0=0x10, BAR1=0x14, BAR2=0x18).
fn read_bar2(bus: u8, dev: u8, func: u8) -> u64 {
    let bar2_lo = pci_read32(bus, dev, func, 0x18) & !0xF;
    let bar2_hi = pci_read32(bus, dev, func, 0x1C);
    (bar2_lo as u64) | ((bar2_hi as u64) << 32)
}

// -- PCI device discovery --

/// Find an AMD CCP/PSP device on the PCI bus.
/// Returns (bus, dev, func, device_id) if found.
fn find_psp() -> Option<(u8, u8, u8, u16)> {
    let count = unsafe { pci_device_count() };
    for i in 0..count {
        let dev = unsafe { &*pci_get_device(i) };
        if is_psp_device(dev) {
            return Some((dev.bus, dev.dev, dev.func, dev.device_id));
        }
    }
    None
}

// -- PSP mailbox offset detection --

/// Detect the PSP mailbox offset within BAR2.
///
/// Reads a signature/probe value at the expected offset to verify that
/// the PSP mailbox is accessible. Returns the offset on success, or 0
/// if detection fails.
fn detect_mbox_offset(bar2_base: *mut u8) -> usize {
    // The standard PSP mailbox offset is 0x10570 from BAR2 base.
    // Verify accessibility by reading P2C_MSG_0; it should not be all-ones
    // (which would indicate unmapped/invalid MMIO).
    fence(Ordering::SeqCst);
    let probe = unsafe {
        read_volatile(bar2_base.add(PSP_MBOX_OFFSET + P2C_MSG_0) as *const u32)
    };
    if probe != 0xFFFF_FFFF {
        return PSP_MBOX_OFFSET;
    }

    // Fallback: some implementations use offset 0x10500.
    let alt_offset: usize = 0x10500;
    let probe_alt = unsafe {
        read_volatile(bar2_base.add(alt_offset + P2C_MSG_0) as *const u32)
    };
    if probe_alt != 0xFFFF_FFFF {
        return alt_offset;
    }

    0
}

// -- FFI exports --

/// Initialise the AMD PSP driver.
///
/// Scans PCI for an AMD CCP/PSP device, maps BAR2, detects the PSP mailbox
/// offset, and queries the PSP firmware version.
///
/// Returns 0 on success, negative error on failure.
#[unsafe(no_mangle)]
pub extern "C" fn amd_psp_init() -> i32 {
    log("amd_psp: scanning PCI for AMD PSP device...");

    let (bus, dev, func, device_id) = match find_psp() {
        Some(bdf) => bdf,
        None => {
            log("amd_psp: no AMD CCP/PSP device found");
            return -1;
        }
    };

    unsafe {
        fut_printf(
            b"amd_psp: found PSP (device %04x) at PCI %02x:%02x.%x\n\0".as_ptr(),
            device_id as u32,
            bus as u32,
            dev as u32,
            func as u32,
        );
    }

    // Enable PCI memory space access and bus mastering.
    let cmd = pci_read16(bus, dev, func, 0x04);
    pci_write16(bus, dev, func, 0x04, cmd | 0x06);

    // Read BAR2 (64-bit MMIO).
    let bar2_phys = read_bar2(bus, dev, func);
    if bar2_phys == 0 {
        log("amd_psp: BAR2 not configured");
        return -2;
    }

    unsafe {
        fut_printf(
            b"amd_psp: BAR2 phys = 0x%016lx\n\0".as_ptr(),
            bar2_phys,
        );
    }

    // Map the BAR2 MMIO region.
    let bar2_base = unsafe { map_mmio_region(bar2_phys, BAR2_MMIO_SIZE, MMIO_DEFAULT_FLAGS) };
    if bar2_base.is_null() {
        log("amd_psp: failed to map BAR2 MMIO region");
        return -3;
    }

    // Detect PSP mailbox offset within BAR2.
    let mbox_offset = detect_mbox_offset(bar2_base);
    if mbox_offset == 0 {
        log("amd_psp: failed to detect PSP mailbox (MMIO not responding)");
        unsafe { unmap_mmio_region(bar2_base, BAR2_MMIO_SIZE) };
        return -4;
    }

    unsafe {
        fut_printf(
            b"amd_psp: mailbox offset = 0x%x\n\0".as_ptr(),
            mbox_offset as u32,
        );
    }

    let mbox_base = unsafe { bar2_base.add(mbox_offset) };

    let mut psp = AmdPsp {
        bar2_base,
        bar2_phys,
        mbox_base,
        pci_bus: bus,
        pci_dev: dev,
        pci_func: func,
        device_id,
        fw_major: 0,
        fw_minor: 0,
        fw_version_valid: false,
    };

    // Query firmware version to verify the mailbox is functional.
    let ret = psp.query_fw_version();
    if ret < 0 {
        log("amd_psp: failed to query firmware version (mailbox not responding)");
        unsafe { unmap_mmio_region(bar2_base, BAR2_MMIO_SIZE) };
        return -5;
    }

    // Query boot status for diagnostic logging.
    let mut boot_resp = [0u32; 1];
    let boot_status = psp.send_command(CMD_GET_BOOT_STATUS, &[], &mut boot_resp);
    if boot_status >= 0 {
        unsafe {
            fut_printf(
                b"amd_psp: boot status = 0x%08x\n\0".as_ptr(),
                boot_resp[0],
            );
        }
    }

    // Query capabilities for diagnostic logging.
    let mut caps_resp = [0u32; 1];
    let caps_status = psp.send_command(CMD_QUERY_CAPS, &[], &mut caps_resp);
    if caps_status >= 0 {
        unsafe {
            fut_printf(
                b"amd_psp: capabilities = 0x%08x\n\0".as_ptr(),
                caps_resp[0],
            );
        }
    }

    // Query feature status for diagnostic logging.
    let mut feat_resp = [0u32; 1];
    let feat_status = psp.send_command(CMD_PSP_FEATURE_STATUS, &[], &mut feat_resp);
    if feat_status >= 0 {
        unsafe {
            fut_printf(
                b"amd_psp: feature status = 0x%08x\n\0".as_ptr(),
                feat_resp[0],
            );
        }
    }

    unsafe {
        (*PSP.get()) = Some(psp);
    }

    log("amd_psp: driver initialised successfully");
    0
}

/// Get the PSP firmware version.
///
/// `major` - Pointer to receive the major version number.
/// `minor` - Pointer to receive the minor version number.
///
/// Returns 0 on success, negative error on failure.
#[unsafe(no_mangle)]
pub extern "C" fn amd_psp_get_fw_version(major: *mut u32, minor: *mut u32) -> i32 {
    if major.is_null() || minor.is_null() {
        return -22; // EINVAL
    }

    let psp = match unsafe { (*PSP.get()).as_mut() } {
        Some(p) => p,
        None => return -19, // ENODEV
    };

    // If we have not yet queried the firmware version, do so now.
    if !psp.fw_version_valid {
        let ret = psp.query_fw_version();
        if ret < 0 {
            return ret;
        }
    }

    unsafe {
        write_volatile(major, psp.fw_major);
        write_volatile(minor, psp.fw_minor);
    }

    0
}

/// Get the PSP boot status.
///
/// Returns the boot status word from P2C_MSG_1 on success,
/// or 0 if the PSP is not initialised or the command fails.
#[unsafe(no_mangle)]
pub extern "C" fn amd_psp_get_boot_status() -> u32 {
    let psp = match unsafe { (*PSP.get()).as_ref() } {
        Some(p) => p,
        None => return 0,
    };

    let mut resp = [0u32; 1];
    let status = psp.send_command(CMD_GET_BOOT_STATUS, &[], &mut resp);
    if status < 0 {
        return 0;
    }

    resp[0]
}

/// Query PSP capabilities.
///
/// Returns the capabilities bitmask from P2C_MSG_1 on success,
/// or 0 if the PSP is not initialised or the command fails.
#[unsafe(no_mangle)]
pub extern "C" fn amd_psp_query_caps() -> u32 {
    let psp = match unsafe { (*PSP.get()).as_ref() } {
        Some(p) => p,
        None => return 0,
    };

    let mut resp = [0u32; 1];
    let status = psp.send_command(CMD_QUERY_CAPS, &[], &mut resp);
    if status < 0 {
        return 0;
    }

    resp[0]
}

/// Check whether an AMD PSP device is present and initialised.
///
/// Returns true if the driver has been successfully initialised, false otherwise.
#[unsafe(no_mangle)]
pub extern "C" fn amd_psp_is_present() -> bool {
    unsafe { (*PSP.get()).is_some() }
}

/// Send a generic command to the PSP mailbox.
///
/// `cmd`   - PSP command ID.
/// `args`  - Pointer to an array of command parameters (written to C2P_MSG_1..15).
/// `nargs` - Number of command parameters (max 15).
/// `resp`  - Pointer to a buffer for response data (read from P2C_MSG_1..15).
/// `nresp` - Number of response words to read (max 15).
///
/// Returns the P2C_MSG_0 status word (with bit 31 = ready) on success,
/// or a negative error code on failure.
#[unsafe(no_mangle)]
pub extern "C" fn amd_psp_send_command(
    cmd: u32,
    args: *const u32,
    nargs: u32,
    resp: *mut u32,
    nresp: u32,
) -> i32 {
    let psp = match unsafe { (*PSP.get()).as_ref() } {
        Some(p) => p,
        None => return -19, // ENODEV
    };

    // Clamp parameter counts to MAX_MSG_PARAMS.
    let nargs_clamped = if nargs > MAX_MSG_PARAMS {
        MAX_MSG_PARAMS as usize
    } else {
        nargs as usize
    };
    let nresp_clamped = if nresp > MAX_MSG_PARAMS {
        MAX_MSG_PARAMS as usize
    } else {
        nresp as usize
    };

    // Build argument slice from the raw pointer.
    let arg_slice = if args.is_null() || nargs_clamped == 0 {
        &[] as &[u32]
    } else {
        unsafe { core::slice::from_raw_parts(args, nargs_clamped) }
    };

    // Build a mutable response buffer on the stack and copy results out.
    let mut resp_buf = [0u32; 15];
    let status = psp.send_command(cmd, arg_slice, &mut resp_buf[..nresp_clamped]);

    // Copy response data to the caller's buffer.
    if status >= 0 && !resp.is_null() && nresp_clamped > 0 {
        for i in 0..nresp_clamped {
            unsafe {
                write_volatile(resp.add(i), resp_buf[i]);
            }
        }
    }

    status
}
