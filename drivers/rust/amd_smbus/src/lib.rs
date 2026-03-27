// SPDX-License-Identifier: MPL-2.0
//
// AMD FCH SMBus/I2C Controller Driver for Futura OS
//
// Implements the AMD Fusion Controller Hub (FCH) SMBus 2.0 controller
// found on AM4 (X370-X570) and AM5 (X670-X870) platforms.
//
// Architecture:
//   - I/O port-based register access (BAR0 is I/O space)
//   - SMBus 2.0 compatible: Quick, Byte, Word, Block transfers
//   - Polling-based completion with timeout
//   - PCI discovery for AMD vendor 1022h, device 790Bh/790Eh
//
// PCI class: 0Ch (Serial Bus), subclass 05h (SMBus)
//
// Register access uses x86 IN/OUT instructions to the I/O base
// obtained from PCI BAR0 (or PCI config offset 0x10).

#![no_std]
#![forbid(unsafe_op_in_unsafe_fn)]
#![allow(unexpected_cfgs)]

use core::ptr::{read_volatile, write_volatile};
use core::sync::atomic::{fence, Ordering};

use common::log;

unsafe extern "C" {
    fn fut_printf(fmt: *const u8, ...);
    fn pci_device_count() -> i32;
    fn pci_get_device(index: i32) -> *const PciDevice;
}

// ── PCI device structure (mirrors kernel/pci.h) ──

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

fn pci_read8(bus: u8, dev: u8, func: u8, offset: u8) -> u8 {
    let val32 = pci_read32(bus, dev, func, offset & 0xFC);
    ((val32 >> ((offset & 3) * 8)) & 0xFF) as u8
}

// ── x86 I/O port helpers ──

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
fn io_delay() {
    io_inb(0x80);
}

// ── AMD FCH SMBus PCI identification ──

/// AMD vendor ID.
const AMD_VENDOR_ID: u16 = 0x1022;
/// AM4 platforms (X370, B350, X470, B450, X570, B550, A520).
const AMD_SMBUS_DEVICE_AM4: u16 = 0x790B;
/// AM5 platforms (X670, B650, X870, B850, A620).
const AMD_SMBUS_DEVICE_AM5: u16 = 0x790E;

/// PCI class: Serial Bus Controller.
const PCI_CLASS_SERIAL: u8 = 0x0C;
/// PCI subclass: SMBus.
const PCI_SUBCLASS_SMBUS: u8 = 0x05;

// ── SMBus I/O Register Offsets (relative to I/O base) ──

/// Status register.
const SMB_STATUS: u16 = 0x00;
/// Control register.
const SMB_CONTROL: u16 = 0x02;
/// Command byte (register address on target device).
const SMB_COMMAND: u16 = 0x04;
/// Target address (bits 7:1 = 7-bit addr, bit 0 = R/W direction).
const SMB_ADDRESS: u16 = 0x05;
/// Data byte 0.
const SMB_DATA0: u16 = 0x06;
/// Data byte 1.
const SMB_DATA1: u16 = 0x07;
/// Block data port (auto-incrementing FIFO).
const SMB_BLOCK_DATA: u16 = 0x08;

// ── SMB_STATUS bits ──

/// Host controller is busy.
const STATUS_HOST_BUSY: u8 = 1 << 0;
/// Transfer completed successfully (interrupt flag).
const STATUS_INTR: u8 = 1 << 1;
/// Device error (NACK or protocol violation).
const STATUS_DEV_ERR: u8 = 1 << 2;
/// Bus collision detected.
const STATUS_BUS_COL: u8 = 1 << 3;
/// Transaction failed (e.g. timeout on bus).
const STATUS_FAILED: u8 = 1 << 4;
/// Mask of all error bits.
const STATUS_ERROR_MASK: u8 = STATUS_DEV_ERR | STATUS_BUS_COL | STATUS_FAILED;
/// Mask of all clearable status bits (write 1 to clear).
const STATUS_CLEAR_MASK: u8 = STATUS_INTR | STATUS_DEV_ERR | STATUS_BUS_COL | STATUS_FAILED;

// ── SMB_CONTROL bits and fields ──

/// Abort the current transfer.
const CONTROL_KILL: u8 = 1 << 1;
/// Initiate a transfer.
const CONTROL_START: u8 = 1 << 3;
/// Enable interrupt on completion.
const CONTROL_INTREN: u8 = 1 << 6;

// ── SMBus protocol types (bits 4:2 of SMB_CONTROL) ──

/// Quick Command (address only, no data).
const SMB_CMD_QUICK: u8 = 0x00 << 2;
/// Send/Receive Byte (address + 1 data byte, no command).
const SMB_CMD_BYTE: u8 = 0x01 << 2;
/// Byte Data (address + command + 1 data byte).
const SMB_CMD_BYTE_DATA: u8 = 0x02 << 2;
/// Word Data (address + command + 2 data bytes).
const SMB_CMD_WORD_DATA: u8 = 0x03 << 2;
/// Block (address + command + count + up to 32 data bytes).
const SMB_CMD_BLOCK: u8 = 0x05 << 2;

// ── Timeout and limits ──

/// Maximum poll iterations (~50 ms at typical loop overhead).
const POLL_TIMEOUT: u32 = 500_000;
/// Maximum block transfer size per SMBus 2.0 specification.
const SMBUS_BLOCK_MAX: u8 = 32;

// ── Common I2C/SPD addresses ──

/// SPD EEPROM base address (DIMM slot 0). SPD occupies 0x50-0x57.
const SPD_BASE_ADDR: u8 = 0x50;
/// Temperature Sensor (TSE2004av) base address. Occupies 0x18-0x1F.
const TSOD_BASE_ADDR: u8 = 0x18;
/// TSE2004av temperature register (read-only, 16-bit).
const TSOD_TEMP_REG: u8 = 0x05;

// ── Controller state ──

struct AmdSmbus {
    /// I/O port base address for SMBus registers.
    io_base: u16,
    /// PCI bus/device/function.
    bus: u8,
    dev: u8,
    func: u8,
    /// Device ID (AM4 or AM5 variant).
    device_id: u16,
}

static mut SMBUS: Option<AmdSmbus> = None;

// ── SMBus register I/O ──

impl AmdSmbus {
    /// Read an SMBus register.
    fn read_reg(&self, offset: u16) -> u8 {
        io_inb(self.io_base + offset)
    }

    /// Write an SMBus register.
    fn write_reg(&self, offset: u16, val: u8) {
        io_outb(self.io_base + offset, val);
    }

    /// Clear all pending status bits by writing 1s to the clearable flags.
    fn clear_status(&self) {
        self.write_reg(SMB_STATUS, STATUS_CLEAR_MASK);
    }

    /// Wait for the host controller to become idle (not busy).
    /// Returns 0 on success, -1 on timeout.
    fn wait_idle(&self) -> i32 {
        for _ in 0..POLL_TIMEOUT {
            let status = self.read_reg(SMB_STATUS);
            if status & STATUS_HOST_BUSY == 0 {
                return 0;
            }
            io_delay();
        }
        -1
    }

    /// Wait for a transfer to complete. Polls for INTR (success) or error bits.
    /// Returns 0 on success, negative error code on failure.
    fn wait_completion(&self) -> i32 {
        for _ in 0..POLL_TIMEOUT {
            let status = self.read_reg(SMB_STATUS);

            // Check for errors first.
            if status & STATUS_FAILED != 0 {
                self.clear_status();
                return -5; // EIO
            }
            if status & STATUS_BUS_COL != 0 {
                self.clear_status();
                return -11; // EAGAIN (bus collision, retry)
            }
            if status & STATUS_DEV_ERR != 0 {
                self.clear_status();
                return -6; // ENXIO (device not responding)
            }

            // Success: transfer completed.
            if status & STATUS_INTR != 0 {
                self.clear_status();
                return 0;
            }

            io_delay();
        }
        // Timed out waiting for completion. Kill the transaction.
        self.abort();
        -110 // ETIMEDOUT
    }

    /// Abort the current transaction by setting the KILL bit,
    /// then clear status and wait briefly for the controller to settle.
    fn abort(&self) {
        self.write_reg(SMB_CONTROL, CONTROL_KILL);
        io_delay();
        // Clear the KILL bit.
        self.write_reg(SMB_CONTROL, 0);
        // Clear all status bits.
        self.clear_status();
        // Brief delay to let the bus settle.
        for _ in 0..100 {
            io_delay();
        }
    }

    /// Prepare a transaction: wait for idle, clear status, set address and command byte.
    /// `addr7` is the 7-bit I2C address.
    /// `read` indicates direction (true = read from device).
    /// `cmd` is the SMBus command byte (register address on the target).
    fn setup(&self, addr7: u8, read: bool, cmd: u8) -> i32 {
        // Wait for any previous transaction to finish.
        if self.wait_idle() != 0 {
            log("amd_smbus: bus busy, aborting stale transaction");
            self.abort();
            if self.wait_idle() != 0 {
                return -16; // EBUSY
            }
        }

        // Clear status from prior operations.
        self.clear_status();

        // Set the target address with R/W bit.
        let addr_rw = (addr7 << 1) | (if read { 1 } else { 0 });
        self.write_reg(SMB_ADDRESS, addr_rw);

        // Set the command byte (register address).
        self.write_reg(SMB_COMMAND, cmd);

        0
    }

    /// Start a transaction with the given protocol type.
    fn start(&self, protocol: u8) {
        fence(Ordering::SeqCst);
        self.write_reg(SMB_CONTROL, CONTROL_START | protocol);
    }

    // ── Public transfer methods ──

    /// Quick Command: sends just the address byte with R/W direction.
    fn quick_command(&self, addr7: u8, read: bool) -> i32 {
        let rc = self.setup(addr7, read, 0);
        if rc != 0 { return rc; }
        self.start(SMB_CMD_QUICK);
        self.wait_completion()
    }

    /// Read a single byte via Byte Data protocol.
    /// Returns 0 on success and writes the byte to `*out`.
    fn read_byte_data(&self, addr7: u8, cmd: u8, out: &mut u8) -> i32 {
        let rc = self.setup(addr7, true, cmd);
        if rc != 0 { return rc; }
        self.start(SMB_CMD_BYTE_DATA);
        let rc = self.wait_completion();
        if rc != 0 { return rc; }
        *out = self.read_reg(SMB_DATA0);
        0
    }

    /// Write a single byte via Byte Data protocol.
    fn write_byte_data(&self, addr7: u8, cmd: u8, val: u8) -> i32 {
        let rc = self.setup(addr7, false, cmd);
        if rc != 0 { return rc; }
        self.write_reg(SMB_DATA0, val);
        self.start(SMB_CMD_BYTE_DATA);
        self.wait_completion()
    }

    /// Read a 16-bit word via Word Data protocol (little-endian on the bus).
    fn read_word_data(&self, addr7: u8, cmd: u8, out: &mut u16) -> i32 {
        let rc = self.setup(addr7, true, cmd);
        if rc != 0 { return rc; }
        self.start(SMB_CMD_WORD_DATA);
        let rc = self.wait_completion();
        if rc != 0 { return rc; }
        let lo = self.read_reg(SMB_DATA0) as u16;
        let hi = self.read_reg(SMB_DATA1) as u16;
        *out = lo | (hi << 8);
        0
    }

    /// Write a 16-bit word via Word Data protocol.
    fn write_word_data(&self, addr7: u8, cmd: u8, val: u16) -> i32 {
        let rc = self.setup(addr7, false, cmd);
        if rc != 0 { return rc; }
        self.write_reg(SMB_DATA0, val as u8);
        self.write_reg(SMB_DATA1, (val >> 8) as u8);
        self.start(SMB_CMD_WORD_DATA);
        self.wait_completion()
    }

    /// Read a block of bytes via Block protocol.
    /// The first byte returned by the device is the count.
    /// Returns the number of bytes read (positive), or negative error.
    fn read_block_data(&self, addr7: u8, cmd: u8, buf: &mut [u8]) -> i32 {
        if buf.is_empty() {
            return -22; // EINVAL
        }

        let rc = self.setup(addr7, true, cmd);
        if rc != 0 { return rc; }

        self.start(SMB_CMD_BLOCK);
        let rc = self.wait_completion();
        if rc != 0 { return rc; }

        // The device returns the byte count in DATA0.
        let mut count = self.read_reg(SMB_DATA0);
        if count == 0 {
            return 0;
        }
        if count > SMBUS_BLOCK_MAX {
            count = SMBUS_BLOCK_MAX;
        }
        let actual = count.min(buf.len() as u8);

        // Read bytes from the block data port (auto-incrementing).
        for i in 0..actual {
            buf[i as usize] = self.read_reg(SMB_BLOCK_DATA);
        }
        // Drain any extra bytes the device sent beyond our buffer.
        for _ in actual..count {
            let _ = self.read_reg(SMB_BLOCK_DATA);
        }

        actual as i32
    }

    /// Write a block of bytes via Block protocol.
    /// Returns 0 on success, negative error.
    fn write_block_data(&self, addr7: u8, cmd: u8, buf: &[u8]) -> i32 {
        if buf.is_empty() || buf.len() > SMBUS_BLOCK_MAX as usize {
            return -22; // EINVAL
        }

        let rc = self.setup(addr7, false, cmd);
        if rc != 0 { return rc; }

        // Set byte count.
        self.write_reg(SMB_DATA0, buf.len() as u8);

        // Load data into block data port (auto-incrementing).
        for &b in buf {
            self.write_reg(SMB_BLOCK_DATA, b);
        }

        self.start(SMB_CMD_BLOCK);
        self.wait_completion()
    }

    /// Read a temperature value from a TSE2004av-compatible TSOD (JEDEC JC-42.4).
    ///
    /// `channel` selects DIMM slot (0-7 maps to I2C addresses 0x18-0x1F).
    ///
    /// Returns temperature in millidegrees Celsius, or negative error.
    ///
    /// The TSE2004av temperature register (offset 0x05) format:
    ///   - Bit 15:13 = flag bits (sign at bit 12)
    ///   - Bit 12    = sign (1 = negative)
    ///   - Bit 11:4  = integer part
    ///   - Bit 3:0   = fractional part (1/16th degree steps)
    fn read_temperature(&self, channel: u8) -> i32 {
        if channel > 7 {
            return -22; // EINVAL
        }
        let addr = TSOD_BASE_ADDR + channel;
        let mut raw: u16 = 0;
        let rc = self.read_word_data(addr, TSOD_TEMP_REG, &mut raw);
        if rc != 0 {
            return rc;
        }

        // TSE2004av returns big-endian; swap bytes since our read_word_data
        // reads low byte first from DATA0, high byte from DATA1.
        // The hardware actually puts MSB in DATA0 for word reads on TSOD,
        // but the FCH treats it as little-endian. We need to byte-swap.
        let raw_be = ((raw & 0xFF) << 8) | ((raw >> 8) & 0xFF);

        // Extract sign and magnitude.
        let sign = (raw_be >> 12) & 1;
        let magnitude = raw_be & 0x0FFF;

        // Convert to millidegrees: each LSB = 0.0625 degrees C = 62.5 milli-degrees.
        // magnitude * 625 / 10 = millidegrees.
        let millideg = (magnitude as i32) * 625 / 10;

        if sign != 0 {
            -millideg
        } else {
            millideg
        }
    }
}

// ── PCI discovery ──

/// Find AMD FCH SMBus controller on the PCI bus.
/// Returns (bus, dev, func, device_id) if found.
fn find_amd_smbus() -> Option<(u8, u8, u8, u16)> {
    let count = unsafe { pci_device_count() };
    for i in 0..count {
        let dev = unsafe { &*pci_get_device(i) };
        if dev.vendor_id == AMD_VENDOR_ID
            && (dev.device_id == AMD_SMBUS_DEVICE_AM4 || dev.device_id == AMD_SMBUS_DEVICE_AM5)
            && dev.class_code == PCI_CLASS_SERIAL
            && dev.subclass == PCI_SUBCLASS_SMBUS
        {
            return Some((dev.bus, dev.dev, dev.func, dev.device_id));
        }
    }
    None
}

/// Read the SMBus I/O base address from PCI BAR0.
///
/// AMD FCH SMBus uses an I/O BAR (bit 0 of BAR is 1 for I/O space).
/// The I/O base is in bits 15:2 of BAR0.
/// As a fallback, the legacy SMBus base can be found at PCI config offset 0x90.
fn get_io_base(bus: u8, dev: u8, func: u8) -> Option<u16> {
    // Try BAR0 first (PCI config offset 0x10).
    let bar0 = pci_read32(bus, dev, func, 0x10);
    if bar0 & 0x01 != 0 {
        // I/O space BAR: bits 15:2 are the base address.
        let base = (bar0 & 0xFFFC) as u16;
        if base != 0 && base != 0xFFFC {
            return Some(base);
        }
    }

    // Fallback: AMD FCH stores the SMBus base at PCI config offset 0x90.
    // This is a legacy decode register specific to AMD south bridges.
    let legacy = pci_read32(bus, dev, func, 0x90);
    let base = (legacy & 0xFF00) as u16;
    if base != 0 && base != 0xFF00 {
        return Some(base);
    }

    // Last resort: try the standard AMD FCH default I/O base 0x0B00.
    // Many AMD boards use this as the default SMBus port.
    Some(0x0B00)
}

/// Verify the SMBus controller is responsive by reading the status register.
/// A valid controller should return a value that is not 0xFF (bus float).
fn verify_controller(io_base: u16) -> bool {
    let status = io_inb(io_base + SMB_STATUS);
    // 0xFF typically means nothing is mapped at this I/O port.
    status != 0xFF
}

// ── Controller initialisation ──

fn controller_reset(smbus: &AmdSmbus) {
    // Abort any in-progress transaction.
    smbus.abort();

    // Enable the SMBus host controller in PCI config.
    // AMD FCH has a host configuration register at PCI offset 0xD2.
    // Bit 0 = SMBus host enable.
    let hostcfg = pci_read8(smbus.bus, smbus.dev, smbus.func, 0xD2);
    if hostcfg & 0x01 == 0 {
        // Enable the host controller.
        let val32 = pci_read32(smbus.bus, smbus.dev, smbus.func, 0xD0);
        let byte_shift = (0xD2 & 3) * 8;
        let mask = !(0xFF << byte_shift);
        let new_val = (val32 & mask) | (((hostcfg | 0x01) as u32) << byte_shift);
        pci_write32(smbus.bus, smbus.dev, smbus.func, 0xD0, new_val);
        log("amd_smbus: enabled SMBus host controller");
    }

    // Clear all pending status bits.
    smbus.clear_status();
}

// ── FFI exports ──

/// Initialise the AMD FCH SMBus controller.
///
/// Scans PCI for the AMD SMBus device, retrieves the I/O base address,
/// resets the controller, and verifies it is responsive.
///
/// Returns 0 on success, negative error on failure.
#[unsafe(no_mangle)]
pub extern "C" fn amd_smbus_init() -> i32 {
    log("amd_smbus: scanning PCI for AMD FCH SMBus controller...");

    let (bus, dev, func, device_id) = match find_amd_smbus() {
        Some(bdf) => bdf,
        None => {
            log("amd_smbus: no AMD SMBus controller found");
            return -1;
        }
    };

    let platform = if device_id == AMD_SMBUS_DEVICE_AM4 { "AM4" } else { "AM5" };
    unsafe {
        fut_printf(
            b"amd_smbus: found %s controller (device %04x) at PCI %02x:%02x.%x\n\0".as_ptr(),
            platform.as_ptr(),
            device_id as u32,
            bus as u32,
            dev as u32,
            func as u32,
        );
    }

    // Enable I/O space access in PCI command register.
    let cmd = pci_read16(bus, dev, func, 0x04);
    if cmd & 0x01 == 0 {
        pci_write16(bus, dev, func, 0x04, cmd | 0x01);
    }

    // Get the SMBus I/O base address.
    let io_base = match get_io_base(bus, dev, func) {
        Some(base) => base,
        None => {
            log("amd_smbus: failed to determine I/O base address");
            return -2;
        }
    };

    if !verify_controller(io_base) {
        unsafe {
            fut_printf(
                b"amd_smbus: controller not responding at I/O base 0x%04x\n\0".as_ptr(),
                io_base as u32,
            );
        }
        return -3;
    }

    unsafe {
        fut_printf(b"amd_smbus: I/O base = 0x%04x\n\0".as_ptr(), io_base as u32);
    }

    let smbus = AmdSmbus {
        io_base,
        bus,
        dev,
        func,
        device_id,
    };

    // Reset and enable the controller.
    controller_reset(&smbus);

    // Verify the controller is idle after reset.
    let status = smbus.read_reg(SMB_STATUS);
    if status & STATUS_HOST_BUSY != 0 {
        log("amd_smbus: controller stuck busy after reset");
        smbus.abort();
    }

    unsafe {
        core::ptr::addr_of_mut!(SMBUS).write(Some(smbus));
    }

    log("amd_smbus: controller initialised successfully");
    0
}

/// Read a single byte from an SMBus device.
///
/// `addr` - 7-bit I2C address of the target device.
/// `cmd`  - Command/register byte.
/// `out`  - Pointer to receive the read byte.
///
/// Returns 0 on success, negative error code on failure.
#[unsafe(no_mangle)]
pub extern "C" fn amd_smbus_read_byte(addr: u8, cmd: u8, out: *mut u8) -> i32 {
    if out.is_null() {
        return -22; // EINVAL
    }
    let smbus = match unsafe { (*core::ptr::addr_of!(SMBUS)).as_ref() } {
        Some(s) => s,
        None => return -19, // ENODEV
    };
    let mut val: u8 = 0;
    let rc = smbus.read_byte_data(addr, cmd, &mut val);
    if rc == 0 {
        unsafe { write_volatile(out, val) };
    }
    rc
}

/// Write a single byte to an SMBus device.
///
/// `addr` - 7-bit I2C address of the target device.
/// `cmd`  - Command/register byte.
/// `val`  - Byte value to write.
///
/// Returns 0 on success, negative error code on failure.
#[unsafe(no_mangle)]
pub extern "C" fn amd_smbus_write_byte(addr: u8, cmd: u8, val: u8) -> i32 {
    let smbus = match unsafe { (*core::ptr::addr_of!(SMBUS)).as_ref() } {
        Some(s) => s,
        None => return -19, // ENODEV
    };
    smbus.write_byte_data(addr, cmd, val)
}

/// Read a 16-bit word from an SMBus device.
///
/// `addr` - 7-bit I2C address.
/// `cmd`  - Command/register byte.
/// `out`  - Pointer to receive the 16-bit word (little-endian).
///
/// Returns 0 on success, negative error code on failure.
#[unsafe(no_mangle)]
pub extern "C" fn amd_smbus_read_word(addr: u8, cmd: u8, out: *mut u16) -> i32 {
    if out.is_null() {
        return -22; // EINVAL
    }
    let smbus = match unsafe { (*core::ptr::addr_of!(SMBUS)).as_ref() } {
        Some(s) => s,
        None => return -19, // ENODEV
    };
    let mut val: u16 = 0;
    let rc = smbus.read_word_data(addr, cmd, &mut val);
    if rc == 0 {
        unsafe { write_volatile(out, val) };
    }
    rc
}

/// Write a 16-bit word to an SMBus device.
///
/// `addr` - 7-bit I2C address.
/// `cmd`  - Command/register byte.
/// `val`  - 16-bit word to write (little-endian).
///
/// Returns 0 on success, negative error code on failure.
#[unsafe(no_mangle)]
pub extern "C" fn amd_smbus_write_word(addr: u8, cmd: u8, val: u16) -> i32 {
    let smbus = match unsafe { (*core::ptr::addr_of!(SMBUS)).as_ref() } {
        Some(s) => s,
        None => return -19, // ENODEV
    };
    smbus.write_word_data(addr, cmd, val)
}

/// Read a block of bytes from an SMBus device.
///
/// `addr`    - 7-bit I2C address.
/// `cmd`     - Command/register byte.
/// `buf`     - Buffer to receive data.
/// `max_len` - Maximum number of bytes to read (buffer size).
///
/// Returns the number of bytes actually read (positive), or negative error.
#[unsafe(no_mangle)]
pub extern "C" fn amd_smbus_read_block(addr: u8, cmd: u8, buf: *mut u8, max_len: u8) -> i32 {
    if buf.is_null() || max_len == 0 {
        return -22; // EINVAL
    }
    let smbus = match unsafe { (*core::ptr::addr_of!(SMBUS)).as_ref() } {
        Some(s) => s,
        None => return -19, // ENODEV
    };
    let slice = unsafe { core::slice::from_raw_parts_mut(buf, max_len as usize) };
    smbus.read_block_data(addr, cmd, slice)
}

/// Write a block of bytes to an SMBus device.
///
/// `addr` - 7-bit I2C address.
/// `cmd`  - Command/register byte.
/// `buf`  - Data bytes to write.
/// `len`  - Number of bytes to write (1-32).
///
/// Returns 0 on success, negative error code on failure.
#[unsafe(no_mangle)]
pub extern "C" fn amd_smbus_write_block(addr: u8, cmd: u8, buf: *const u8, len: u8) -> i32 {
    if buf.is_null() || len == 0 || len > SMBUS_BLOCK_MAX {
        return -22; // EINVAL
    }
    let smbus = match unsafe { (*core::ptr::addr_of!(SMBUS)).as_ref() } {
        Some(s) => s,
        None => return -19, // ENODEV
    };
    let slice = unsafe { core::slice::from_raw_parts(buf, len as usize) };
    smbus.write_block_data(addr, cmd, slice)
}

/// Read a DIMM temperature sensor (TSE2004av / JEDEC JC-42.4 TSOD).
///
/// `channel` - DIMM slot index (0-7), mapped to I2C addresses 0x18-0x1F.
///
/// Returns the temperature in millidegrees Celsius (e.g., 45500 = 45.5 C),
/// or a negative error code on failure.
#[unsafe(no_mangle)]
pub extern "C" fn amd_smbus_read_temp_sensor(channel: u8) -> i32 {
    let smbus = match unsafe { (*core::ptr::addr_of!(SMBUS)).as_ref() } {
        Some(s) => s,
        None => return -19, // ENODEV
    };
    smbus.read_temperature(channel)
}
