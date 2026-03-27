// SPDX-License-Identifier: MPL-2.0
//
// AMD SB-TSI (Sideband Temperature Sensor Interface) Driver for Futura OS
//
// Implements the AMD SB-TSI temperature sensor interface found on Ryzen
// CPUs on AM4 (X370-X570) and AM5 (X670-X870) platforms.
//
// Architecture:
//   - SMBus-based register access at 7-bit address 0x4C (default)
//   - Minimal SMBus byte read/write reimplemented via AMD FCH I/O ports
//   - Provides CPU temperature in millidegrees Celsius
//   - Configurable high/low alert thresholds and temperature offset
//
// The SB-TSI is an SMBus slave device built into Ryzen CPUs. It exposes
// CPU temperature, alert thresholds, and configuration through standard
// SMBus byte data read/write transactions. The SMBus controller is the
// AMD FCH, accessed via I/O port registers.
//
// SMBus I/O registers (relative to base, default 0x0B00):
//   0x00 STATUS, 0x02 CONTROL, 0x03 HOST_CMD, 0x04 ADDRESS,
//   0x05 DATA0, 0x06 DATA1

#![no_std]
#![forbid(unsafe_op_in_unsafe_fn)]
#![allow(unexpected_cfgs)]

use core::cell::UnsafeCell;
use core::sync::atomic::{fence, Ordering};

use common::log;

unsafe extern "C" {
    fn fut_printf(fmt: *const u8, ...);
}

// ── Static state wrapper ──

/// Wrapper to allow `UnsafeCell` in a `static` (requires `Sync`).
/// Safety: all access is single-threaded or externally synchronised by the caller.
struct StaticCell<T>(UnsafeCell<T>);
unsafe impl<T> Sync for StaticCell<T> {}
impl<T> StaticCell<T> {
    const fn new(val: T) -> Self { Self(UnsafeCell::new(val)) }
    fn get(&self) -> *mut T { self.0.get() }
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

// ── SMBus I/O Register Offsets (relative to I/O base) ──

/// Status register.
const SMB_STATUS: u16 = 0x00;
/// Control register.
const SMB_CONTROL: u16 = 0x02;
/// Host command byte (register address on target device).
const SMB_HOST_CMD: u16 = 0x03;
/// Target address (bits 7:1 = 7-bit addr, bit 0 = R/W direction).
const SMB_ADDRESS: u16 = 0x04;
/// Data byte 0.
const SMB_DATA0: u16 = 0x05;
/// Data byte 1.
const SMB_DATA1: u16 = 0x06;

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
/// Mask of all clearable status bits (write 1 to clear).
const STATUS_CLEAR_MASK: u8 = STATUS_INTR | STATUS_DEV_ERR | STATUS_BUS_COL | STATUS_FAILED;

// ── SMB_CONTROL bits and fields ──

/// Abort the current transfer.
const CONTROL_KILL: u8 = 1 << 1;
/// Initiate a transfer.
const CONTROL_START: u8 = 1 << 3;
/// Byte Data protocol (bits 4:2 = 0x02).
const SMB_CMD_BYTE_DATA: u8 = 0x02 << 2;

// ── Timeout ──

/// Maximum poll iterations (~50 ms at typical loop overhead).
const POLL_TIMEOUT: u32 = 500_000;

// ── SB-TSI SMBus address ──

/// Default SB-TSI 7-bit SMBus address on Ryzen CPUs.
const SBTSI_DEFAULT_ADDR: u8 = 0x4C;

// ── SB-TSI Register Map ──

/// CPU temperature integer part (degrees C, unsigned, read-only).
const SBTSI_CPU_TEMP_INT: u8 = 0x01;
/// SB-TSI status register.
const SBTSI_STATUS: u8 = 0x02;
/// SB-TSI configuration register (read-only view).
const SBTSI_CONFIG: u8 = 0x03;
/// High temperature threshold — integer part.
const SBTSI_HIGH_TEMP_INT: u8 = 0x07;
/// Low temperature threshold — integer part.
const SBTSI_LOW_TEMP_INT: u8 = 0x08;
/// Configuration write register.
const SBTSI_CONFIG_WR: u8 = 0x09;
/// Temperature offset — integer part (signed).
const SBTSI_TEMP_OFFSET_INT: u8 = 0x0A;
/// CPU temperature decimal part (bits [7:5] = 0.125 C increments, read-only).
const SBTSI_CPU_TEMP_DEC: u8 = 0x10;
/// Temperature offset — decimal part (bits [7:5]).
const SBTSI_TEMP_OFFSET_DEC: u8 = 0x11;
/// High temperature threshold — decimal part (bits [7:5]).
const SBTSI_HIGH_TEMP_DEC: u8 = 0x13;
/// Low temperature threshold — decimal part (bits [7:5]).
const SBTSI_LOW_TEMP_DEC: u8 = 0x14;
/// Manufacturer ID register (should return 0x00 for AMD).
const SBTSI_MANUFACTURER_ID: u8 = 0xFE;
/// Silicon revision register.
const SBTSI_REVISION: u8 = 0xFF;

// ── SB-TSI STATUS bits ──

/// Temperature is above the high threshold.
const SBTSI_STATUS_TEMP_HIGH_ALERT: u8 = 1 << 7;
/// Temperature is below the low threshold.
const SBTSI_STATUS_TEMP_LOW_ALERT: u8 = 1 << 6;
/// SB-TSI is busy updating temperature.
const SBTSI_STATUS_BUSY: u8 = 1 << 0;

// ── SB-TSI CONFIG bits ──

/// Mask ALERT# pin output.
const SBTSI_CONFIG_ALERT_MASK: u8 = 1 << 7;
/// Run/Stop: 1 = conversions stopped, 0 = continuous conversions.
const SBTSI_CONFIG_RUN_STOP: u8 = 1 << 6;

// ── AMD manufacturer ID ──

const AMD_MANUFACTURER_ID: u8 = 0x00;

// ── Driver state ──

struct AmdSbTsi {
    /// SMBus I/O port base address.
    smbus_base: u16,
    /// SB-TSI 7-bit SMBus address.
    addr: u8,
    /// Silicon revision (read during init).
    revision: u8,
}

static SBTSI: StaticCell<Option<AmdSbTsi>> = StaticCell::new(None);

// ── Minimal SMBus byte-level I/O ──

impl AmdSbTsi {
    /// Read an SMBus I/O register.
    fn smb_read(&self, offset: u16) -> u8 {
        io_inb(self.smbus_base + offset)
    }

    /// Write an SMBus I/O register.
    fn smb_write(&self, offset: u16, val: u8) {
        io_outb(self.smbus_base + offset, val);
    }

    /// Clear all pending SMBus status bits.
    fn smb_clear_status(&self) {
        self.smb_write(SMB_STATUS, STATUS_CLEAR_MASK);
    }

    /// Wait for the SMBus host controller to become idle.
    /// Returns 0 on success, -1 on timeout.
    fn smb_wait_idle(&self) -> i32 {
        for _ in 0..POLL_TIMEOUT {
            let status = self.smb_read(SMB_STATUS);
            if status & STATUS_HOST_BUSY == 0 {
                return 0;
            }
            io_delay();
        }
        -1
    }

    /// Abort a stale SMBus transaction.
    fn smb_abort(&self) {
        self.smb_write(SMB_CONTROL, CONTROL_KILL);
        io_delay();
        self.smb_write(SMB_CONTROL, 0);
        self.smb_clear_status();
        for _ in 0..100 {
            io_delay();
        }
    }

    /// Wait for an SMBus transfer to complete.
    /// Returns 0 on success, negative error code on failure.
    fn smb_wait_completion(&self) -> i32 {
        for _ in 0..POLL_TIMEOUT {
            let status = self.smb_read(SMB_STATUS);

            if status & STATUS_FAILED != 0 {
                self.smb_clear_status();
                return -5; // EIO
            }
            if status & STATUS_BUS_COL != 0 {
                self.smb_clear_status();
                return -11; // EAGAIN
            }
            if status & STATUS_DEV_ERR != 0 {
                self.smb_clear_status();
                return -6; // ENXIO
            }
            if status & STATUS_INTR != 0 {
                self.smb_clear_status();
                return 0;
            }

            io_delay();
        }
        self.smb_abort();
        -110 // ETIMEDOUT
    }

    /// Prepare an SMBus byte data transaction.
    fn smb_setup(&self, read: bool, cmd: u8) -> i32 {
        if self.smb_wait_idle() != 0 {
            self.smb_abort();
            if self.smb_wait_idle() != 0 {
                return -16; // EBUSY
            }
        }

        self.smb_clear_status();

        // Set target address with R/W bit.
        let addr_rw = (self.addr << 1) | (if read { 1 } else { 0 });
        self.smb_write(SMB_ADDRESS, addr_rw);

        // Set the command byte (SB-TSI register address).
        self.smb_write(SMB_HOST_CMD, cmd);

        0
    }

    /// Start an SMBus transaction with the given protocol.
    fn smb_start(&self, protocol: u8) {
        fence(Ordering::SeqCst);
        self.smb_write(SMB_CONTROL, CONTROL_START | protocol);
    }

    /// Read a single byte from an SB-TSI register via SMBus Byte Data protocol.
    fn read_reg(&self, reg: u8) -> Result<u8, i32> {
        let rc = self.smb_setup(true, reg);
        if rc != 0 { return Err(rc); }

        self.smb_start(SMB_CMD_BYTE_DATA);

        let rc = self.smb_wait_completion();
        if rc != 0 { return Err(rc); }

        Ok(self.smb_read(SMB_DATA0))
    }

    /// Write a single byte to an SB-TSI register via SMBus Byte Data protocol.
    fn write_reg(&self, reg: u8, val: u8) -> i32 {
        let rc = self.smb_setup(false, reg);
        if rc != 0 { return rc; }

        self.smb_write(SMB_DATA0, val);
        self.smb_start(SMB_CMD_BYTE_DATA);
        self.smb_wait_completion()
    }

    // ── SB-TSI operations ──

    /// Detect the SB-TSI device by reading MANUFACTURER_ID.
    /// Returns true if an AMD SB-TSI device is found.
    fn detect(&self) -> bool {
        match self.read_reg(SBTSI_MANUFACTURER_ID) {
            Ok(id) => id == AMD_MANUFACTURER_ID,
            Err(_) => false,
        }
    }

    /// Wait for the SB-TSI to finish a temperature conversion (BUSY bit clear).
    fn wait_not_busy(&self) -> i32 {
        for _ in 0..POLL_TIMEOUT {
            match self.read_reg(SBTSI_STATUS) {
                Ok(status) => {
                    if status & SBTSI_STATUS_BUSY == 0 {
                        return 0;
                    }
                }
                Err(e) => return e,
            }
            io_delay();
        }
        -110 // ETIMEDOUT
    }

    /// Read the current CPU temperature in millidegrees Celsius.
    ///
    /// Combines CPU_TEMP_INT (integer degrees) and CPU_TEMP_DEC (fractional,
    /// bits [7:5] in 0.125 C increments) into a single millidegree value.
    ///
    /// Returns millidegrees on success, or negative error.
    fn read_temperature(&self) -> i32 {
        // Wait for a stable reading.
        let rc = self.wait_not_busy();
        if rc != 0 { return rc; }

        let int_part = match self.read_reg(SBTSI_CPU_TEMP_INT) {
            Ok(v) => v,
            Err(e) => return e,
        };

        let dec_part = match self.read_reg(SBTSI_CPU_TEMP_DEC) {
            Ok(v) => v,
            Err(e) => return e,
        };

        // Integer part is unsigned degrees C.
        // Decimal part: bits [7:5] represent 0.125 C increments (0-7 -> 0-0.875 C).
        let frac_steps = (dec_part >> 5) & 0x07;
        let millideg = (int_part as i32) * 1000 + (frac_steps as i32) * 125;

        millideg
    }

    /// Convert millidegrees Celsius into (integer_byte, decimal_byte) pair.
    /// The decimal byte has bits [7:5] set to 0.125 C increments.
    fn millideg_to_regs(millideg: i32) -> (u8, u8) {
        // Clamp to valid range (0-255 degrees integer).
        let clamped = if millideg < 0 { 0 } else if millideg > 255_875 { 255_875 } else { millideg };
        let int_part = (clamped / 1000) as u8;
        let frac_millideg = (clamped % 1000) as u8;
        // Each step is 125 millidegrees.
        let frac_steps = frac_millideg / 125;
        let dec_byte = (frac_steps & 0x07) << 5;
        (int_part, dec_byte)
    }

    /// Convert millidegrees (signed) into (integer_byte, decimal_byte) for offset registers.
    /// The integer part is signed (two's complement for negative offsets).
    fn millideg_to_offset_regs(millideg: i32) -> (u8, u8) {
        let negative = millideg < 0;
        let abs_millideg = if negative { -millideg } else { millideg };
        let clamped = if abs_millideg > 127_875 { 127_875 } else { abs_millideg };

        let int_part = (clamped / 1000) as u8;
        let frac_millideg = (clamped % 1000) as u16;
        let frac_steps = (frac_millideg / 125) as u8;
        let dec_byte = (frac_steps & 0x07) << 5;

        if negative {
            // Two's complement for the integer part.
            let int_byte = (!int_part).wrapping_add(1);
            (int_byte, dec_byte)
        } else {
            (int_part, dec_byte)
        }
    }

    /// Set the high temperature alert threshold in millidegrees Celsius.
    fn set_high_threshold(&self, millideg: i32) -> i32 {
        let (int_byte, dec_byte) = Self::millideg_to_regs(millideg);

        let rc = self.write_reg(SBTSI_HIGH_TEMP_INT, int_byte);
        if rc != 0 { return rc; }

        self.write_reg(SBTSI_HIGH_TEMP_DEC, dec_byte)
    }

    /// Set the low temperature alert threshold in millidegrees Celsius.
    fn set_low_threshold(&self, millideg: i32) -> i32 {
        let (int_byte, dec_byte) = Self::millideg_to_regs(millideg);

        let rc = self.write_reg(SBTSI_LOW_TEMP_INT, int_byte);
        if rc != 0 { return rc; }

        self.write_reg(SBTSI_LOW_TEMP_DEC, dec_byte)
    }

    /// Read the SB-TSI status register and return it as a structured bitmask.
    ///
    /// Returned u32 bits:
    ///   bit 0: BUSY — sensor is updating
    ///   bit 1: TEMP_HIGH_ALERT — temperature above high threshold
    ///   bit 2: TEMP_LOW_ALERT — temperature below low threshold
    fn get_status(&self) -> u32 {
        let raw = match self.read_reg(SBTSI_STATUS) {
            Ok(v) => v,
            Err(_) => return 0xFFFF_FFFF,
        };

        let mut result: u32 = 0;
        if raw & SBTSI_STATUS_BUSY != 0 {
            result |= 1 << 0;
        }
        if raw & SBTSI_STATUS_TEMP_HIGH_ALERT != 0 {
            result |= 1 << 1;
        }
        if raw & SBTSI_STATUS_TEMP_LOW_ALERT != 0 {
            result |= 1 << 2;
        }
        result
    }

    /// Set the temperature offset in millidegrees Celsius (signed).
    fn set_offset(&self, millideg: i32) -> i32 {
        let (int_byte, dec_byte) = Self::millideg_to_offset_regs(millideg);

        let rc = self.write_reg(SBTSI_TEMP_OFFSET_INT, int_byte);
        if rc != 0 { return rc; }

        self.write_reg(SBTSI_TEMP_OFFSET_DEC, dec_byte)
    }

    /// Enable continuous monitoring mode (clear RUN/STOP bit in config).
    fn enable_continuous(&self) -> i32 {
        let config = match self.read_reg(SBTSI_CONFIG) {
            Ok(v) => v,
            Err(e) => return e,
        };

        // If RUN/STOP is set (conversions stopped), clear it via CONFIG_WR.
        if config & SBTSI_CONFIG_RUN_STOP != 0 {
            let new_config = config & !SBTSI_CONFIG_RUN_STOP;
            return self.write_reg(SBTSI_CONFIG_WR, new_config);
        }

        0
    }

    /// Unmask the ALERT# output (clear ALERT_MASK bit in config).
    fn enable_alerts(&self) -> i32 {
        let config = match self.read_reg(SBTSI_CONFIG) {
            Ok(v) => v,
            Err(e) => return e,
        };

        if config & SBTSI_CONFIG_ALERT_MASK != 0 {
            let new_config = config & !SBTSI_CONFIG_ALERT_MASK;
            return self.write_reg(SBTSI_CONFIG_WR, new_config);
        }

        0
    }
}

// ── FFI exports ──

/// Initialise the AMD SB-TSI temperature sensor driver.
///
/// `smbus_base` - SMBus controller I/O port base address.
///                Pass 0 to use the default (0x0B00).
///
/// Detects the SB-TSI device at SMBus address 0x4C, reads the manufacturer
/// ID and revision, enables continuous monitoring, and unmasks alerts.
///
/// Returns 0 on success, negative error on failure.
#[unsafe(no_mangle)]
pub extern "C" fn amd_sbtsi_init(smbus_base: u16) -> i32 {
    let base = if smbus_base == 0 { 0x0B00u16 } else { smbus_base };

    unsafe {
        fut_printf(
            b"amd_sbtsi: initialising with SMBus base 0x%04x\n\0".as_ptr(),
            base as u32,
        );
    }

    // Verify the SMBus controller is responsive.
    let status = io_inb(base + SMB_STATUS);
    if status == 0xFF {
        log("amd_sbtsi: SMBus controller not responding at specified base");
        return -6; // ENXIO
    }

    let dev = AmdSbTsi {
        smbus_base: base,
        addr: SBTSI_DEFAULT_ADDR,
        revision: 0,
    };

    // Detect the SB-TSI device.
    if !dev.detect() {
        log("amd_sbtsi: no AMD SB-TSI device found at address 0x4C");
        return -6; // ENXIO
    }

    log("amd_sbtsi: AMD SB-TSI device detected (manufacturer ID verified)");

    // Read silicon revision.
    let revision = match dev.read_reg(SBTSI_REVISION) {
        Ok(v) => v,
        Err(_) => 0,
    };

    unsafe {
        fut_printf(
            b"amd_sbtsi: silicon revision = 0x%02x\n\0".as_ptr(),
            revision as u32,
        );
    }

    // Enable continuous temperature monitoring.
    let rc = dev.enable_continuous();
    if rc != 0 {
        log("amd_sbtsi: warning - failed to enable continuous monitoring");
    }

    // Unmask ALERT# output.
    let rc = dev.enable_alerts();
    if rc != 0 {
        log("amd_sbtsi: warning - failed to unmask alerts");
    }

    // Read initial temperature as a sanity check.
    let temp = dev.read_temperature();
    if temp >= 0 {
        unsafe {
            fut_printf(
                b"amd_sbtsi: current CPU temperature = %d.%03d C\n\0".as_ptr(),
                temp / 1000,
                temp % 1000,
            );
        }
    }

    // Store driver state.
    let sbtsi = AmdSbTsi {
        smbus_base: base,
        addr: SBTSI_DEFAULT_ADDR,
        revision,
    };

    unsafe {
        (*SBTSI.get()) = Some(sbtsi);
    }

    log("amd_sbtsi: driver initialised successfully");
    0
}

/// Read the current CPU temperature from the SB-TSI sensor.
///
/// Returns the temperature in millidegrees Celsius (e.g., 72500 = 72.5 C),
/// or a negative error code on failure.
#[unsafe(no_mangle)]
pub extern "C" fn amd_sbtsi_read_temp() -> i32 {
    let sbtsi = match unsafe { (*SBTSI.get()).as_ref() } {
        Some(s) => s,
        None => return -19, // ENODEV
    };

    sbtsi.read_temperature()
}

/// Set the high temperature alert threshold.
///
/// `millideg` - Threshold in millidegrees Celsius (e.g., 95000 = 95.0 C).
///
/// When the CPU temperature exceeds this threshold, the TEMP_HIGH_ALERT
/// status bit is set and the ALERT# pin is asserted (if unmasked).
///
/// Returns 0 on success, negative error on failure.
#[unsafe(no_mangle)]
pub extern "C" fn amd_sbtsi_set_high_threshold(millideg: i32) -> i32 {
    let sbtsi = match unsafe { (*SBTSI.get()).as_ref() } {
        Some(s) => s,
        None => return -19, // ENODEV
    };

    let rc = sbtsi.set_high_threshold(millideg);
    if rc == 0 {
        unsafe {
            fut_printf(
                b"amd_sbtsi: high threshold set to %d.%03d C\n\0".as_ptr(),
                millideg / 1000,
                millideg % 1000,
            );
        }
    }
    rc
}

/// Set the low temperature alert threshold.
///
/// `millideg` - Threshold in millidegrees Celsius (e.g., 10000 = 10.0 C).
///
/// When the CPU temperature drops below this threshold, the TEMP_LOW_ALERT
/// status bit is set and the ALERT# pin is asserted (if unmasked).
///
/// Returns 0 on success, negative error on failure.
#[unsafe(no_mangle)]
pub extern "C" fn amd_sbtsi_set_low_threshold(millideg: i32) -> i32 {
    let sbtsi = match unsafe { (*SBTSI.get()).as_ref() } {
        Some(s) => s,
        None => return -19, // ENODEV
    };

    let rc = sbtsi.set_low_threshold(millideg);
    if rc == 0 {
        unsafe {
            fut_printf(
                b"amd_sbtsi: low threshold set to %d.%03d C\n\0".as_ptr(),
                millideg / 1000,
                millideg % 1000,
            );
        }
    }
    rc
}

/// Query the current SB-TSI alert and sensor status.
///
/// Returns a bitmask:
///   bit 0: BUSY — sensor is currently updating the temperature reading
///   bit 1: TEMP_HIGH_ALERT — temperature is above the high threshold
///   bit 2: TEMP_LOW_ALERT — temperature is below the low threshold
///
/// Returns 0xFFFFFFFF if the driver is not initialised or on read error.
#[unsafe(no_mangle)]
pub extern "C" fn amd_sbtsi_get_status() -> u32 {
    let sbtsi = match unsafe { (*SBTSI.get()).as_ref() } {
        Some(s) => s,
        None => return 0xFFFF_FFFF,
    };

    sbtsi.get_status()
}

/// Set the CPU temperature offset.
///
/// `millideg` - Offset in millidegrees Celsius (signed). Positive values
///              increase the reported temperature; negative values decrease it.
///              Range: -127875 to +127875 millidegrees (-127.875 to +127.875 C).
///
/// Returns 0 on success, negative error on failure.
#[unsafe(no_mangle)]
pub extern "C" fn amd_sbtsi_set_offset(millideg: i32) -> i32 {
    let sbtsi = match unsafe { (*SBTSI.get()).as_ref() } {
        Some(s) => s,
        None => return -19, // ENODEV
    };

    let rc = sbtsi.set_offset(millideg);
    if rc == 0 {
        let sign = if millideg < 0 { "-" } else { "" };
        let abs_val = if millideg < 0 { -millideg } else { millideg };
        unsafe {
            fut_printf(
                b"amd_sbtsi: temperature offset set to %s%d.%03d C\n\0".as_ptr(),
                sign.as_ptr(),
                abs_val / 1000,
                abs_val % 1000,
            );
        }
    }
    rc
}
