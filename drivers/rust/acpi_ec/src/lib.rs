// SPDX-License-Identifier: MPL-2.0
//
// ACPI Embedded Controller (EC) Driver for Futura OS (x86-64)
//
// The ACPI Embedded Controller is a separate microcontroller on the
// motherboard that manages thermal sensors, fan control, battery
// status (on laptops), keyboard backlight, and platform events.
// Communication uses a pair of I/O ports: a data port and a
// command/status port.
//
// Default I/O ports (from ACPI FADT/ECDT):
//   Data port:           0x62
//   Command/Status port: 0x66
//
// EC Status Register (read from command port):
//   Bit 0: OBF  - Output Buffer Full (data available to read)
//   Bit 1: IBF  - Input Buffer Full (EC busy, don't write)
//   Bit 2: CMD  - Last write was command (1) or data (0)
//   Bit 3: BURST - Burst mode active
//   Bit 4: SCI_EVT - SCI event pending
//   Bit 5: SMI_EVT - SMI event pending
//
// EC Commands (write to command port):
//   0x80: EC_READ         - Read byte at address
//   0x81: EC_WRITE        - Write byte at address
//   0x82: EC_BURST_ENABLE - Enter burst mode
//   0x83: EC_BURST_DISABLE - Leave burst mode
//   0x84: EC_QUERY        - Query pending event ID
//
// EC Read protocol:
//   1. Wait for IBF=0
//   2. Write 0x80 to command port
//   3. Wait for IBF=0
//   4. Write address to data port
//   5. Wait for OBF=1
//   6. Read data from data port
//
// EC Write protocol:
//   1. Wait for IBF=0
//   2. Write 0x81 to command port
//   3. Wait for IBF=0
//   4. Write address to data port
//   5. Wait for IBF=0
//   6. Write value to data port

#![no_std]
#![forbid(unsafe_op_in_unsafe_fn)]
#![allow(unexpected_cfgs)]

use core::cell::UnsafeCell;

use common::{log, thread_yield};

unsafe extern "C" {
    fn fut_printf(fmt: *const u8, ...);
}

// ── StaticCell wrapper (avoids `static mut`) ──

struct StaticCell<T>(UnsafeCell<T>);
unsafe impl<T> Sync for StaticCell<T> {}
impl<T> StaticCell<T> {
    const fn new(v: T) -> Self {
        Self(UnsafeCell::new(v))
    }
    fn get(&self) -> *mut T {
        self.0.get()
    }
}

// ── Default I/O ports ──

const EC_DATA_PORT_DEFAULT: u16 = 0x62;
const EC_CMD_PORT_DEFAULT: u16 = 0x66;

// ── EC Status Register bits (read from command/status port) ──

/// Output Buffer Full -- data is available for the host to read.
const EC_STS_OBF: u8 = 1 << 0;
/// Input Buffer Full -- EC is processing, host must not write.
const EC_STS_IBF: u8 = 1 << 1;
/// Last write was a command (1) rather than data (0).
const _EC_STS_CMD: u8 = 1 << 2;
/// Burst mode is active.
const EC_STS_BURST: u8 = 1 << 3;
/// SCI event pending.
const EC_STS_SCI_EVT: u8 = 1 << 4;
/// SMI event pending.
const _EC_STS_SMI_EVT: u8 = 1 << 5;

// ── EC Commands (write to command port) ──

const EC_CMD_READ: u8 = 0x80;
const EC_CMD_WRITE: u8 = 0x81;
const EC_CMD_BURST_ENABLE: u8 = 0x82;
const EC_CMD_BURST_DISABLE: u8 = 0x83;
const EC_CMD_QUERY: u8 = 0x84;

/// Burst acknowledge byte the EC sends after burst enable.
const EC_BURST_ACK: u8 = 0x90;

/// Maximum number of polling iterations before we declare a timeout.
/// Each iteration includes a thread_yield(), so this is not purely
/// CPU-spinning.
const EC_TIMEOUT_POLLS: u32 = 50_000;

// ── Driver state ──

struct EcState {
    /// Data port (default 0x62).
    data_port: u16,
    /// Command/status port (default 0x66).
    cmd_port: u16,
    /// Whether burst mode is currently active.
    burst_active: bool,
    /// Whether the driver has been initialized.
    initialized: bool,
}

impl EcState {
    const fn new() -> Self {
        Self {
            data_port: EC_DATA_PORT_DEFAULT,
            cmd_port: EC_CMD_PORT_DEFAULT,
            burst_active: false,
            initialized: false,
        }
    }
}

static STATE: StaticCell<EcState> = StaticCell::new(EcState::new());

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

// ── EC register access ──

/// Read the EC status register.
#[inline]
fn ec_read_status(cmd_port: u16) -> u8 {
    io_inb(cmd_port)
}

/// Read a byte from the EC data port.
#[inline]
fn ec_read_data(data_port: u16) -> u8 {
    io_inb(data_port)
}

/// Write a byte to the EC data port.
#[inline]
fn ec_write_data(data_port: u16, val: u8) {
    io_outb(data_port, val);
}

/// Write a command byte to the EC command port.
#[inline]
fn ec_write_cmd(cmd_port: u16, cmd: u8) {
    io_outb(cmd_port, cmd);
}

// ── Wait helpers ──

/// Wait until the Input Buffer Full (IBF) bit clears, meaning the EC
/// has consumed the previous write and is ready for new data.
///
/// Returns 0 on success, -1 on timeout.
fn wait_ibf_clear(cmd_port: u16) -> i32 {
    for _ in 0..EC_TIMEOUT_POLLS {
        if ec_read_status(cmd_port) & EC_STS_IBF == 0 {
            return 0;
        }
        thread_yield();
    }
    -1
}

/// Wait until the Output Buffer Full (OBF) bit is set, meaning the
/// EC has placed data in the output buffer for the host to read.
///
/// Returns 0 on success, -1 on timeout.
fn wait_obf_set(cmd_port: u16) -> i32 {
    for _ in 0..EC_TIMEOUT_POLLS {
        if ec_read_status(cmd_port) & EC_STS_OBF != 0 {
            return 0;
        }
        thread_yield();
    }
    -1
}

// ── Internal EC operations ──

/// Read a single byte from the EC address space.
///
/// Protocol:
///   1. Wait IBF clear
///   2. Write EC_READ command
///   3. Wait IBF clear
///   4. Write address to data port
///   5. Wait OBF set
///   6. Read data from data port
///
/// Returns the byte value (0..255) on success, or negative on error.
fn ec_byte_read(data_port: u16, cmd_port: u16, addr: u8) -> i32 {
    if wait_ibf_clear(cmd_port) != 0 {
        return -1;
    }
    ec_write_cmd(cmd_port, EC_CMD_READ);

    if wait_ibf_clear(cmd_port) != 0 {
        return -2;
    }
    ec_write_data(data_port, addr);

    if wait_obf_set(cmd_port) != 0 {
        return -3;
    }
    ec_read_data(data_port) as i32
}

/// Write a single byte to the EC address space.
///
/// Protocol:
///   1. Wait IBF clear
///   2. Write EC_WRITE command
///   3. Wait IBF clear
///   4. Write address to data port
///   5. Wait IBF clear
///   6. Write value to data port
///
/// Returns 0 on success, negative on error.
fn ec_byte_write(data_port: u16, cmd_port: u16, addr: u8, val: u8) -> i32 {
    if wait_ibf_clear(cmd_port) != 0 {
        return -1;
    }
    ec_write_cmd(cmd_port, EC_CMD_WRITE);

    if wait_ibf_clear(cmd_port) != 0 {
        return -2;
    }
    ec_write_data(data_port, addr);

    if wait_ibf_clear(cmd_port) != 0 {
        return -3;
    }
    ec_write_data(data_port, val);

    0
}

// ── Exported functions ──

/// Initialize the ACPI Embedded Controller driver.
///
/// `data_port` and `cmd_port` specify the I/O port addresses. Pass 0 for
/// both to use the standard defaults (data=0x62, cmd/status=0x66).
///
/// Returns 0 on success, negative on error:
///   -1 = EC status port not responding (IBF stuck)
#[unsafe(no_mangle)]
pub extern "C" fn acpi_ec_init(data_port: u16, cmd_port: u16) -> i32 {
    log("acpi_ec: initializing ACPI Embedded Controller driver");

    let dp = if data_port == 0 && cmd_port == 0 {
        EC_DATA_PORT_DEFAULT
    } else {
        data_port
    };
    let cp = if data_port == 0 && cmd_port == 0 {
        EC_CMD_PORT_DEFAULT
    } else {
        cmd_port
    };

    unsafe {
        fut_printf(
            b"acpi_ec: data port=0x%04x, cmd/status port=0x%04x\n\0".as_ptr(),
            dp as u32,
            cp as u32,
        );
    }

    // Verify the EC is alive by reading the status register and checking
    // that IBF is not permanently stuck.
    let status = ec_read_status(cp);
    unsafe {
        fut_printf(
            b"acpi_ec: initial status=0x%02x (OBF=%u IBF=%u BURST=%u SCI=%u)\n\0".as_ptr(),
            status as u32,
            ((status & EC_STS_OBF) != 0) as u32,
            ((status & EC_STS_IBF) != 0) as u32,
            ((status & EC_STS_BURST) != 0) as u32,
            ((status & EC_STS_SCI_EVT) != 0) as u32,
        );
    }

    // If the output buffer is full, drain it to clear any stale data.
    if status & EC_STS_OBF != 0 {
        let _ = ec_read_data(dp);
        log("acpi_ec: drained stale data from output buffer");
    }

    // Wait for IBF to clear -- if it doesn't, the EC is stuck or absent.
    if status & EC_STS_IBF != 0 {
        if wait_ibf_clear(cp) != 0 {
            log("acpi_ec: ERROR -- IBF stuck, EC not responding");
            return -1;
        }
    }

    // Store driver state.
    let state = STATE.get();
    unsafe {
        (*state).data_port = dp;
        (*state).cmd_port = cp;
        (*state).burst_active = false;
        (*state).initialized = true;
    }

    // Try a probe read of address 0x00 to verify communication.
    let probe = ec_byte_read(dp, cp, 0x00);
    if probe >= 0 {
        unsafe {
            fut_printf(
                b"acpi_ec: probe read EC[0x00]=0x%02x -- EC responding\n\0".as_ptr(),
                probe as u32,
            );
        }
    } else {
        log("acpi_ec: WARNING -- probe read of EC[0x00] timed out");
    }

    log("acpi_ec: driver initialized");
    0
}

/// Read a single byte from the EC address space.
///
/// `addr` is the EC-internal register address (0x00..0xFF).
///
/// Returns the byte value (0..255) on success, or negative on error:
///   -1 = not initialized
///   -2..-4 = timeout during EC transaction
#[unsafe(no_mangle)]
pub extern "C" fn acpi_ec_read(addr: u8) -> i32 {
    let state = STATE.get();
    let (dp, cp, init) = unsafe {
        ((*state).data_port, (*state).cmd_port, (*state).initialized)
    };
    if !init {
        return -1;
    }
    let result = ec_byte_read(dp, cp, addr);
    if result < 0 {
        unsafe {
            fut_printf(
                b"acpi_ec: read timeout at addr 0x%02x (err=%d)\n\0".as_ptr(),
                addr as u32,
                result,
            );
        }
    }
    result
}

/// Write a single byte to the EC address space.
///
/// `addr` is the EC-internal register address (0x00..0xFF).
/// `val` is the byte value to write.
///
/// Returns 0 on success, negative on error:
///   -1 = not initialized
///   -2..-4 = timeout during EC transaction
#[unsafe(no_mangle)]
pub extern "C" fn acpi_ec_write(addr: u8, val: u8) -> i32 {
    let state = STATE.get();
    let (dp, cp, init) = unsafe {
        ((*state).data_port, (*state).cmd_port, (*state).initialized)
    };
    if !init {
        return -1;
    }
    let result = ec_byte_write(dp, cp, addr, val);
    if result < 0 {
        unsafe {
            fut_printf(
                b"acpi_ec: write timeout at addr 0x%02x val 0x%02x (err=%d)\n\0".as_ptr(),
                addr as u32,
                val as u32,
                result,
            );
        }
    }
    result
}

/// Read a block of consecutive bytes from the EC address space.
///
/// Reads `len` bytes starting at `addr` into the buffer at `buf`.
/// The function automatically enables burst mode for the transfer
/// and disables it afterwards for faster sequential access.
///
/// Returns the number of bytes successfully read (may be less than
/// `len` if an error occurs mid-transfer), or negative on error:
///   -1 = not initialized
///   -2 = null buffer pointer
#[unsafe(no_mangle)]
pub extern "C" fn acpi_ec_read_block(addr: u8, buf: *mut u8, len: u8) -> i32 {
    let state = STATE.get();
    let (dp, cp, init) = unsafe {
        ((*state).data_port, (*state).cmd_port, (*state).initialized)
    };
    if !init {
        return -1;
    }
    if buf.is_null() {
        return -2;
    }
    if len == 0 {
        return 0;
    }

    // Enable burst mode for faster sequential access.
    let burst_was_active = unsafe { (*state).burst_active };
    if !burst_was_active {
        let _ = ec_burst_enable_internal(dp, cp);
    }

    let mut count: i32 = 0;
    let mut current_addr = addr;

    for i in 0..len as usize {
        let result = ec_byte_read(dp, cp, current_addr);
        if result < 0 {
            unsafe {
                fut_printf(
                    b"acpi_ec: block read error at addr 0x%02x (err=%d), read %d of %u bytes\n\0"
                        .as_ptr(),
                    current_addr as u32,
                    result,
                    count,
                    len as u32,
                );
            }
            break;
        }
        unsafe {
            *buf.add(i) = result as u8;
        }
        count += 1;
        current_addr = current_addr.wrapping_add(1);
    }

    // Restore burst mode to previous state.
    if !burst_was_active {
        let _ = ec_burst_disable_internal(dp, cp);
    }

    count
}

/// Query the EC for a pending event identifier.
///
/// When the EC asserts SCI (SCI_EVT status bit), the OS should issue
/// an EC_QUERY command to determine which event triggered the
/// interrupt. The EC returns a one-byte event ID.
///
/// Returns the event ID (0x00..0xFF) on success, or -1 on error.
/// An event ID of 0x00 means no event is pending.
#[unsafe(no_mangle)]
pub extern "C" fn acpi_ec_query() -> i32 {
    let state = STATE.get();
    let (dp, cp, init) = unsafe {
        ((*state).data_port, (*state).cmd_port, (*state).initialized)
    };
    if !init {
        return -1;
    }

    // Check if SCI_EVT is actually set.
    let status = ec_read_status(cp);
    if status & EC_STS_SCI_EVT == 0 {
        return 0; // No event pending.
    }

    if wait_ibf_clear(cp) != 0 {
        log("acpi_ec: query timeout waiting for IBF clear");
        return -1;
    }
    ec_write_cmd(cp, EC_CMD_QUERY);

    if wait_obf_set(cp) != 0 {
        log("acpi_ec: query timeout waiting for OBF set");
        return -1;
    }
    let event_id = ec_read_data(dp);

    if event_id != 0 {
        unsafe {
            fut_printf(
                b"acpi_ec: query returned event 0x%02x\n\0".as_ptr(),
                event_id as u32,
            );
        }
    }

    event_id as i32
}

// ── Burst mode internals ──

/// Internal burst enable -- does not check initialized state.
fn ec_burst_enable_internal(data_port: u16, cmd_port: u16) -> i32 {
    if wait_ibf_clear(cmd_port) != 0 {
        return -1;
    }
    ec_write_cmd(cmd_port, EC_CMD_BURST_ENABLE);

    if wait_obf_set(cmd_port) != 0 {
        return -2;
    }
    let ack = ec_read_data(data_port);
    if ack != EC_BURST_ACK {
        unsafe {
            fut_printf(
                b"acpi_ec: burst enable got 0x%02x instead of ACK 0x%02x\n\0".as_ptr(),
                ack as u32,
                EC_BURST_ACK as u32,
            );
        }
        return -3;
    }

    // Verify BURST status bit is set.
    let status = ec_read_status(cmd_port);
    if status & EC_STS_BURST == 0 {
        log("acpi_ec: WARNING -- burst mode ACK received but BURST bit not set");
    }

    let state = STATE.get();
    unsafe {
        (*state).burst_active = true;
    }
    0
}

/// Internal burst disable -- does not check initialized state.
fn ec_burst_disable_internal(data_port: u16, cmd_port: u16) -> i32 {
    if wait_ibf_clear(cmd_port) != 0 {
        return -1;
    }
    ec_write_cmd(cmd_port, EC_CMD_BURST_DISABLE);

    // The EC does not send an acknowledgement for burst disable.
    // Wait for IBF to clear to confirm the command was accepted.
    if wait_ibf_clear(cmd_port) != 0 {
        return -2;
    }

    // Drain OBF if the EC put anything there.
    let status = ec_read_status(cmd_port);
    if status & EC_STS_OBF != 0 {
        let _ = ec_read_data(data_port);
    }

    let state = STATE.get();
    unsafe {
        (*state).burst_active = false;
    }
    0
}

/// Enable EC burst mode for faster sequential register access.
///
/// In burst mode the EC does not release the bus between transactions,
/// allowing back-to-back reads/writes without re-arbitration. This is
/// useful when reading many consecutive registers (e.g., battery data).
///
/// The host should call `acpi_ec_burst_disable()` when the burst
/// sequence is complete.
///
/// Returns 0 on success, negative on error:
///   -1 = not initialized
///   -2..-4 = EC communication error
#[unsafe(no_mangle)]
pub extern "C" fn acpi_ec_burst_enable() -> i32 {
    let state = STATE.get();
    let (dp, cp, init) = unsafe {
        ((*state).data_port, (*state).cmd_port, (*state).initialized)
    };
    if !init {
        return -1;
    }

    let result = ec_burst_enable_internal(dp, cp);
    if result == 0 {
        log("acpi_ec: burst mode enabled");
    } else {
        unsafe {
            fut_printf(
                b"acpi_ec: burst enable failed (err=%d)\n\0".as_ptr(),
                result,
            );
        }
    }
    result
}

/// Disable EC burst mode.
///
/// Returns 0 on success, negative on error:
///   -1 = not initialized
///   -2..-3 = EC communication error
#[unsafe(no_mangle)]
pub extern "C" fn acpi_ec_burst_disable() -> i32 {
    let state = STATE.get();
    let (dp, cp, init) = unsafe {
        ((*state).data_port, (*state).cmd_port, (*state).initialized)
    };
    if !init {
        return -1;
    }

    let result = ec_burst_disable_internal(dp, cp);
    if result == 0 {
        log("acpi_ec: burst mode disabled");
    } else {
        unsafe {
            fut_printf(
                b"acpi_ec: burst disable failed (err=%d)\n\0".as_ptr(),
                result,
            );
        }
    }
    result
}
