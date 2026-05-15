// SPDX-License-Identifier: MPL-2.0
// Copyright (c) 2026 Kelsi Davis
//
// intel_i2c_hid — discover HID-over-I2C devices on Intel LPSS I2C buses and
// poll them for input reports. Targets the Chromebook touchpad on HP Gemini
// Lake hardware (Elan or Synaptics over LPSS I2C 0), but the protocol is
// device-agnostic.
//
// I2C-HID protocol summary (Microsoft "HID over I2C" v1.0):
//
//   * The HID Descriptor lives at a known register address on the I2C
//     device — typically 0x0020 on Chromebooks. Reading it (30 bytes)
//     yields the report descriptor length / address and the input/output
//     register addresses for subsequent transactions.
//
//   * To poll for an input report: write the 2-byte input register address
//     (little-endian) and read MAX_INPUT_LEN bytes back. The first 2 bytes
//     of the response are the report length (also LE); the rest is the
//     raw HID input report.
//
//   * Initial reset / power-on uses SET_POWER (opcode 0x08) on the
//     command register, followed by RESET (opcode 0x01). The device
//     asserts its IRQ pin when ready and exposes an initial "reset
//     complete" report.
//
// This MVP implementation:
//   * Probes I2C addresses 0x15 (Elan default), 0x2C (Synaptics), 0x49
//     (Atmel) on each LPSS I2C controller looking for a valid HID
//     descriptor at register 0x0020.
//   * Stores the discovered device's HID descriptor.
//   * Provides a polled `intel_i2c_hid_poll_input` function that reads
//     the next input report — kernel calls this from a timer or a
//     dedicated thread until we wire the GPIO interrupt for the touchpad.

#![no_std]
#![allow(dead_code)]

use core::ffi::c_char;

unsafe extern "C" {
    fn fut_printf(fmt: *const u8, ...);

    fn intel_lpss_i2c_count() -> u32;
    fn intel_lpss_i2c_read(idx: u32, addr: u8, buf: *mut u8, len: u32) -> i32;
    fn intel_lpss_i2c_write(idx: u32, addr: u8, data: *const u8, len: u32) -> i32;
    fn intel_lpss_i2c_write_read(
        idx: u32,
        addr: u8,
        wr: *const u8,
        wr_len: u32,
        rd: *mut u8,
        rd_len: u32,
    ) -> i32;

    /// Monotonic tick counter — used to bound total probe time so a
    /// stalled controller can't wedge boot for more than a few seconds
    /// even if the per-call timeout misbehaves.  Ticks at 100 Hz on
    /// x86_64 once the LAPIC timer is running.
    fn fut_get_ticks() -> u64;
}

// ── HID Descriptor (Microsoft HID over I2C, §5.1) ──

#[repr(C, packed)]
#[derive(Copy, Clone)]
struct HidDescriptor {
    w_hid_desc_length: u16,    // typically 30
    bcd_version: u16,           // 0x0100 = v1.0
    w_report_desc_length: u16,
    w_report_desc_register: u16,
    w_input_register: u16,
    w_max_input_length: u16,
    w_output_register: u16,
    w_max_output_length: u16,
    w_command_register: u16,
    w_data_register: u16,
    w_vendor_id: u16,
    w_product_id: u16,
    w_version_id: u16,
    reserved: u32,
}

// ── Discovered device state ──

#[derive(Copy, Clone)]
struct I2cHidDevice {
    valid: bool,
    bus_idx: u32,
    slave_addr: u8,
    hid_desc_register: u16,
    desc: HidDescriptor,
}

impl I2cHidDevice {
    const fn empty() -> Self {
        Self {
            valid: false,
            bus_idx: 0,
            slave_addr: 0,
            hid_desc_register: 0,
            desc: HidDescriptor {
                w_hid_desc_length: 0,
                bcd_version: 0,
                w_report_desc_length: 0,
                w_report_desc_register: 0,
                w_input_register: 0,
                w_max_input_length: 0,
                w_output_register: 0,
                w_max_output_length: 0,
                w_command_register: 0,
                w_data_register: 0,
                w_vendor_id: 0,
                w_product_id: 0,
                w_version_id: 0,
                reserved: 0,
            },
        }
    }
}

const MAX_DEVICES: usize = 4;

// Candidate I2C slave addresses to probe on each LPSS controller. These are
// the well-known addresses for major Chromebook/laptop touchpad vendors.
const CANDIDATE_ADDRS: &[u8] = &[0x15, 0x2C, 0x49, 0x2A];

// Candidate HID descriptor register addresses. The HID-over-I2C spec
// doesn't fix this — it's read from ACPI _DSM. Without an ACPI walker
// we use 0x0020, which is the universal choice on Chromebook touchpads
// (the only I2C-HID target we currently care about). Adding the Windows-
// tablet fallbacks (0x0001 / 0x0021) tripled probe time on hardware where
// no I2C-HID device exists, and any board that ever needs them can be
// extended individually rather than paying the cost for all boards.
const CANDIDATE_HID_REGS: &[u16] = &[0x0020];

// SAFETY: single-CPU boot. Once we restore SMP, this needs a real lock.
struct State {
    devices: [I2cHidDevice; MAX_DEVICES],
    count: u32,
}
static mut STATE: State = State {
    devices: [I2cHidDevice::empty(); MAX_DEVICES],
    count: 0,
};

fn state_mut() -> &'static mut State {
    // SAFETY: single-CPU initialization order — STATE is touched only from
    // the BSP after boot enters this module's init.
    unsafe { &mut *core::ptr::addr_of_mut!(STATE) }
}

// ── HID descriptor probe ──

/// Outcome of one HID descriptor probe attempt.
enum ProbeResult {
    /// Bytes returned and validated as a HID descriptor.
    Found(HidDescriptor),
    /// Bus responded but no slave ACKed at this address (-6 ENXIO) or the
    /// bytes returned didn't validate as a HID descriptor. Safe to try the
    /// next address on the same bus.
    NoDevice,
    /// I2C controller failed to complete the transaction (any timeout/abort
    /// other than a clean NACK). The bus is in a weird state — caller
    /// should skip it entirely rather than burn another ~500ms per probe.
    BusError,
}

/// Attempt to read a HID descriptor from `slave_addr` on `bus_idx` at the
/// given register address.
fn probe_hid_descriptor(bus_idx: u32, slave_addr: u8, reg: u16) -> ProbeResult {
    let wr = [(reg & 0xFF) as u8, ((reg >> 8) & 0xFF) as u8];
    let mut buf = [0u8; 30];
    let rc = unsafe {
        intel_lpss_i2c_write_read(
            bus_idx,
            slave_addr,
            wr.as_ptr(),
            wr.len() as u32,
            buf.as_mut_ptr(),
            buf.len() as u32,
        )
    };
    if rc == -6 {
        return ProbeResult::NoDevice;
    }
    if rc != 0 {
        return ProbeResult::BusError;
    }
    let desc = HidDescriptor {
        w_hid_desc_length: u16::from_le_bytes([buf[0], buf[1]]),
        bcd_version: u16::from_le_bytes([buf[2], buf[3]]),
        w_report_desc_length: u16::from_le_bytes([buf[4], buf[5]]),
        w_report_desc_register: u16::from_le_bytes([buf[6], buf[7]]),
        w_input_register: u16::from_le_bytes([buf[8], buf[9]]),
        w_max_input_length: u16::from_le_bytes([buf[10], buf[11]]),
        w_output_register: u16::from_le_bytes([buf[12], buf[13]]),
        w_max_output_length: u16::from_le_bytes([buf[14], buf[15]]),
        w_command_register: u16::from_le_bytes([buf[16], buf[17]]),
        w_data_register: u16::from_le_bytes([buf[18], buf[19]]),
        w_vendor_id: u16::from_le_bytes([buf[20], buf[21]]),
        w_product_id: u16::from_le_bytes([buf[22], buf[23]]),
        w_version_id: u16::from_le_bytes([buf[24], buf[25]]),
        reserved: u32::from_le_bytes([buf[26], buf[27], buf[28], buf[29]]),
    };
    // Validate: bcdVersion must be 0x0100, length must be 30, and the
    // report descriptor length must be plausibly nonzero.
    if desc.bcd_version != 0x0100
        || desc.w_hid_desc_length != 30
        || desc.w_report_desc_length == 0
        || desc.w_report_desc_length > 4096
        || desc.w_max_input_length == 0
        || desc.w_max_input_length > 1024
    {
        return ProbeResult::NoDevice;
    }
    ProbeResult::Found(desc)
}

// ── Init (FFI) ──

/// Probe every I2C-HID candidate on every LPSS I2C bus. Records each match
/// into the module's STATE array. Returns the number of devices found.
///
/// **Diagnostic-heavy:** the L490 used to hang somewhere between the end of
/// this routine and the first scheduler tick, with no clue which step
/// corrupted state.  Every transition gets a banner print so the next
/// real-hardware boot log pinpoints the exact suspect.  Total probe time
/// is also capped (`MAX_PROBE_TICKS`) so a runaway controller can't wedge
/// boot even if individual `intel_lpss_i2c_write_read` calls misbehave.
#[unsafe(no_mangle)]
pub extern "C" fn intel_i2c_hid_init() -> i32 {
    // 500 ticks @ 100 Hz = 5 s.  Generous enough that a slow but working
    // probe finishes; tight enough that a wedged controller doesn't make
    // the user reboot.
    const MAX_PROBE_TICKS: u64 = 500;

    let t_start = unsafe { fut_get_ticks() };
    let bus_count = unsafe { intel_lpss_i2c_count() };
    unsafe {
        fut_printf(
            b"intel_i2c_hid: probe begin, lpss_i2c_count=%u\n\0".as_ptr(),
            bus_count,
        );
    }
    if bus_count == 0 {
        unsafe {
            fut_printf(
                b"intel_i2c_hid: no LPSS I2C buses, skipping probe\n\0".as_ptr(),
            );
        }
        return 0;
    }

    let st = state_mut();
    st.count = 0;

    'bus_loop: for bus in 0..bus_count {
        if unsafe { fut_get_ticks() }.saturating_sub(t_start) > MAX_PROBE_TICKS {
            unsafe {
                fut_printf(
                    b"intel_i2c_hid: total probe budget exhausted at bus %u, aborting\n\0"
                        .as_ptr(),
                    bus,
                );
            }
            break 'bus_loop;
        }
        unsafe {
            fut_printf(
                b"intel_i2c_hid: bus %u -- probing candidate addrs\n\0".as_ptr(),
                bus,
            );
        }
        for &addr in CANDIDATE_ADDRS {
            'reg_loop: for &reg in CANDIDATE_HID_REGS {
                unsafe {
                    fut_printf(
                        b"intel_i2c_hid:   bus=%u addr=0x%02x reg=0x%04x -> write_read...\n\0"
                            .as_ptr(),
                        bus,
                        addr as u32,
                        reg as u32,
                    );
                }
                match probe_hid_descriptor(bus, addr, reg) {
                    ProbeResult::Found(desc) => {
                        if (st.count as usize) >= MAX_DEVICES {
                            unsafe {
                                fut_printf(
                                    b"intel_i2c_hid: too many devices (>%u), skipping rest\n\0"
                                        .as_ptr(),
                                    MAX_DEVICES as u32,
                                );
                            }
                            return st.count as i32;
                        }
                        let slot = st.count as usize;
                        st.devices[slot] = I2cHidDevice {
                            valid: true,
                            bus_idx: bus,
                            slave_addr: addr,
                            hid_desc_register: reg,
                            desc,
                        };
                        st.count += 1;
                        unsafe {
                            fut_printf(
                                b"intel_i2c_hid: found device bus=%u addr=0x%02x hid_reg=0x%04x vid=0x%04x pid=0x%04x report_desc_len=%u max_input=%u\n\0"
                                    .as_ptr(),
                                bus,
                                addr as u32,
                                reg as u32,
                                desc.w_vendor_id as u32,
                                desc.w_product_id as u32,
                                desc.w_report_desc_length as u32,
                                desc.w_max_input_length as u32,
                            );
                        }
                        // First-match-wins per (bus, addr) — stop probing other
                        // HID descriptor registers on this slave.
                        break 'reg_loop;
                    }
                    ProbeResult::NoDevice => {
                        // Clean NACK or invalid descriptor — try the next
                        // (addr, reg) combination on the same bus.
                        unsafe {
                            fut_printf(
                                b"intel_i2c_hid:   bus=%u addr=0x%02x -> NoDevice\n\0"
                                    .as_ptr(),
                                bus,
                                addr as u32,
                            );
                        }
                    }
                    ProbeResult::BusError => {
                        // The controller stalled / timed out. Each timeout
                        // burns ~500ms of POLL_TIMEOUT iters in intel_lpss;
                        // if one probe blew, the rest on this bus will too.
                        // Skip the bus entirely. Without this guard, an
                        // unresponsive controller burned ~48s on HP boot
                        // and broke subsequent xhci_init scheduling.
                        unsafe {
                            fut_printf(
                                b"intel_i2c_hid: bus %u stalled at addr 0x%02x, skipping bus\n\0"
                                    .as_ptr(),
                                bus,
                                addr as u32,
                            );
                        }
                        continue 'bus_loop;
                    }
                }
            }
        }
    }

    if st.count == 0 {
        unsafe {
            fut_printf(
                b"intel_i2c_hid: no devices found across %u bus(es)\n\0".as_ptr(),
                bus_count,
            );
        }
    }
    let elapsed = unsafe { fut_get_ticks() }.saturating_sub(t_start);
    unsafe {
        fut_printf(
            b"intel_i2c_hid: probe end, found=%u elapsed_ticks=%u\n\0".as_ptr(),
            st.count,
            elapsed as u32,
        );
    }
    st.count as i32
}

/// Number of I2C-HID devices discovered by init().
#[unsafe(no_mangle)]
pub extern "C" fn intel_i2c_hid_count() -> u32 {
    state_mut().count
}

/// Poll device `idx` for its next input report. Writes up to `max_len` bytes
/// into `out` and returns the actual report length on success. Returns 0 if
/// no report is pending (the spec says the device returns a 2-byte length
/// of zero when there's nothing to deliver), or a negative I2C error code.
///
/// `out` should be at least `desc.w_max_input_length` bytes long.
#[unsafe(no_mangle)]
pub extern "C" fn intel_i2c_hid_poll_input(idx: u32, out: *mut u8, max_len: u32) -> i32 {
    let st = state_mut();
    if idx >= st.count || (idx as usize) >= MAX_DEVICES {
        return -22; // EINVAL
    }
    let dev = st.devices[idx as usize];
    if !dev.valid {
        return -19; // ENODEV
    }
    let in_reg = dev.desc.w_input_register;
    let max_in = dev.desc.w_max_input_length;
    let wr = [(in_reg & 0xFF) as u8, ((in_reg >> 8) & 0xFF) as u8];

    // Read up to max_in bytes into a small stack buffer, then copy out.
    // Spec says first 2 bytes are the report length (LE) and the body
    // follows; if the length is 0 there's no input.
    let mut tmp = [0u8; 256];
    let read_len = (max_in as u32).min(tmp.len() as u32);
    let rc = unsafe {
        intel_lpss_i2c_write_read(
            dev.bus_idx,
            dev.slave_addr,
            wr.as_ptr(),
            wr.len() as u32,
            tmp.as_mut_ptr(),
            read_len,
        )
    };
    if rc != 0 {
        return rc;
    }

    let report_len = u16::from_le_bytes([tmp[0], tmp[1]]) as u32;
    if report_len == 0 {
        return 0; // no input pending
    }
    if report_len > read_len {
        // Truncated read — report something is wrong rather than blindly
        // copying garbage.
        return -75; // EOVERFLOW
    }

    let body_len = (report_len - 2).min(max_len);
    if !out.is_null() && body_len > 0 {
        unsafe {
            core::ptr::copy_nonoverlapping(tmp.as_ptr().add(2), out, body_len as usize);
        }
    }
    body_len as i32
}

/// Get the vendor/product ID for a discovered device. Returns 0 on success
/// and writes vid/pid via the out-pointers. Useful for kernel-side dispatch
/// (Elan vs Synaptics vs Atmel touchpad parsing).
#[unsafe(no_mangle)]
pub extern "C" fn intel_i2c_hid_get_ids(
    idx: u32,
    out_vid: *mut u16,
    out_pid: *mut u16,
) -> i32 {
    let st = state_mut();
    if idx >= st.count || (idx as usize) >= MAX_DEVICES {
        return -22;
    }
    let dev = st.devices[idx as usize];
    if !dev.valid {
        return -19;
    }
    if !out_vid.is_null() {
        unsafe { *out_vid = dev.desc.w_vendor_id; }
    }
    if !out_pid.is_null() {
        unsafe { *out_pid = dev.desc.w_product_id; }
    }
    0
}

// Linker-required panic handler — never called when the driver compiles
// cleanly with no unwinding allowed.
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {
        core::hint::spin_loop();
    }
}

// Silence "unused" warning for the C-pointer type alias.
#[allow(dead_code)]
type _CChar = c_char;
