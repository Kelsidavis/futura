// SPDX-License-Identifier: MPL-2.0
//
// x86 CMOS Real-Time Clock Driver for Futura OS
//
// Implements the MC146818 / DS12887 compatible RTC accessed through
// the standard CMOS I/O ports (0x70 address, 0x71 data).
//
// Features:
//   - NMI-safe CMOS register access (bit 7 of port 0x70)
//   - UIP (Update In Progress) wait before reading time
//   - Auto-detect BCD vs binary mode from Status Register B
//   - 12-hour to 24-hour conversion
//   - Century register support (0x32) with fallback to 20xx
//   - Alarm set/clear via CMOS alarm registers
//   - Battery status via Status Register D
//   - Approximate Unix timestamp calculation

#![no_std]
#![forbid(unsafe_op_in_unsafe_fn)]
#![allow(unexpected_cfgs)]

use core::cell::UnsafeCell;

use common::log;

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

// ── RtcDateTime ──

/// Date and time structure returned by the CMOS RTC.
#[repr(C)]
#[derive(Copy, Clone)]
pub struct RtcDateTime {
    /// Full year (e.g. 2026).
    pub year: u16,
    /// Month, 1-12.
    pub month: u8,
    /// Day of month, 1-31.
    pub day: u8,
    /// Hour, 0-23.
    pub hour: u8,
    /// Minute, 0-59.
    pub minute: u8,
    /// Second, 0-59.
    pub second: u8,
    /// Day of week, 1-7 (1 = Sunday).
    pub weekday: u8,
}

impl RtcDateTime {
    const fn zero() -> Self {
        Self {
            year: 0,
            month: 0,
            day: 0,
            hour: 0,
            minute: 0,
            second: 0,
            weekday: 0,
        }
    }
}

// ── Driver state ──

struct RtcState {
    initialized: bool,
    /// Century register index (0x32 on most ACPI systems, 0 = unavailable).
    century_reg: u8,
}

static STATE: StaticCell<RtcState> = StaticCell::new(RtcState {
    initialized: false,
    century_reg: 0x32,
});

// ── CMOS I/O ports ──

/// CMOS address / NMI register. Bit 7 = NMI disable, bits [6:0] = register index.
const CMOS_ADDR: u16 = 0x70;
/// CMOS data register.
const CMOS_DATA: u16 = 0x71;

// ── CMOS register indices ──

const REG_SECONDS: u8 = 0x00;
const REG_ALARM_SECONDS: u8 = 0x01;
const REG_MINUTES: u8 = 0x02;
const REG_ALARM_MINUTES: u8 = 0x03;
const REG_HOURS: u8 = 0x04;
const REG_ALARM_HOURS: u8 = 0x05;
const REG_WEEKDAY: u8 = 0x06;
const REG_DAY: u8 = 0x07;
const REG_MONTH: u8 = 0x08;
const REG_YEAR: u8 = 0x09;
const REG_STATUS_A: u8 = 0x0A;
const REG_STATUS_B: u8 = 0x0B;
const REG_STATUS_C: u8 = 0x0C;
const REG_STATUS_D: u8 = 0x0D;
const REG_CENTURY: u8 = 0x32;

// ── Status Register A bits ──

/// Update In Progress — do not read time while set.
const STATUS_A_UIP: u8 = 1 << 7;

// ── Status Register B bits ──

/// Daylight Saving Enable.
const _STATUS_B_DSE: u8 = 1 << 0;
/// 24-hour mode (1) vs 12-hour mode (0).
const STATUS_B_24HR: u8 = 1 << 1;
/// Data mode: 0 = BCD, 1 = binary.
const STATUS_B_DM: u8 = 1 << 2;
/// Update-ended Interrupt Enable.
const STATUS_B_UIE: u8 = 1 << 4;
/// Alarm Interrupt Enable.
const STATUS_B_AIE: u8 = 1 << 5;
/// Periodic Interrupt Enable.
const STATUS_B_PIE: u8 = 1 << 6;
/// SET — halt clock updates for writing time.
const STATUS_B_SET: u8 = 1 << 7;

// ── Status Register D bits ──

/// RTC valid / battery OK.
const STATUS_D_VRT: u8 = 1 << 7;

/// Wildcard value: "don't care" for alarm registers (matches every value).
const ALARM_WILDCARD: u8 = 0xC0;

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

/// Small I/O delay (standard x86 technique: dummy read of port 0x80).
fn io_delay() {
    io_inb(0x80);
}

// ── CMOS register access ──

/// Read a CMOS register, disabling NMI during access.
fn cmos_read(reg: u8) -> u8 {
    // Set bit 7 to disable NMI while we access the CMOS.
    io_outb(CMOS_ADDR, (1 << 7) | (reg & 0x7F));
    io_delay();
    let val = io_inb(CMOS_DATA);
    // Re-enable NMI by writing index with bit 7 clear.
    io_outb(CMOS_ADDR, reg & 0x7F);
    val
}

/// Write a CMOS register, disabling NMI during access.
fn cmos_write(reg: u8, val: u8) {
    io_outb(CMOS_ADDR, (1 << 7) | (reg & 0x7F));
    io_delay();
    io_outb(CMOS_DATA, val);
    // Re-enable NMI.
    io_outb(CMOS_ADDR, reg & 0x7F);
}

// ── BCD / time helpers ──

/// Convert BCD-encoded byte to binary.
fn bcd_to_bin(bcd: u8) -> u8 {
    (bcd & 0x0F) + ((bcd >> 4) * 10)
}

/// Convert binary byte to BCD.
fn bin_to_bcd(bin: u8) -> u8 {
    ((bin / 10) << 4) | (bin % 10)
}

/// Wait until the UIP bit clears in Status Register A.
/// Returns `true` on success, `false` on timeout.
fn wait_uip_clear() -> bool {
    // The UIP flag is set for ~244 us before each update; poll up to ~10 ms.
    for _ in 0..10_000u32 {
        if cmos_read(REG_STATUS_A) & STATUS_A_UIP == 0 {
            return true;
        }
        io_delay();
    }
    false
}

/// Read the raw time registers into an `RtcDateTime`.
/// Caller must ensure UIP is clear.
fn read_raw_time() -> RtcDateTime {
    RtcDateTime {
        second: cmos_read(REG_SECONDS),
        minute: cmos_read(REG_MINUTES),
        hour: cmos_read(REG_HOURS),
        weekday: cmos_read(REG_WEEKDAY),
        day: cmos_read(REG_DAY),
        month: cmos_read(REG_MONTH),
        year: cmos_read(REG_YEAR) as u16,
    }
}

/// Decode raw register values according to Status Register B settings.
/// Handles BCD-to-binary and 12-hour-to-24-hour conversion.
fn decode_time(raw: &mut RtcDateTime, status_b: u8, century_raw: u8) {
    let is_binary = status_b & STATUS_B_DM != 0;
    let is_24hr = status_b & STATUS_B_24HR != 0;

    // In 12-hour mode, bit 7 of the hours register means PM.
    let pm = !is_24hr && (raw.hour & 0x80 != 0);
    raw.hour &= 0x7F; // Strip PM flag before conversion.

    if !is_binary {
        raw.second = bcd_to_bin(raw.second);
        raw.minute = bcd_to_bin(raw.minute);
        raw.hour = bcd_to_bin(raw.hour);
        raw.day = bcd_to_bin(raw.day);
        raw.month = bcd_to_bin(raw.month);
        raw.weekday = bcd_to_bin(raw.weekday);
        raw.year = bcd_to_bin(raw.year as u8) as u16;
    }

    // 12-hour to 24-hour conversion.
    if !is_24hr {
        if raw.hour == 12 {
            // 12 AM = 0, 12 PM = 12.
            if !pm {
                raw.hour = 0;
            }
        } else if pm {
            raw.hour += 12;
        }
    }

    // Resolve century.
    let state = unsafe { &*STATE.get() };
    let century = if state.century_reg != 0 {
        let c = if !is_binary {
            bcd_to_bin(century_raw)
        } else {
            century_raw
        };
        if c >= 19 && c <= 29 {
            c as u16
        } else {
            20u16 // Fallback
        }
    } else {
        20u16
    };
    raw.year += century * 100;
}

/// Encode a `RtcDateTime` into raw register values for writing.
/// Returns `(seconds, minutes, hours, weekday, day, month, year_2digit, century)`.
fn encode_time(dt: &RtcDateTime, status_b: u8) -> (u8, u8, u8, u8, u8, u8, u8, u8) {
    let is_binary = status_b & STATUS_B_DM != 0;
    let is_24hr = status_b & STATUS_B_24HR != 0;

    let mut second = dt.second;
    let mut minute = dt.minute;
    let mut hour = dt.hour;
    let mut day = dt.day;
    let mut month = dt.month;
    let mut weekday = dt.weekday;
    let mut year_2 = (dt.year % 100) as u8;
    let mut century = (dt.year / 100) as u8;

    // Convert 24-hour to 12-hour if needed.
    let mut pm_flag: u8 = 0;
    if !is_24hr {
        if hour == 0 {
            hour = 12;
            // AM, no flag
        } else if hour < 12 {
            // AM, no flag
        } else if hour == 12 {
            pm_flag = 0x80;
        } else {
            hour -= 12;
            pm_flag = 0x80;
        }
    }

    if !is_binary {
        second = bin_to_bcd(second);
        minute = bin_to_bcd(minute);
        hour = bin_to_bcd(hour);
        day = bin_to_bcd(day);
        month = bin_to_bcd(month);
        weekday = bin_to_bcd(weekday);
        year_2 = bin_to_bcd(year_2);
        century = bin_to_bcd(century);
    }

    hour |= pm_flag;

    (second, minute, hour, weekday, day, month, year_2, century)
}

// ── Days-in-month helper for Unix timestamp calculation ──

fn is_leap_year(year: u16) -> bool {
    (year % 4 == 0 && year % 100 != 0) || (year % 400 == 0)
}

fn days_in_month(month: u8, year: u16) -> u16 {
    match month {
        1 => 31,
        2 => {
            if is_leap_year(year) {
                29
            } else {
                28
            }
        }
        3 => 31,
        4 => 30,
        5 => 31,
        6 => 30,
        7 => 31,
        8 => 31,
        9 => 30,
        10 => 31,
        11 => 30,
        12 => 31,
        _ => 30,
    }
}

/// Convert date/time to approximate Unix timestamp (seconds since 1970-01-01 00:00 UTC).
fn datetime_to_unix(dt: &RtcDateTime) -> i64 {
    let mut days: i64 = 0;

    // Count complete years from 1970 to dt.year - 1.
    let mut y = 1970u16;
    while y < dt.year {
        days += if is_leap_year(y) { 366 } else { 365 };
        y += 1;
    }

    // Count complete months in the current year.
    let mut m = 1u8;
    while m < dt.month {
        days += days_in_month(m, dt.year) as i64;
        m += 1;
    }

    // Add days in current month (day 1 = 0 extra days past the month start).
    days += (dt.day as i64).saturating_sub(1);

    days * 86400 + (dt.hour as i64) * 3600 + (dt.minute as i64) * 60 + (dt.second as i64)
}

// ── Exported functions ──

/// Initialize the CMOS RTC driver.
///
/// Returns 0 on success, -1 on failure.
#[unsafe(no_mangle)]
pub extern "C" fn cmos_rtc_init() -> i32 {
    log("cmos_rtc: initializing CMOS RTC driver");

    // Check battery / validity.
    let status_d = cmos_read(REG_STATUS_D);
    if status_d & STATUS_D_VRT == 0 {
        log("cmos_rtc: WARNING — RTC battery dead or CMOS invalid");
    }

    // Probe century register: read it and see if the value makes sense.
    let century_raw = cmos_read(REG_CENTURY);
    let century_val = bcd_to_bin(century_raw);
    let state = unsafe { &mut *STATE.get() };

    if century_val >= 19 && century_val <= 29 {
        state.century_reg = REG_CENTURY;
        unsafe {
            fut_printf(
                b"cmos_rtc: century register 0x32 = %u (valid)\n\0".as_ptr(),
                century_val as u32,
            );
        }
    } else {
        state.century_reg = 0;
        log("cmos_rtc: century register 0x32 not usable, assuming 20xx");
    }

    // Read and acknowledge any pending interrupt from Status Register C.
    let _ = cmos_read(REG_STATUS_C);

    // Log current Status B configuration.
    let status_b = cmos_read(REG_STATUS_B);
    let mode_str = if status_b & STATUS_B_DM != 0 {
        "binary"
    } else {
        "BCD"
    };
    let hour_str = if status_b & STATUS_B_24HR != 0 {
        "24h"
    } else {
        "12h"
    };
    unsafe {
        fut_printf(
            b"cmos_rtc: data mode=%s, hour mode=%s\n\0".as_ptr(),
            mode_str.as_ptr(),
            hour_str.as_ptr(),
        );
    }

    // Read and display the current time.
    let mut dt = RtcDateTime::zero();
    state.initialized = true;

    if cmos_rtc_read_time(&mut dt as *mut RtcDateTime) == 0 {
        unsafe {
            fut_printf(
                b"cmos_rtc: current time: %04u-%02u-%02u %02u:%02u:%02u\n\0".as_ptr(),
                dt.year as u32,
                dt.month as u32,
                dt.day as u32,
                dt.hour as u32,
                dt.minute as u32,
                dt.second as u32,
            );
        }
    }

    log("cmos_rtc: driver initialized");
    0
}

/// Read the current date/time from the CMOS RTC.
///
/// Uses the MC146818 double-read technique: read registers twice and compare
/// to ensure we did not read during an update cycle.
///
/// Returns 0 on success, -1 on failure.
#[unsafe(no_mangle)]
pub extern "C" fn cmos_rtc_read_time(out: *mut RtcDateTime) -> i32 {
    if out.is_null() {
        return -1;
    }

    let state = unsafe { &*STATE.get() };
    if !state.initialized {
        return -1;
    }

    // Double-read loop: read time, then read again; if values differ the first
    // read may have straddled an update.  Retry up to 5 times.
    let mut prev;
    let mut cur;
    let mut century_raw;

    // First read.
    if !wait_uip_clear() {
        log("cmos_rtc: UIP timeout on read");
        return -1;
    }
    prev = read_raw_time();
    century_raw = if state.century_reg != 0 {
        cmos_read(state.century_reg)
    } else {
        0
    };

    for _ in 0..5u32 {
        if !wait_uip_clear() {
            log("cmos_rtc: UIP timeout on read");
            return -1;
        }
        cur = read_raw_time();
        let cen = if state.century_reg != 0 {
            cmos_read(state.century_reg)
        } else {
            0
        };

        if cur.second == prev.second
            && cur.minute == prev.minute
            && cur.hour == prev.hour
            && cur.day == prev.day
            && cur.month == prev.month
            && cur.year == prev.year
            && cen == century_raw
        {
            // Consistent read — decode and return.
            let status_b = cmos_read(REG_STATUS_B);
            decode_time(&mut cur, status_b, century_raw);
            unsafe {
                *out = cur;
            }
            return 0;
        }

        prev = cur;
        century_raw = cen;
    }

    // Last attempt didn't converge — use the last read anyway.
    let status_b = cmos_read(REG_STATUS_B);
    decode_time(&mut prev, status_b, century_raw);
    unsafe {
        *out = prev;
    }
    0
}

/// Set the CMOS RTC date/time.
///
/// Halts the RTC update cycle (Status B SET bit), writes all registers,
/// then resumes updates.
///
/// Returns 0 on success, -1 on failure.
#[unsafe(no_mangle)]
pub extern "C" fn cmos_rtc_set_time(time: *const RtcDateTime) -> i32 {
    if time.is_null() {
        return -1;
    }

    let state = unsafe { &*STATE.get() };
    if !state.initialized {
        return -1;
    }

    let dt = unsafe { &*time };

    // Basic validation.
    if dt.month < 1
        || dt.month > 12
        || dt.day < 1
        || dt.day > 31
        || dt.hour > 23
        || dt.minute > 59
        || dt.second > 59
    {
        log("cmos_rtc: set_time: invalid date/time values");
        return -1;
    }

    let status_b = cmos_read(REG_STATUS_B);
    let (sec, min, hr, wkday, day, mon, yr2, cen) = encode_time(dt, status_b);

    // Halt updates by setting the SET bit in Status B.
    cmos_write(REG_STATUS_B, status_b | STATUS_B_SET);

    cmos_write(REG_SECONDS, sec);
    cmos_write(REG_MINUTES, min);
    cmos_write(REG_HOURS, hr);
    cmos_write(REG_WEEKDAY, wkday);
    cmos_write(REG_DAY, day);
    cmos_write(REG_MONTH, mon);
    cmos_write(REG_YEAR, yr2);

    if state.century_reg != 0 {
        cmos_write(state.century_reg, cen);
    }

    // Resume updates by clearing the SET bit (restore original status B).
    cmos_write(REG_STATUS_B, status_b & !STATUS_B_SET);

    unsafe {
        fut_printf(
            b"cmos_rtc: time set to %04u-%02u-%02u %02u:%02u:%02u\n\0".as_ptr(),
            dt.year as u32,
            dt.month as u32,
            dt.day as u32,
            dt.hour as u32,
            dt.minute as u32,
            dt.second as u32,
        );
    }

    0
}

/// Set the RTC alarm to trigger at the specified hour, minute, second.
///
/// The alarm fires once per day when the current time matches all three
/// fields.  Pass 0xC0 for any field to act as a wildcard ("don't care").
///
/// Returns 0 on success, -1 on failure.
#[unsafe(no_mangle)]
pub extern "C" fn cmos_rtc_set_alarm(hour: u8, minute: u8, second: u8) -> i32 {
    let state = unsafe { &*STATE.get() };
    if !state.initialized {
        return -1;
    }

    let status_b = cmos_read(REG_STATUS_B);
    let is_binary = status_b & STATUS_B_DM != 0;
    let is_24hr = status_b & STATUS_B_24HR != 0;

    // Encode the alarm values.
    let alarm_sec = if second >= ALARM_WILDCARD {
        ALARM_WILDCARD
    } else if !is_binary {
        bin_to_bcd(second)
    } else {
        second
    };

    let alarm_min = if minute >= ALARM_WILDCARD {
        ALARM_WILDCARD
    } else if !is_binary {
        bin_to_bcd(minute)
    } else {
        minute
    };

    let alarm_hr = if hour >= ALARM_WILDCARD {
        ALARM_WILDCARD
    } else {
        let mut h = hour;
        let mut pm_flag: u8 = 0;
        if !is_24hr {
            if h == 0 {
                h = 12;
            } else if h > 12 {
                h -= 12;
                pm_flag = 0x80;
            } else if h == 12 {
                pm_flag = 0x80;
            }
        }
        let encoded = if !is_binary { bin_to_bcd(h) } else { h };
        encoded | pm_flag
    };

    // Write alarm registers.
    cmos_write(REG_ALARM_SECONDS, alarm_sec);
    cmos_write(REG_ALARM_MINUTES, alarm_min);
    cmos_write(REG_ALARM_HOURS, alarm_hr);

    // Enable the Alarm Interrupt in Status B.
    let new_b = cmos_read(REG_STATUS_B) | STATUS_B_AIE;
    cmos_write(REG_STATUS_B, new_b);

    // Read Status C to clear any pending interrupt flags.
    let _ = cmos_read(REG_STATUS_C);

    unsafe {
        fut_printf(
            b"cmos_rtc: alarm set to %02u:%02u:%02u\n\0".as_ptr(),
            hour as u32,
            minute as u32,
            second as u32,
        );
    }

    0
}

/// Clear (disable) the RTC alarm interrupt.
///
/// Returns 0 on success, -1 on failure.
#[unsafe(no_mangle)]
pub extern "C" fn cmos_rtc_clear_alarm() -> i32 {
    let state = unsafe { &*STATE.get() };
    if !state.initialized {
        return -1;
    }

    // Disable alarm interrupt in Status B.
    let status_b = cmos_read(REG_STATUS_B);
    cmos_write(REG_STATUS_B, status_b & !STATUS_B_AIE);

    // Set alarm registers to wildcard (don't care).
    cmos_write(REG_ALARM_SECONDS, ALARM_WILDCARD);
    cmos_write(REG_ALARM_MINUTES, ALARM_WILDCARD);
    cmos_write(REG_ALARM_HOURS, ALARM_WILDCARD);

    // Acknowledge any pending alarm IRQ.
    let _ = cmos_read(REG_STATUS_C);

    log("cmos_rtc: alarm cleared");
    0
}

/// Check whether the RTC CMOS battery is OK.
///
/// Returns `true` if the VRT (Valid RAM and Time) bit is set in Status Register D.
#[unsafe(no_mangle)]
pub extern "C" fn cmos_rtc_battery_ok() -> bool {
    let status_d = cmos_read(REG_STATUS_D);
    status_d & STATUS_D_VRT != 0
}

/// Compute an approximate Unix timestamp (seconds since 1970-01-01 00:00:00 UTC).
///
/// Note: the CMOS RTC has no concept of time zone; the returned value assumes
/// the RTC is set to UTC.  No leap-second compensation is applied.
///
/// Returns the timestamp, or -1 on error.
#[unsafe(no_mangle)]
pub extern "C" fn cmos_rtc_unix_timestamp() -> i64 {
    let mut dt = RtcDateTime::zero();
    if cmos_rtc_read_time(&mut dt as *mut RtcDateTime) != 0 {
        return -1;
    }
    datetime_to_unix(&dt)
}
