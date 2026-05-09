// SPDX-License-Identifier: MPL-2.0
//
// rust-date — seventeenth user-space Rust program for Futura OS.
//
// Prints the current wall-clock time via clock_gettime(CLOCK_REALTIME).
// Format: "YYYY-MM-DD HH:MM:SS UTC". TZ_OFFSET_SEC env var is honored
// when present (positive seconds east of UTC) so a local timezone can
// be displayed without pulling in a tzdata blob.

#![no_std]
#![forbid(unsafe_op_in_unsafe_fn)]

use core::panic::PanicInfo;

#[cfg(target_arch = "aarch64")]
mod sysn {
    pub const WRITE: u64 = 64;
    pub const EXIT: u64 = 93;
    pub const CLOCK_GETTIME: u64 = 113;
}

#[cfg(target_arch = "x86_64")]
mod sysn {
    pub const WRITE: u64 = 1;
    pub const EXIT: u64 = 60;
    pub const CLOCK_GETTIME: u64 = 228;
}

const CLOCK_REALTIME: u64 = 0;
const STDOUT: i32 = 1;
const STDERR: i32 = 2;

#[repr(C)]
struct Timespec {
    tv_sec: i64,
    tv_nsec: i64,
}

#[cfg(target_arch = "aarch64")]
#[inline(always)]
unsafe fn syscall2(nr: u64, a: u64, b: u64) -> i64 {
    let mut ret: i64;
    unsafe {
        core::arch::asm!(
            "svc #0",
            in("x8") nr,
            inout("x0") a => ret,
            in("x1") b,
            options(nostack),
        );
    }
    ret
}

#[cfg(target_arch = "aarch64")]
#[inline(always)]
unsafe fn syscall3(nr: u64, a: u64, b: u64, c: u64) -> i64 {
    let mut ret: i64;
    unsafe {
        core::arch::asm!(
            "svc #0",
            in("x8") nr,
            inout("x0") a => ret,
            in("x1") b,
            in("x2") c,
            options(nostack),
        );
    }
    ret
}

#[cfg(target_arch = "aarch64")]
#[inline(always)]
unsafe fn sys_exit(code: u64) -> ! {
    unsafe {
        core::arch::asm!(
            "svc #0",
            in("x8") sysn::EXIT,
            in("x0") code,
            options(nostack, noreturn),
        );
    }
}

#[cfg(target_arch = "x86_64")]
#[inline(always)]
unsafe fn syscall2(nr: u64, a: u64, b: u64) -> i64 {
    let mut ret: i64;
    unsafe {
        core::arch::asm!(
            "syscall",
            inout("rax") nr => ret,
            in("rdi") a,
            in("rsi") b,
            lateout("rcx") _,
            lateout("r11") _,
            options(nostack),
        );
    }
    ret
}

#[cfg(target_arch = "x86_64")]
#[inline(always)]
unsafe fn syscall3(nr: u64, a: u64, b: u64, c: u64) -> i64 {
    let mut ret: i64;
    unsafe {
        core::arch::asm!(
            "syscall",
            inout("rax") nr => ret,
            in("rdi") a,
            in("rsi") b,
            in("rdx") c,
            lateout("rcx") _,
            lateout("r11") _,
            options(nostack),
        );
    }
    ret
}

#[cfg(target_arch = "x86_64")]
#[inline(always)]
unsafe fn sys_exit(code: u64) -> ! {
    unsafe {
        core::arch::asm!(
            "syscall",
            in("rax") sysn::EXIT,
            in("rdi") code,
            options(nostack, noreturn),
        );
    }
}

fn write_str(fd: i32, s: &[u8]) {
    unsafe {
        let _ = syscall3(sysn::WRITE, fd as u64, s.as_ptr() as u64, s.len() as u64);
    }
}

fn cstr_len(p: *const u8) -> usize {
    let mut n = 0;
    unsafe {
        while *p.add(n) != 0 {
            n += 1;
        }
    }
    n
}

#[panic_handler]
fn panic(_info: &PanicInfo) -> ! {
    write_str(STDERR, b"[rust-date] panic\n");
    unsafe {
        sys_exit(1);
    }
}

// Walk envp looking for "TZ_OFFSET_SEC=<n>". Returns the parsed offset
// (positive seconds east of UTC) or 0 if missing/malformed.
fn read_tz_offset(envp: *const *const u8) -> i64 {
    if envp.is_null() {
        return 0;
    }
    let key: &[u8] = b"TZ_OFFSET_SEC=";
    let mut i = 0usize;
    loop {
        let entry = unsafe { *envp.add(i) };
        if entry.is_null() {
            return 0;
        }
        if (entry as usize) < 0x10000 {
            return 0;
        }
        // Match prefix.
        let mut ok = true;
        for j in 0..key.len() {
            if unsafe { *entry.add(j) } != key[j] {
                ok = false;
                break;
            }
        }
        if ok {
            // Parse remainder as signed integer.
            let mut p = unsafe { entry.add(key.len()) };
            let mut neg = false;
            if unsafe { *p } == b'-' {
                neg = true;
                p = unsafe { p.add(1) };
            } else if unsafe { *p } == b'+' {
                p = unsafe { p.add(1) };
            }
            let mut v: i64 = 0;
            loop {
                let b = unsafe { *p };
                if !(b'0'..=b'9').contains(&b) {
                    break;
                }
                v = v.wrapping_mul(10).wrapping_add((b - b'0') as i64);
                p = unsafe { p.add(1) };
            }
            return if neg { -v } else { v };
        }
        i += 1;
    }
}

// Civil-from-days: convert days since 1970-01-01 (Unix epoch) to
// (year, month, day) using Howard Hinnant's algorithm. Always
// proleptic Gregorian, no leap-second hacks.
fn civil_from_days(z: i64) -> (i32, u32, u32) {
    let z = z + 719468;
    let era = if z >= 0 { z / 146097 } else { (z - 146096) / 146097 };
    let doe = (z - era * 146097) as u64; // [0, 146096]
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365;
    let y = yoe as i64 + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = (doy - (153 * mp + 2) / 5 + 1) as u32;
    let m = if mp < 10 { (mp + 3) as u32 } else { (mp - 9) as u32 };
    let y = if m <= 2 { y + 1 } else { y };
    (y as i32, m, d)
}

fn write_uint(buf: &mut [u8], pos: &mut usize, n: u64, width: usize) {
    let mut tmp = [0u8; 20];
    let mut t = 0usize;
    let mut x = n;
    if x == 0 {
        tmp[0] = b'0';
        t = 1;
    } else {
        while x > 0 && t < tmp.len() {
            tmp[t] = b'0' + (x % 10) as u8;
            x /= 10;
            t += 1;
        }
    }
    while t < width && t < tmp.len() {
        tmp[t] = b'0';
        t += 1;
    }
    for i in 0..t {
        if *pos < buf.len() {
            buf[*pos] = tmp[t - 1 - i];
            *pos += 1;
        }
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn main(_argc: i32, _argv: *const *const u8, envp: *const *const u8) -> i32 {
    let ts = Timespec { tv_sec: 0, tv_nsec: 0 };
    let rc = unsafe {
        syscall2(
            sysn::CLOCK_GETTIME,
            CLOCK_REALTIME,
            &ts as *const Timespec as u64,
        )
    };
    if rc < 0 {
        write_str(STDERR, b"rust-date: clock_gettime failed\n");
        return 1;
    }

    let tz_off = read_tz_offset(envp);
    let secs = ts.tv_sec.saturating_add(tz_off);

    // secs is signed seconds since epoch in the local zone.
    let day_secs = if secs >= 0 { secs % 86400 } else { ((secs % 86400) + 86400) % 86400 };
    let days = if secs >= 0 { secs / 86400 } else { (secs - 86399) / 86400 };
    let hh = (day_secs / 3600) as u64;
    let mm = ((day_secs % 3600) / 60) as u64;
    let ss = (day_secs % 60) as u64;
    let (y, mo, d) = civil_from_days(days);

    let mut out = [0u8; 64];
    let mut pos = 0usize;
    write_uint(&mut out, &mut pos, y as u64, 4);
    if pos < out.len() { out[pos] = b'-'; pos += 1; }
    write_uint(&mut out, &mut pos, mo as u64, 2);
    if pos < out.len() { out[pos] = b'-'; pos += 1; }
    write_uint(&mut out, &mut pos, d as u64, 2);
    if pos < out.len() { out[pos] = b' '; pos += 1; }
    write_uint(&mut out, &mut pos, hh, 2);
    if pos < out.len() { out[pos] = b':'; pos += 1; }
    write_uint(&mut out, &mut pos, mm, 2);
    if pos < out.len() { out[pos] = b':'; pos += 1; }
    write_uint(&mut out, &mut pos, ss, 2);
    if tz_off == 0 {
        let suf = b" UTC\n";
        for &b in suf {
            if pos < out.len() { out[pos] = b; pos += 1; }
        }
    } else {
        if pos < out.len() { out[pos] = b'\n'; pos += 1; }
    }
    write_str(STDOUT, &out[..pos]);
    let _ = cstr_len; // silence unused-import linter
    0
}
