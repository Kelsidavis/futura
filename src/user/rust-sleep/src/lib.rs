// SPDX-License-Identifier: MPL-2.0
//
// rust-sleep — sleep for N seconds via the nanosleep(2) syscall.
//
//   rust-sleep 5            5 seconds
//   rust-sleep 0.5          half a second
//   rust-sleep 5s 1m 2h     5 seconds + 1 minute + 2 hours (summed)
//   rust-sleep              1 second (default)
//
// Each argument is parsed as `<int>[.<frac>][<suffix>]` where suffix
// is one of s / m / h / d (seconds / minutes / hours / days). All
// args are summed and slept in a single nanosleep call. Fractional
// resolution is bounded by Timespec.tv_nsec (1 ns).

#![no_std]
#![forbid(unsafe_op_in_unsafe_fn)]

use core::panic::PanicInfo;

#[cfg(target_arch = "aarch64")]
mod sysn {
    pub const WRITE: u64 = 64;
    pub const EXIT: u64 = 93;
    pub const NANOSLEEP: u64 = 101;
}

#[cfg(target_arch = "x86_64")]
mod sysn {
    pub const WRITE: u64 = 1;
    pub const EXIT: u64 = 60;
    pub const NANOSLEEP: u64 = 35;
}

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

fn argv_get(argc: i32, argv: *const *const u8, idx: usize) -> Option<*const u8> {
    if (idx as i32) >= argc {
        return None;
    }
    unsafe {
        let p = *argv.add(idx);
        if p.is_null() { None } else { Some(p) }
    }
}

// Parse one sleep token of the form `<int>[.<frac>][<suffix>]` and
// return its duration in nanoseconds.
//
// Suffixes: s (seconds, default), m (minutes), h (hours), d (days).
// Fractional precision is read up to 9 digits (matches Timespec
// resolution) — extra digits are silently truncated.
fn parse_token(p: *const u8) -> Option<u64> {
    let n = cstr_len(p);
    if n == 0 { return None; }

    // Optional unit suffix at the end.
    let last = unsafe { *p.add(n - 1) };
    let (digit_end, mult_ns_per_unit): (usize, u64) = match last {
        b's' => (n - 1, 1_000_000_000),
        b'm' => (n - 1, 60u64 * 1_000_000_000),
        b'h' => (n - 1, 3_600u64 * 1_000_000_000),
        b'd' => (n - 1, 86_400u64 * 1_000_000_000),
        b'0'..=b'9' | b'.' => (n, 1_000_000_000),
        _ => return None,
    };
    if digit_end == 0 { return None; }

    // Split at the optional decimal point.
    let mut dot = digit_end;
    for i in 0..digit_end {
        if unsafe { *p.add(i) } == b'.' { dot = i; break; }
    }

    // Integer part.
    let mut whole: u64 = 0;
    if dot > 0 {
        for i in 0..dot {
            let b = unsafe { *p.add(i) };
            if !(b'0'..=b'9').contains(&b) { return None; }
            whole = whole.checked_mul(10)?.checked_add((b - b'0') as u64)?;
        }
    }

    // Fractional part: scale to nanoseconds. With suffix=s the scale
    // is 1e9; for m/h/d we scale up after the parse so we keep ns
    // precision rather than losing it.
    let mut frac_ns: u64 = 0;
    if dot < digit_end {
        let mut place: u64 = 100_000_000; // 0.1 ns place start
        let mut i = dot + 1;
        while i < digit_end && place > 0 {
            let b = unsafe { *p.add(i) };
            if !(b'0'..=b'9').contains(&b) { return None; }
            frac_ns += (b - b'0') as u64 * place;
            place /= 10;
            i += 1;
        }
        // Skip any extra fractional digits (precision lost, not an error).
    }

    // Compose. For non-second suffixes, scale BOTH the whole-unit
    // count and the per-unit fractional ns by the unit-to-ns ratio.
    // mult_ns_per_unit IS the ns count for one unit. The fractional
    // part above was computed assuming 1-second-equivalent precision,
    // so for minutes/hours/days we scale both pieces consistently.
    let unit_secs = mult_ns_per_unit / 1_000_000_000; // 1, 60, 3600, 86400
    let total_ns = whole.checked_mul(mult_ns_per_unit)?
        .checked_add(frac_ns.checked_mul(unit_secs)?)?;
    Some(total_ns)
}

#[panic_handler]
fn panic(_info: &PanicInfo) -> ! {
    write_str(STDERR, b"[rust-sleep] panic\n");
    unsafe {
        sys_exit(1);
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn main(argc: i32, argv: *const *const u8, _envp: *const *const u8) -> i32 {
    // Sum every argv token. With no args, sleep 1 second to match
    // the previous default.
    let mut total_ns: u64 = 0;
    let mut idx: usize = 1;
    let mut had_arg = false;
    // Top-level --help short-circuit (single-arg form: `sleep --help`).
    if argc == 2 {
        let first = unsafe { *argv.add(1) };
        if !first.is_null() && (first as usize) >= 0x10000 {
            let want = b"--help";
            let n = cstr_len(first);
            if n == want.len() {
                let mut ok = true;
                for i in 0..want.len() {
                    if unsafe { *first.add(i) } != want[i] { ok = false; break; }
                }
                if ok {
                    let help: &[u8] = b"\
Usage: rust-sleep [DURATION...]
Pause for DURATION seconds. Multiple DURATIONs are summed.

  DURATION   integer or fractional seconds with optional unit suffix:
             s (seconds, default), m (minutes), h (hours), d (days)
             e.g. 0.5  /  5s  /  1m  /  1.5h  /  2d
      --help     show this help and exit

With no DURATION, sleep 1 second.
\0";
                    let len = help.len() - 1;
                    unsafe { let _ = syscall3(sysn::WRITE, 1, help.as_ptr() as u64, len as u64); }
                    return 0;
                }
            }
        }
    }
    while let Some(p) = argv_get(argc, argv, idx) {
        idx += 1;
        had_arg = true;
        match parse_token(p) {
            Some(ns) => match total_ns.checked_add(ns) {
                Some(s) => total_ns = s,
                None => {
                    write_str(STDERR, b"rust-sleep: total duration overflows u64 ns\n");
                    return 1;
                }
            },
            None => {
                write_str(STDERR, b"rust-sleep: invalid duration (use NUM[.frac][s|m|h|d])\n");
                return 1;
            }
        }
    }
    if !had_arg {
        total_ns = 1_000_000_000;
    }

    let secs = (total_ns / 1_000_000_000) as i64;
    let nsecs = (total_ns % 1_000_000_000) as i64;
    let req = Timespec { tv_sec: secs, tv_nsec: nsecs };
    let rem = Timespec { tv_sec: 0, tv_nsec: 0 };
    let rc = unsafe {
        syscall2(
            sysn::NANOSLEEP,
            &req as *const Timespec as u64,
            &rem as *const Timespec as u64,
        )
    };
    if rc < 0 {
        write_str(STDERR, b"rust-sleep: nanosleep failed\n");
        return 1;
    }
    0
}
