// SPDX-License-Identifier: MPL-2.0
//
// rust-kill — send a signal to a pid.
//
//   rust-kill <pid>             send SIGTERM (15)
//   rust-kill -<sig> <pid>      send signal by number or name
//   rust-kill -s <sig> <pid>    send signal by number or name (POSIX form)
//   rust-kill -l                list known signal names
//
// Accepts decimal signal numbers OR Linux-generic signal names
// (with or without the SIG prefix), e.g. -TERM, -SIGTERM, -9, -KILL.
//
// Multiple <pid> args: signals every one and exits 1 if any kill()
// call failed.

#![no_std]
#![forbid(unsafe_op_in_unsafe_fn)]

use core::panic::PanicInfo;

#[cfg(target_arch = "aarch64")]
mod sysn {
    pub const WRITE: u64 = 64;
    pub const EXIT: u64 = 93;
    pub const KILL: u64 = 129;
}

#[cfg(target_arch = "x86_64")]
mod sysn {
    pub const WRITE: u64 = 1;
    pub const EXIT: u64 = 60;
    pub const KILL: u64 = 62;
}

const STDERR: i32 = 2;
const SIGTERM: i32 = 15;

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

#[panic_handler]
fn panic(_info: &PanicInfo) -> ! {
    write_str(STDERR, b"[rust-kill] panic\n");
    unsafe {
        sys_exit(1);
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

// Parse a decimal i32. Returns None on non-digit / overflow.
fn parse_i32(p: *const u8) -> Option<i32> {
    let n = cstr_len(p);
    if n == 0 {
        return None;
    }
    let s = unsafe { core::slice::from_raw_parts(p, n) };
    let (start, neg) = if s[0] == b'-' { (1, true) } else { (0, false) };
    if start == n {
        return None;
    }
    let mut v: i64 = 0;
    for &c in &s[start..] {
        if !(b'0'..=b'9').contains(&c) {
            return None;
        }
        v = v * 10 + (c - b'0') as i64;
        if v > i32::MAX as i64 {
            return None;
        }
    }
    Some(if neg { -(v as i32) } else { v as i32 })
}

// Linux-generic signal numbers. Same on aarch64 and x86_64 except
// SIGSTKFLT (16, x86 only) — omitted to keep the table portable.
const SIG_TABLE: &[(&[u8], i32)] = &[
    (b"HUP", 1),  (b"INT", 2),  (b"QUIT", 3),  (b"ILL", 4),
    (b"TRAP", 5), (b"ABRT", 6), (b"IOT", 6),   (b"BUS", 7),
    (b"FPE", 8),  (b"KILL", 9), (b"USR1", 10), (b"SEGV", 11),
    (b"USR2", 12),(b"PIPE", 13),(b"ALRM", 14), (b"TERM", 15),
    (b"CHLD", 17),(b"CONT", 18),(b"STOP", 19), (b"TSTP", 20),
    (b"TTIN", 21),(b"TTOU", 22),(b"URG", 23),  (b"XCPU", 24),
    (b"XFSZ", 25),(b"VTALRM",26),(b"PROF", 27),(b"WINCH",28),
    (b"IO", 29),  (b"PWR", 30), (b"SYS", 31),
];

fn ascii_eq_upper(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() { return false; }
    for i in 0..a.len() {
        let ca = a[i];
        let cu = if ca >= b'a' && ca <= b'z' { ca - 32 } else { ca };
        if cu != b[i] { return false; }
    }
    true
}

// Parse a signal token (already stripped of leading '-' if any).
// Accepts decimal (e.g. "9", "15") OR a name (TERM, SIGTERM,
// case-insensitive).
fn parse_signal(s: &[u8]) -> Option<i32> {
    if s.is_empty() { return None; }
    if s[0] >= b'0' && s[0] <= b'9' {
        let mut v: i64 = 0;
        for &c in s {
            if !(b'0'..=b'9').contains(&c) { return None; }
            v = v * 10 + (c - b'0') as i64;
            if v > i32::MAX as i64 { return None; }
        }
        return Some(v as i32);
    }
    // Strip optional "SIG" / "sig" prefix.
    let body: &[u8] = if s.len() > 3 &&
        (s[0] == b'S' || s[0] == b's') &&
        (s[1] == b'I' || s[1] == b'i') &&
        (s[2] == b'G' || s[2] == b'g') {
        &s[3..]
    } else {
        s
    };
    for &(name, num) in SIG_TABLE {
        if ascii_eq_upper(body, name) { return Some(num); }
    }
    None
}

fn write_dec(fd: i32, mut n: i32) {
    let mut buf = [0u8; 12];
    let mut i = buf.len();
    if n == 0 { i -= 1; buf[i] = b'0'; }
    let neg = n < 0;
    if neg { n = -n; }
    while n > 0 { i -= 1; buf[i] = b'0' + (n % 10) as u8; n /= 10; }
    if neg { i -= 1; buf[i] = b'-'; }
    write_str(fd, &buf[i..]);
}

fn list_signals() {
    const STDOUT: i32 = 1;
    for &(name, num) in SIG_TABLE {
        write_dec(STDOUT, num);
        write_str(STDOUT, b") SIG");
        write_str(STDOUT, name);
        write_str(STDOUT, b"\n");
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn main(argc: i32, argv: *const *const u8, _envp: *const *const u8) -> i32 {
    if argc < 2 {
        write_str(STDERR, b"usage: rust-kill [-<sig>|-s <sig>] <pid>...\n");
        return 1;
    }

    let mut sig: i32 = SIGTERM;
    let mut idx: i32 = 1;
    let first = unsafe { *argv.add(1) };
    if !first.is_null() && (first as usize) >= 0x10000 {
        let n = cstr_len(first);
        let bytes = unsafe { core::slice::from_raw_parts(first, n) };
        if n == 2 && bytes[0] == b'-' && bytes[1] == b'l' {
            list_signals();
            return 0;
        }
        if n >= 2 && bytes[0] == b'-' {
            // -s <sig> <pid>... or -<sig> <pid>...
            if n == 2 && bytes[1] == b's' {
                if argc < 4 {
                    write_str(STDERR, b"rust-kill: -s needs a signal and at least one pid\n");
                    return 1;
                }
                let sig_p = unsafe { *argv.add(2) };
                if sig_p.is_null() || (sig_p as usize) < 0x10000 {
                    return 1;
                }
                let sn = cstr_len(sig_p);
                let sslice = unsafe { core::slice::from_raw_parts(sig_p, sn) };
                match parse_signal(sslice) {
                    Some(v) if v >= 0 => sig = v,
                    _ => {
                        write_str(STDERR, b"rust-kill: invalid signal\n");
                        return 1;
                    }
                }
                idx = 3;
            } else {
                // -<sig> form: skip the leading '-' and parse name or number.
                match parse_signal(&bytes[1..]) {
                    Some(v) if v >= 0 => sig = v,
                    _ => {
                        write_str(STDERR, b"rust-kill: invalid signal\n");
                        return 1;
                    }
                }
                idx = 2;
            }
        }
    }

    if idx >= argc {
        write_str(STDERR, b"rust-kill: no pid given\n");
        return 1;
    }

    let mut had_error = false;
    for ai in idx..argc {
        let p = unsafe { *argv.add(ai as usize) };
        if p.is_null() || (p as usize) < 0x10000 {
            had_error = true;
            continue;
        }
        let pid = match parse_i32(p) {
            Some(v) => v,
            None => {
                write_str(STDERR, b"rust-kill: invalid pid\n");
                had_error = true;
                continue;
            }
        };
        let r = unsafe { syscall2(sysn::KILL, pid as i64 as u64, sig as u64) };
        if r < 0 {
            write_str(STDERR, b"rust-kill: kill() failed\n");
            had_error = true;
        }
    }
    if had_error { 1 } else { 0 }
}
