// SPDX-License-Identifier: MPL-2.0
//
// rust-kill — send a signal to a pid.
//
//   rust-kill <pid>             send SIGTERM (15)
//   rust-kill -<sig> <pid>      send numeric signal <sig>
//   rust-kill -s <sig> <pid>    send numeric signal <sig> (POSIX form)
//
// Decimal signal numbers only — no name → number table yet
// (TERM, KILL, INT, HUP, …). The shell already has those names
// covered for interactive use; this is mostly here so /usr/bin/kill
// resolves and scripts that exec it directly Just Work.
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
        if n >= 2 && unsafe { *first } == b'-' {
            // -s <sig> <pid>... or -<sig> <pid>...
            let second_byte = unsafe { *first.add(1) };
            if n == 2 && second_byte == b's' {
                if argc < 4 {
                    write_str(STDERR, b"rust-kill: -s needs a signal and at least one pid\n");
                    return 1;
                }
                let sig_p = unsafe { *argv.add(2) };
                if sig_p.is_null() || (sig_p as usize) < 0x10000 {
                    return 1;
                }
                match parse_i32(sig_p) {
                    Some(v) if v >= 0 => sig = v,
                    _ => {
                        write_str(STDERR, b"rust-kill: invalid signal (decimal only)\n");
                        return 1;
                    }
                }
                idx = 3;
            } else {
                // -<sig> form: skip the leading '-' and parse the rest as decimal.
                let sig_slice = &unsafe { core::slice::from_raw_parts(first, n) }[1..];
                let mut v: i64 = 0;
                for &c in sig_slice {
                    if !(b'0'..=b'9').contains(&c) {
                        write_str(STDERR, b"rust-kill: invalid signal (decimal only)\n");
                        return 1;
                    }
                    v = v * 10 + (c - b'0') as i64;
                    if v > i32::MAX as i64 {
                        return 1;
                    }
                }
                sig = v as i32;
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
