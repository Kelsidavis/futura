// SPDX-License-Identifier: MPL-2.0
//
// rust-strings — extract sequences of printable ASCII bytes.
//
//   rust-strings [-n <min>] [<file>]
//
// Walks the input byte-by-byte and prints each maximal run of
// printable bytes (0x20..=0x7e plus tab) that's at least <min>
// bytes long, terminated by '\n'. Default <min> is 4 (matches
// GNU strings). With no FILE arg, reads stdin.
//
// Stream-style: 4 KiB read buffer, fixed RUN_BUF for the
// in-progress candidate run, no allocator.

#![no_std]
#![forbid(unsafe_op_in_unsafe_fn)]

use core::panic::PanicInfo;

#[cfg(target_arch = "aarch64")]
mod sysn {
    pub const READ: u64 = 63;
    pub const WRITE: u64 = 64;
    pub const EXIT: u64 = 93;
    pub const OPENAT: u64 = 56;
    pub const CLOSE: u64 = 57;
}

#[cfg(target_arch = "x86_64")]
mod sysn {
    pub const READ: u64 = 0;
    pub const WRITE: u64 = 1;
    pub const EXIT: u64 = 60;
    pub const OPENAT: u64 = 257;
    pub const CLOSE: u64 = 3;
}

const AT_FDCWD: i64 = -100;
const O_RDONLY: u64 = 0;
const STDIN: i32 = 0;
const STDOUT: i32 = 1;
const STDERR: i32 = 2;
const READ_BUF: usize = 4096;
const RUN_BUF: usize = 4096;

#[cfg(target_arch = "aarch64")]
#[inline(always)]
unsafe fn syscall1(nr: u64, a: u64) -> i64 {
    let mut ret: i64;
    unsafe {
        core::arch::asm!(
            "svc #0",
            in("x8") nr,
            inout("x0") a => ret,
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
unsafe fn syscall4(nr: u64, a: u64, b: u64, c: u64, d: u64) -> i64 {
    let mut ret: i64;
    unsafe {
        core::arch::asm!(
            "svc #0",
            in("x8") nr,
            inout("x0") a => ret,
            in("x1") b,
            in("x2") c,
            in("x3") d,
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
unsafe fn syscall1(nr: u64, a: u64) -> i64 {
    let mut ret: i64;
    unsafe {
        core::arch::asm!(
            "syscall",
            inout("rax") nr => ret,
            in("rdi") a,
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
unsafe fn syscall4(nr: u64, a: u64, b: u64, c: u64, d: u64) -> i64 {
    let mut ret: i64;
    unsafe {
        core::arch::asm!(
            "syscall",
            inout("rax") nr => ret,
            in("rdi") a,
            in("rsi") b,
            in("rdx") c,
            in("r10") d,
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

fn write_all(fd: i32, mut s: &[u8]) -> bool {
    while !s.is_empty() {
        let n = unsafe { syscall3(sysn::WRITE, fd as u64, s.as_ptr() as u64, s.len() as u64) };
        if n <= 0 {
            return false;
        }
        s = &s[n as usize..];
    }
    true
}

fn write_str(fd: i32, s: &[u8]) {
    let _ = write_all(fd, s);
}

#[panic_handler]
fn panic(_info: &PanicInfo) -> ! {
    write_str(STDERR, b"[rust-strings] panic\n");
    unsafe {
        sys_exit(1);
    }
}

fn cstr_eq(p: *const u8, s: &[u8]) -> bool {
    for (i, &b) in s.iter().enumerate() {
        if unsafe { *p.add(i) } != b {
            return false;
        }
    }
    unsafe { *p.add(s.len()) == 0 }
}

fn parse_usize(p: *const u8) -> Option<usize> {
    let mut n = 0usize;
    unsafe { while *p.add(n) != 0 { n += 1; } }
    if n == 0 || n > 10 {
        return None;
    }
    let s = unsafe { core::slice::from_raw_parts(p, n) };
    let mut v: u64 = 0;
    for &c in s {
        if !(b'0'..=b'9').contains(&c) {
            return None;
        }
        v = v * 10 + (c - b'0') as u64;
        if v > usize::MAX as u64 {
            return None;
        }
    }
    Some(v as usize)
}

fn is_print(b: u8) -> bool {
    b == b'\t' || (0x20..=0x7e).contains(&b)
}

#[unsafe(no_mangle)]
pub extern "C" fn main(argc: i32, argv: *const *const u8, _envp: *const *const u8) -> i32 {
    let mut min: usize = 4;
    let mut idx: i32 = 1;
    while idx < argc {
        let p = unsafe { *argv.add(idx as usize) };
        if p.is_null() || (p as usize) < 0x10000 {
            idx += 1;
            continue;
        }
        if cstr_eq(p, b"-n") {
            if idx + 1 >= argc {
                write_str(STDERR, b"rust-strings: -n needs an argument\n");
                return 2;
            }
            let arg = unsafe { *argv.add((idx + 1) as usize) };
            if arg.is_null() || (arg as usize) < 0x10000 {
                return 2;
            }
            match parse_usize(arg) {
                Some(v) if v > 0 => min = v,
                _ => {
                    write_str(STDERR, b"rust-strings: invalid -n value\n");
                    return 2;
                }
            }
            idx += 2;
        } else {
            break; // first non-flag arg is the file
        }
    }

    if idx >= argc {
        return if scan_fd(STDIN, min) { 0 } else { 1 };
    }
    let mut had_error = false;
    while idx < argc {
        let p = unsafe { *argv.add(idx as usize) };
        idx += 1;
        if p.is_null() || (p as usize) < 0x10000 {
            had_error = true;
            continue;
        }
        let mut nlen = 0usize;
        unsafe { while *p.add(nlen) != 0 { nlen += 1; } }
        let is_dash = nlen == 1 && unsafe { *p } == b'-';
        if is_dash {
            if !scan_fd(STDIN, min) { had_error = true; }
            continue;
        }
        let f = unsafe {
            syscall4(sysn::OPENAT, AT_FDCWD as u64, p as u64, O_RDONLY, 0) as i32
        };
        if f < 0 {
            write_str(STDERR, b"rust-strings: cannot open '");
            unsafe { let _ = syscall3(sysn::WRITE, STDERR as u64, p as u64, nlen as u64); }
            write_str(STDERR, b"'\n");
            had_error = true;
            continue;
        }
        if !scan_fd(f, min) { had_error = true; }
        unsafe { let _ = syscall1(sysn::CLOSE, f as u64); }
    }
    if had_error { 1 } else { 0 }
}

// Scan one fd for runs of printable bytes >= min and emit each on its
// own line. Returns true on success.
fn scan_fd(fd: i32, min: usize) -> bool {
    let mut buf = [0u8; READ_BUF];
    let mut run = [0u8; RUN_BUF];
    let mut run_len = 0usize;
    let mut had_error = false;

    'outer: loop {
        let n = unsafe {
            syscall3(sysn::READ, fd as u64, buf.as_mut_ptr() as u64, buf.len() as u64)
        };
        if n < 0 { had_error = true; break; }
        if n == 0 { break; }
        let chunk = &buf[..n as usize];
        for &c in chunk {
            if is_print(c) {
                if run_len < RUN_BUF {
                    run[run_len] = c;
                    run_len += 1;
                } else {
                    if !write_all(STDOUT, &run[..run_len]) { had_error = true; break 'outer; }
                    if !write_all(STDOUT, b"\n") { had_error = true; break 'outer; }
                    run[0] = c;
                    run_len = 1;
                }
            } else {
                if run_len >= min {
                    if !write_all(STDOUT, &run[..run_len]) { had_error = true; break 'outer; }
                    if !write_all(STDOUT, b"\n") { had_error = true; break 'outer; }
                }
                run_len = 0;
            }
        }
    }
    if !had_error && run_len >= min {
        if !write_all(STDOUT, &run[..run_len]) { had_error = true; }
        else if !write_all(STDOUT, b"\n") { had_error = true; }
    }
    !had_error
}
