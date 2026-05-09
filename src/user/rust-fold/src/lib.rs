// SPDX-License-Identifier: MPL-2.0
//
// rust-fold — wrap each input line at COLS columns.
//
//   rust-fold                       wrap stdin at 80 columns
//   rust-fold -w <cols>             wrap stdin at <cols> columns
//   rust-fold [-w <cols>] FILE…     wrap each FILE in turn
//   rust-fold ... -                 wrap stdin (in any position)
//
// Stream-style: emits a '\n' every <cols> bytes within a logical
// input line and resets the column count on each newline. Doesn't
// special-case tabs or backspace (BSD fold's -s/-b/-w semantics
// beyond -w are TBD); each byte is one column.
//
// 4 KiB read buffer, no allocator.

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
const DEFAULT_COLS: u32 = 80;

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
    write_str(STDERR, b"[rust-fold] panic\n");
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

fn parse_u32(p: *const u8) -> Option<u32> {
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
        if v > u32::MAX as u64 {
            return None;
        }
    }
    Some(v as u32)
}

// Process one fd. Each call resets the column counter so wrap state
// doesn't leak between files. Returns true on success.
fn fold_fd(fd: i32, cols: u32) -> bool {
    let mut buf = [0u8; READ_BUF];
    let mut col: u32 = 0;
    loop {
        let n = unsafe {
            syscall3(sysn::READ, fd as u64, buf.as_mut_ptr() as u64, buf.len() as u64)
        };
        if n < 0 { return false; }
        if n == 0 { return true; }
        let chunk = &buf[..n as usize];
        let mut start = 0usize;
        for i in 0..chunk.len() {
            let c = chunk[i];
            if c == b'\n' {
                if !write_all(STDOUT, &chunk[start..=i]) { return false; }
                col = 0;
                start = i + 1;
            } else {
                if col == cols {
                    if !write_all(STDOUT, &chunk[start..i]) { return false; }
                    if !write_all(STDOUT, b"\n") { return false; }
                    col = 0;
                    start = i;
                }
                col += 1;
            }
        }
        if start < chunk.len() {
            if !write_all(STDOUT, &chunk[start..]) { return false; }
        }
    }
}

fn cstr_len(p: *const u8) -> usize {
    let mut n = 0;
    unsafe { while *p.add(n) != 0 { n += 1; } }
    n
}

#[unsafe(no_mangle)]
pub extern "C" fn main(argc: i32, argv: *const *const u8, _envp: *const *const u8) -> i32 {
    let mut cols: u32 = DEFAULT_COLS;
    // First pass: skip just the leading flag(s) so the file list starts
    // after them. Files are processed in the second pass.
    let mut idx: i32 = 1;
    while idx < argc {
        let p = unsafe { *argv.add(idx as usize) };
        if p.is_null() || (p as usize) < 0x10000 {
            idx += 1;
            continue;
        }
        if cstr_eq(p, b"-w") {
            if idx + 1 >= argc {
                write_str(STDERR, b"rust-fold: -w needs an argument\n");
                return 2;
            }
            let arg = unsafe { *argv.add((idx + 1) as usize) };
            if arg.is_null() || (arg as usize) < 0x10000 {
                return 2;
            }
            match parse_u32(arg) {
                Some(v) if v > 0 => cols = v,
                _ => {
                    write_str(STDERR, b"rust-fold: invalid width\n");
                    return 2;
                }
            }
            idx += 2;
            continue;
        }
        if cstr_eq(p, b"--") { idx += 1; break; }
        break;  // first non-flag arg starts the file list
    }

    if idx >= argc {
        return if fold_fd(STDIN, cols) { 0 } else { 1 };
    }

    let mut had_error = false;
    while idx < argc {
        let p = unsafe { *argv.add(idx as usize) };
        idx += 1;
        if p.is_null() || (p as usize) < 0x10000 {
            had_error = true;
            continue;
        }
        let nlen = cstr_len(p);
        let is_dash = nlen == 1 && unsafe { *p } == b'-';
        if is_dash {
            if !fold_fd(STDIN, cols) { had_error = true; }
            continue;
        }
        let fd = unsafe {
            syscall4(sysn::OPENAT, AT_FDCWD as u64, p as u64, O_RDONLY, 0) as i32
        };
        if fd < 0 {
            write_str(STDERR, b"rust-fold: cannot open '");
            unsafe { let _ = syscall3(sysn::WRITE, STDERR as u64, p as u64, nlen as u64); }
            write_str(STDERR, b"'\n");
            had_error = true;
            continue;
        }
        if !fold_fd(fd, cols) { had_error = true; }
        unsafe { let _ = syscall1(sysn::CLOSE, fd as u64); }
    }
    if had_error { 1 } else { 0 }
}
