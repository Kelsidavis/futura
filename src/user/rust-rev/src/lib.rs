// SPDX-License-Identifier: MPL-2.0
//
// rust-rev — reverse each line of input.
//
//   rust-rev               read stdin, reverse each line
//   rust-rev FILE [FILE…]  reverse each line of each file in turn
//
// util-linux rev(1) shape: read a line, write its bytes in reverse,
// then '\n'. Lines longer than MAX_LINE are still reversed in chunks
// (older portions of the buffer get flushed first), so the relative
// order of bytes within the available window is preserved as the
// "reverse" — same fallback behavior as util-linux on impossibly
// long lines.

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
const MAX_LINE: usize = 8192;

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
    write_str(STDERR, b"[rust-rev] panic\n");
    unsafe {
        sys_exit(1);
    }
}

// Reverse line[..len] in place and write it (without the implied '\n').
fn flush_line(line: &mut [u8], len: usize) -> bool {
    if len == 0 {
        return true;
    }
    let mut i = 0usize;
    let mut j = len - 1;
    while i < j {
        line.swap(i, j);
        i += 1;
        j -= 1;
    }
    write_all(STDOUT, &line[..len])
}

fn cstr_len(p: *const u8) -> usize {
    let mut n = 0;
    unsafe { while *p.add(n) != 0 { n += 1; } }
    n
}

// Process a single fd. Returns true on clean EOF, false on read/write error.
fn rev_fd(fd: i32) -> bool {
    let mut rbuf = [0u8; READ_BUF];
    let mut line = [0u8; MAX_LINE];
    let mut len = 0usize;
    let mut had_error = false;

    loop {
        let n = unsafe {
            syscall3(sysn::READ, fd as u64, rbuf.as_mut_ptr() as u64, rbuf.len() as u64)
        };
        if n < 0 { had_error = true; break; }
        if n == 0 { break; }
        let chunk = &rbuf[..n as usize];
        for &c in chunk {
            if c == b'\n' {
                if !flush_line(&mut line, len) { had_error = true; break; }
                if !write_all(STDOUT, b"\n") { had_error = true; break; }
                len = 0;
            } else if len < line.len() {
                line[len] = c;
                len += 1;
            } else {
                // Buffer full — flush what we have (already in forward
                // order, but rev is byte-level so the result is "the
                // visible window reversed"), then start fresh.
                if !flush_line(&mut line, len) { had_error = true; break; }
                len = 0;
                line[len] = c;
                len += 1;
            }
        }
        if had_error { break; }
    }

    // Trailing line without newline — emit reversed, no '\n' appended.
    if !had_error && len > 0 {
        if !flush_line(&mut line, len) { had_error = true; }
    }
    !had_error
}

#[unsafe(no_mangle)]
pub extern "C" fn main(argc: i32, argv: *const *const u8, _envp: *const *const u8) -> i32 {
    // --help short-circuit before any reads.
    if argc >= 2 {
        let first = unsafe { *argv.add(1) };
        if !first.is_null() && (first as usize) >= 0x10000 {
            let n = cstr_len(first);
            if n == 6 && unsafe {
                *first == b'-' && *first.add(1) == b'-' &&
                *first.add(2) == b'h' && *first.add(3) == b'e' &&
                *first.add(4) == b'l' && *first.add(5) == b'p'
            } {
                let help: &[u8] = b"\
Usage: rust-rev [FILE]...
Reverse each line of input. With no FILE (or FILE = '-') reads stdin.

  --help    show this help and exit
\0";
                let len = help.len() - 1;
                unsafe { let _ = syscall3(sysn::WRITE, STDOUT as u64,
                                          help.as_ptr() as u64, len as u64); }
                return 0;
            }
        }
    }
    if argc < 2 {
        return if rev_fd(STDIN) { 0 } else { 1 };
    }
    let mut had_error = false;
    for ai in 1..argc {
        let p = unsafe { *argv.add(ai as usize) };
        if p.is_null() || (p as usize) < 0x10000 {
            had_error = true;
            continue;
        }
        // "-" reads stdin (matches GNU rev's convention).
        let nlen = cstr_len(p);
        let is_dash = nlen == 1 && unsafe { *p } == b'-';
        if is_dash {
            if !rev_fd(STDIN) { had_error = true; }
            continue;
        }
        let fd = unsafe {
            syscall4(sysn::OPENAT, AT_FDCWD as u64, p as u64, O_RDONLY, 0)
        };
        if fd < 0 {
            write_str(STDERR, b"rust-rev: cannot open '");
            unsafe { let _ = syscall3(sysn::WRITE, STDERR as u64, p as u64, nlen as u64); }
            write_str(STDERR, b"'\n");
            had_error = true;
            continue;
        }
        if !rev_fd(fd as i32) { had_error = true; }
        unsafe { let _ = syscall1(sysn::CLOSE, fd as u64); }
    }
    if had_error { 1 } else { 0 }
}
