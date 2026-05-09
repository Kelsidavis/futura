// SPDX-License-Identifier: MPL-2.0
//
// rust-rev — reverse each line read from stdin.
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
}

#[cfg(target_arch = "x86_64")]
mod sysn {
    pub const READ: u64 = 0;
    pub const WRITE: u64 = 1;
    pub const EXIT: u64 = 60;
}

const STDIN: i32 = 0;
const STDOUT: i32 = 1;
const STDERR: i32 = 2;
const READ_BUF: usize = 4096;
const MAX_LINE: usize = 8192;

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

#[unsafe(no_mangle)]
pub extern "C" fn main(_argc: i32, _argv: *const *const u8, _envp: *const *const u8) -> i32 {
    let mut rbuf = [0u8; READ_BUF];
    let mut line = [0u8; MAX_LINE];
    let mut len = 0usize;
    let mut had_error = false;

    loop {
        let n = unsafe {
            syscall3(sysn::READ, STDIN as u64, rbuf.as_mut_ptr() as u64, rbuf.len() as u64)
        };
        if n < 0 {
            had_error = true;
            break;
        }
        if n == 0 {
            break;
        }
        let chunk = &rbuf[..n as usize];
        for &c in chunk {
            if c == b'\n' {
                if !flush_line(&mut line, len) { had_error = true; break; }
                if !write_all(STDOUT, b"\n") { had_error = true; break; }
                len = 0;
            } else {
                if len < line.len() {
                    line[len] = c;
                    len += 1;
                } else {
                    // Buffer full — flush what we have (already in
                    // forward order, but rev is byte-level so the
                    // result is "the visible window reversed"), then
                    // start a fresh buffer with the current byte.
                    if !flush_line(&mut line, len) { had_error = true; break; }
                    len = 0;
                    line[len] = c;
                    len += 1;
                }
            }
        }
        if had_error { break; }
    }

    // Trailing line without newline — emit reversed, no '\n' appended.
    if !had_error && len > 0 {
        if !flush_line(&mut line, len) {
            had_error = true;
        }
    }

    if had_error { 1 } else { 0 }
}
