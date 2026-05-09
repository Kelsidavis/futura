// SPDX-License-Identifier: MPL-2.0
//
// rust-nl — number lines from stdin (cat -n shape).
//
// Each non-empty line is prefixed with a 6-char right-aligned line
// number, a tab, then the line. Blank lines pass through unprefixed
// (matching GNU `nl` default body style "t": number text lines only).
// Lines longer than READ_BUF chunks have the prefix only on the
// chunk that ended in '\n' (or final flush) — the tail-fragment case
// is rare with 4 KiB chunks and not worth the bookkeeping for now.

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
    write_str(STDERR, b"[rust-nl] panic\n");
    unsafe {
        sys_exit(1);
    }
}

// Format a u64 right-aligned into a 6-char field followed by a tab.
fn write_lineno(n: u64) -> bool {
    let mut buf = [b' '; 7];
    let mut v = n;
    let mut i = 6;
    if v == 0 {
        i -= 1;
        buf[i] = b'0';
    } else {
        while v > 0 && i > 0 {
            i -= 1;
            buf[i] = b'0' + (v % 10) as u8;
            v /= 10;
        }
    }
    buf[6] = b'\t';
    write_all(STDOUT, &buf)
}

#[unsafe(no_mangle)]
pub extern "C" fn main(_argc: i32, _argv: *const *const u8, _envp: *const *const u8) -> i32 {
    let mut buf = [0u8; READ_BUF];
    let mut at_line_start = true;
    let mut line_starts_blank = true; // current line had no non-newline byte yet
    let mut line_no: u64 = 0;
    let mut had_error = false;

    loop {
        let n = unsafe {
            syscall3(sysn::READ, STDIN as u64, buf.as_mut_ptr() as u64, buf.len() as u64)
        };
        if n < 0 {
            had_error = true;
            break;
        }
        if n == 0 {
            break;
        }
        let chunk = &buf[..n as usize];
        let mut start = 0usize;
        for i in 0..chunk.len() {
            let c = chunk[i];
            if c == b'\n' {
                // Print this line: prefix-or-not, then segment incl. '\n'.
                let seg = &chunk[start..i + 1];
                if at_line_start && line_starts_blank {
                    // Empty line — no prefix, just the '\n'.
                    if !write_all(STDOUT, seg) { had_error = true; break; }
                } else {
                    if at_line_start {
                        // Whole line fit in this chunk and is non-empty.
                        line_no += 1;
                        if !write_lineno(line_no) { had_error = true; break; }
                    }
                    if !write_all(STDOUT, seg) { had_error = true; break; }
                }
                at_line_start = true;
                line_starts_blank = true;
                start = i + 1;
            } else if at_line_start && line_starts_blank {
                // First non-newline byte of a line — this line has content.
                line_starts_blank = false;
            }
        }
        if had_error { break; }
        // Tail fragment that didn't end in '\n' — emit prefix once for the
        // line, then the partial bytes; remember that we're no longer at
        // line start for the next chunk.
        if start < chunk.len() {
            if at_line_start {
                line_no += 1;
                if !write_lineno(line_no) { had_error = true; break; }
                at_line_start = false;
                line_starts_blank = false;
            }
            if !write_all(STDOUT, &chunk[start..]) { had_error = true; break; }
        }
    }

    if had_error { 1 } else { 0 }
}
