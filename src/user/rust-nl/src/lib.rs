// SPDX-License-Identifier: MPL-2.0
//
// rust-nl — number lines (cat -n shape).
//
//   rust-nl                      number stdin
//   rust-nl FILE [FILE…]         number each file in turn
//   rust-nl ... -                number stdin (in any position)
//
// Each non-empty line is prefixed with a 6-char right-aligned line
// number, a tab, then the line. Blank lines pass through unprefixed
// (matching GNU `nl` default body style "t": number text lines only).
// Multiple files share a single running line counter — same as
// `cat | nl`, which is the conventional behaviour. Lines longer than
// READ_BUF chunks have the prefix only on the chunk that ended in
// '\n' (or final flush) — the tail-fragment case is rare with 4 KiB
// chunks and not worth the bookkeeping for now.

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

struct NlState {
    at_line_start: bool,
    line_starts_blank: bool,
    line_no: u64,
}

fn nl_fd(fd: i32, st: &mut NlState) -> bool {
    let mut buf = [0u8; READ_BUF];
    let mut had_error = false;

    loop {
        let n = unsafe {
            syscall3(sysn::READ, fd as u64, buf.as_mut_ptr() as u64, buf.len() as u64)
        };
        if n < 0 { had_error = true; break; }
        if n == 0 { break; }
        let chunk = &buf[..n as usize];
        let mut start = 0usize;
        for i in 0..chunk.len() {
            let c = chunk[i];
            if c == b'\n' {
                let seg = &chunk[start..i + 1];
                if st.at_line_start && st.line_starts_blank {
                    if !write_all(STDOUT, seg) { had_error = true; break; }
                } else {
                    if st.at_line_start {
                        st.line_no += 1;
                        if !write_lineno(st.line_no) { had_error = true; break; }
                    }
                    if !write_all(STDOUT, seg) { had_error = true; break; }
                }
                st.at_line_start = true;
                st.line_starts_blank = true;
                start = i + 1;
            } else if st.at_line_start && st.line_starts_blank {
                st.line_starts_blank = false;
            }
        }
        if had_error { break; }
        if start < chunk.len() {
            if st.at_line_start {
                st.line_no += 1;
                if !write_lineno(st.line_no) { had_error = true; break; }
                st.at_line_start = false;
                st.line_starts_blank = false;
            }
            if !write_all(STDOUT, &chunk[start..]) { had_error = true; break; }
        }
    }
    !had_error
}

#[unsafe(no_mangle)]
pub extern "C" fn main(argc: i32, argv: *const *const u8, _envp: *const *const u8) -> i32 {
    let mut st = NlState {
        at_line_start: true,
        line_starts_blank: true,
        line_no: 0,
    };
    let mut had_error = false;

    // Top-level --help short-circuits before any input processing.
    if argc >= 2 {
        let first = unsafe { *argv.add(1) };
        if !first.is_null() && (first as usize) >= 0x10000 {
            let want = b"--help";
            let mut ok = true;
            for i in 0..want.len() {
                if unsafe { *first.add(i) } != want[i] { ok = false; break; }
            }
            if ok && unsafe { *first.add(want.len()) } == 0 {
                let help: &[u8] = b"\
Usage: rust-nl [FILE]...
Number text lines (cat -n shape). Blank lines pass through with no
prefix; non-blank lines get a 6-char right-aligned line number plus
a tab. Multiple FILEs share a single running counter.

  --help    show this help and exit

A '-' in the FILE list means standard input.
\0";
                let len = help.len() - 1;
                unsafe { let _ = syscall3(sysn::WRITE, STDOUT as u64,
                                          help.as_ptr() as u64, len as u64); }
                return 0;
            }
        }
    }
    if argc < 2 {
        if !nl_fd(STDIN, &mut st) { had_error = true; }
    } else {
        for ai in 1..argc {
            let p = unsafe { *argv.add(ai as usize) };
            if p.is_null() || (p as usize) < 0x10000 {
                had_error = true;
                continue;
            }
            let mut nlen = 0usize;
            unsafe { while *p.add(nlen) != 0 { nlen += 1; } }
            let is_dash = nlen == 1 && unsafe { *p } == b'-';
            if is_dash {
                if !nl_fd(STDIN, &mut st) { had_error = true; }
                continue;
            }
            let fd = unsafe {
                syscall4(sysn::OPENAT, AT_FDCWD as u64, p as u64, O_RDONLY, 0) as i32
            };
            if fd < 0 {
                write_str(STDERR, b"rust-nl: cannot open '");
                unsafe { let _ = syscall3(sysn::WRITE, STDERR as u64, p as u64, nlen as u64); }
                write_str(STDERR, b"'\n");
                had_error = true;
                continue;
            }
            if !nl_fd(fd, &mut st) { had_error = true; }
            unsafe { let _ = syscall1(sysn::CLOSE, fd as u64); }
        }
    }

    if had_error { 1 } else { 0 }
}
