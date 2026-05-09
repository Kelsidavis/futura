// SPDX-License-Identifier: MPL-2.0
//
// rust-fold — wrap each input line at COLS columns.
//
//   rust-fold              wrap at 80 columns
//   rust-fold -w <cols>    wrap at <cols> columns
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
const DEFAULT_COLS: u32 = 80;

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

#[unsafe(no_mangle)]
pub extern "C" fn main(argc: i32, argv: *const *const u8, _envp: *const *const u8) -> i32 {
    let mut cols: u32 = DEFAULT_COLS;
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
        } else {
            // Future iteration: file arguments. For now stdin only.
            write_str(STDERR, b"rust-fold: unexpected argument\n");
            return 2;
        }
    }

    let mut buf = [0u8; READ_BUF];
    let mut col: u32 = 0;
    loop {
        let n = unsafe {
            syscall3(sysn::READ, STDIN as u64, buf.as_mut_ptr() as u64, buf.len() as u64)
        };
        if n < 0 {
            return 1;
        }
        if n == 0 {
            break;
        }
        let chunk = &buf[..n as usize];
        // Walk byte-by-byte so we can inject '\n' at column boundaries.
        // Defer flushing so we still write large stretches in one syscall.
        let mut start = 0usize;
        for i in 0..chunk.len() {
            let c = chunk[i];
            if c == b'\n' {
                // Emit through and reset column.
                if !write_all(STDOUT, &chunk[start..=i]) { return 1; }
                col = 0;
                start = i + 1;
            } else {
                if col == cols {
                    // Force-wrap before this byte.
                    if !write_all(STDOUT, &chunk[start..i]) { return 1; }
                    if !write_all(STDOUT, b"\n") { return 1; }
                    col = 0;
                    start = i;
                }
                col += 1;
            }
        }
        if start < chunk.len() {
            if !write_all(STDOUT, &chunk[start..]) { return 1; }
        }
    }
    0
}
