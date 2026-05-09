// SPDX-License-Identifier: MPL-2.0
//
// rust-truncate — set a file's size via truncate(2).
//
//   rust-truncate -s <bytes> <file>
//
// If <bytes> is greater than the current size, the file is extended
// with sparse zeros (the kernel reserves no backing for the gap on
// FuturaFS' tmpfs). If smaller, the tail is dropped.
//
// No -c (no-create) yet — truncate(2) creates the file if it doesn't
// exist on Linux generic, which matches the GNU default.

#![no_std]
#![forbid(unsafe_op_in_unsafe_fn)]

use core::panic::PanicInfo;

#[cfg(target_arch = "aarch64")]
mod sysn {
    pub const WRITE: u64 = 64;
    pub const EXIT: u64 = 93;
    pub const TRUNCATE: u64 = 45;
}

#[cfg(target_arch = "x86_64")]
mod sysn {
    pub const WRITE: u64 = 1;
    pub const EXIT: u64 = 60;
    pub const TRUNCATE: u64 = 76;
}

const STDERR: i32 = 2;

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
    write_str(STDERR, b"[rust-truncate] panic\n");
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

fn parse_u64(p: *const u8) -> Option<u64> {
    let mut n = 0usize;
    unsafe { while *p.add(n) != 0 { n += 1; } }
    if n == 0 || n > 20 {
        return None;
    }
    let s = unsafe { core::slice::from_raw_parts(p, n) };
    let mut v: u64 = 0;
    for &c in s {
        if !(b'0'..=b'9').contains(&c) {
            return None;
        }
        v = match v.checked_mul(10).and_then(|x| x.checked_add((c - b'0') as u64)) {
            Some(x) => x,
            None => return None,
        };
    }
    Some(v)
}

#[unsafe(no_mangle)]
pub extern "C" fn main(argc: i32, argv: *const *const u8, _envp: *const *const u8) -> i32 {
    if argc < 4 {
        write_str(STDERR, b"usage: rust-truncate -s <bytes> <file>\n");
        return 1;
    }
    let flag = unsafe { *argv.add(1) };
    if flag.is_null() || (flag as usize) < 0x10000 || !cstr_eq(flag, b"-s") {
        write_str(STDERR, b"rust-truncate: missing -s flag\n");
        return 1;
    }
    let size_p = unsafe { *argv.add(2) };
    let path = unsafe { *argv.add(3) };
    if size_p.is_null() || (size_p as usize) < 0x10000 ||
       path.is_null() || (path as usize) < 0x10000 {
        write_str(STDERR, b"rust-truncate: invalid arguments\n");
        return 1;
    }
    let size = match parse_u64(size_p) {
        Some(v) => v,
        None => {
            write_str(STDERR, b"rust-truncate: invalid size\n");
            return 1;
        }
    };

    let r = unsafe { syscall2(sysn::TRUNCATE, path as u64, size) };
    if r < 0 {
        write_str(STDERR, b"rust-truncate: truncate failed\n");
        return 1;
    }
    0
}
