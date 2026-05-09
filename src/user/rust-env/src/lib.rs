// SPDX-License-Identifier: MPL-2.0
//
// rust-env — twelfth user-space Rust program for Futura OS.
//
// Walks the envp NUL-terminated pointer array passed on the stack
// and prints each entry on its own line. Same default behaviour as
// /usr/bin/env with no args.

#![no_std]
#![forbid(unsafe_op_in_unsafe_fn)]

use core::panic::PanicInfo;

#[cfg(target_arch = "aarch64")]
mod sysn {
    pub const WRITE: u64 = 64;
    pub const EXIT: u64 = 93;
}

#[cfg(target_arch = "x86_64")]
mod sysn {
    pub const WRITE: u64 = 1;
    pub const EXIT: u64 = 60;
}

const STDOUT: i32 = 1;
const STDERR: i32 = 2;

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

fn write_all(fd: i32, mut s: &[u8]) {
    while !s.is_empty() {
        let n = unsafe { syscall3(sysn::WRITE, fd as u64, s.as_ptr() as u64, s.len() as u64) };
        if n <= 0 {
            return;
        }
        s = &s[n as usize..];
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

#[panic_handler]
fn panic(_info: &PanicInfo) -> ! {
    write_all(STDERR, b"[rust-env] panic\n");
    unsafe {
        sys_exit(1);
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn main(_argc: i32, _argv: *const *const u8, envp: *const *const u8) -> i32 {
    if envp.is_null() {
        return 0;
    }
    let mut i = 0usize;
    loop {
        let e = unsafe { *envp.add(i) };
        if e.is_null() {
            break;
        }
        // Defensive: a corrupt envp could hold a low-half non-pointer.
        // Refuse to dereference it before its first byte fault.
        if (e as usize) < 0x10000 {
            break;
        }
        let n = cstr_len(e);
        let bytes = unsafe { core::slice::from_raw_parts(e, n) };
        write_all(STDOUT, bytes);
        write_all(STDOUT, b"\n");
        i += 1;
    }
    0
}
