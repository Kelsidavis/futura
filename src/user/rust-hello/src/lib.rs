// SPDX-License-Identifier: MPL-2.0
//
// rust-hello — first user-space Rust program for Futura OS.
//
// Proves the toolchain wiring: cargo builds librust_hello.a, the
// Makefile links it with the C crt0 + libfutura.a to produce a
// staged ELF binary. main() is exported with C linkage so the
// existing crt0 entry point ("bl main" / "call main") finds it.

#![no_std]
#![forbid(unsafe_op_in_unsafe_fn)]

use core::panic::PanicInfo;

/// Linux/Futura syscall numbers. Match include/user/sysnums.h.
#[cfg(target_arch = "aarch64")]
const SYS_WRITE: u64 = 64;
#[cfg(target_arch = "aarch64")]
const SYS_EXIT: u64 = 93;

#[cfg(target_arch = "x86_64")]
const SYS_WRITE: u64 = 1;
#[cfg(target_arch = "x86_64")]
const SYS_EXIT: u64 = 60;

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
            in("x8") SYS_EXIT,
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
            in("rax") SYS_EXIT,
            in("rdi") code,
            options(nostack, noreturn),
        );
    }
}

fn write_str(fd: i32, s: &[u8]) {
    unsafe {
        let _ = syscall3(SYS_WRITE, fd as u64, s.as_ptr() as u64, s.len() as u64);
    }
}

#[panic_handler]
fn panic(_info: &PanicInfo) -> ! {
    write_str(2, b"[rust-hello] panic\n");
    unsafe {
        sys_exit(1);
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn main(_argc: i32, _argv: *const *const u8, _envp: *const *const u8) -> i32 {
    write_str(1, b"Hello from Rust user-space on Futura\n");
    0
}
