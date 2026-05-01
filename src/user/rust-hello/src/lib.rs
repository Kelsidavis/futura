// SPDX-License-Identifier: MPL-2.0
//
// rust-hello — first user-space Rust program for Futura OS.
//
// Proves the toolchain wiring: cargo builds librust_hello.a, the
// Makefile links it with the C crt0 + libfutura.a to produce a
// staged ELF binary. main() is exported with C linkage so the
// existing crt0_arm64.S entry point ("bl main") finds it.
//
// Once this builds and runs, follow-up apps (a Rust file picker,
// a Rust settings panel, etc.) can be added under src/user/rust-*/
// using the same pattern.

#![no_std]
#![forbid(unsafe_op_in_unsafe_fn)]

use core::panic::PanicInfo;

/// Linux/Futura syscall numbers we need. Match include/user/sysnums.h
/// (the aarch64 set).
const SYS_WRITE: u64 = 64;
const SYS_EXIT: u64 = 93;

/// Raw aarch64 SVC #0 syscall ABI: nr in x8, args in x0..x5, return in x0.
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

fn write_str(fd: i32, s: &[u8]) {
    // Best effort: ignore short writes for this demo. Real apps should
    // loop to handle EINTR / partial writes.
    unsafe {
        let _ = syscall3(SYS_WRITE, fd as u64, s.as_ptr() as u64, s.len() as u64);
    }
}

/// Panic handler — write the message header and exit. Without this,
/// rustc refuses to link a no_std crate.
#[panic_handler]
fn panic(_info: &PanicInfo) -> ! {
    write_str(2, b"[rust-hello] panic\n");
    unsafe {
        sys_exit(1);
    }
}

/// Entry point invoked by crt0_arm64.S. The C-style signature matches
/// what the assembly stub passes (argc in x0, argv in x1, envp in x2);
/// we ignore them for now.
#[unsafe(no_mangle)]
pub extern "C" fn main(_argc: i32, _argv: *const *const u8, _envp: *const *const u8) -> i32 {
    write_str(1, b"Hello from Rust user-space on Futura\n");
    0
}
