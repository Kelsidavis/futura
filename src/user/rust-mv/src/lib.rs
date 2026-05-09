// SPDX-License-Identifier: MPL-2.0
//
// rust-mv — single-file rename via renameat(2).
//
//   rust-mv <src> <dst>
//
// One renameat call. Cross-filesystem moves are not handled (the
// kernel returns EXDEV and we surface it as an error). For same-FS
// moves on FuturaFS this is a metadata operation, not a copy + delete.

#![no_std]
#![forbid(unsafe_op_in_unsafe_fn)]

use core::panic::PanicInfo;

#[cfg(target_arch = "aarch64")]
mod sysn {
    pub const WRITE: u64 = 64;
    pub const EXIT: u64 = 93;
    pub const RENAMEAT: u64 = 38;
}

#[cfg(target_arch = "x86_64")]
mod sysn {
    pub const WRITE: u64 = 1;
    pub const EXIT: u64 = 60;
    // x86_64 sysnums.h only exports SYS_rename = 82 (the deprecated
    // 2-arg form). aarch64 uses renameat = 38. Pick at compile time.
    pub const RENAME: u64 = 82;
}

#[cfg(target_arch = "aarch64")]
const AT_FDCWD: i64 = -100;
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
    write_str(STDERR, b"[rust-mv] panic\n");
    unsafe {
        sys_exit(1);
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn main(argc: i32, argv: *const *const u8, _envp: *const *const u8) -> i32 {
    if argc < 3 {
        write_str(STDERR, b"usage: rust-mv <src> <dst>\n");
        return 1;
    }
    let src = unsafe { *argv.add(1) };
    let dst = unsafe { *argv.add(2) };
    if src.is_null() || (src as usize) < 0x10000 || dst.is_null() || (dst as usize) < 0x10000 {
        write_str(STDERR, b"rust-mv: invalid arguments\n");
        return 1;
    }

    #[cfg(target_arch = "aarch64")]
    let r = unsafe {
        syscall4(
            sysn::RENAMEAT,
            AT_FDCWD as u64,
            src as u64,
            AT_FDCWD as u64,
            dst as u64,
        )
    };
    #[cfg(target_arch = "x86_64")]
    let r = unsafe { syscall2(sysn::RENAME, src as u64, dst as u64) };
    if r < 0 {
        write_str(STDERR, b"rust-mv: renameat failed\n");
        return 1;
    }
    0
}
