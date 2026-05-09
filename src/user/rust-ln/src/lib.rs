// SPDX-License-Identifier: MPL-2.0
//
// rust-ln — create a symbolic link.
//
//   rust-ln -s <target> <linkpath>
//
// Hard links aren't supported on FuturaFS yet, so we hardwire -s.
// Per-arch syscall: aarch64 uses symlinkat (3-arg, target/dirfd/link),
// x86_64 uses the deprecated symlink (2-arg) since sysnums.h doesn't
// export symlinkat there. Same shape as rust-mv's per-arch dispatch.

#![no_std]
#![forbid(unsafe_op_in_unsafe_fn)]

use core::panic::PanicInfo;

#[cfg(target_arch = "aarch64")]
mod sysn {
    pub const WRITE: u64 = 64;
    pub const EXIT: u64 = 93;
    pub const SYMLINKAT: u64 = 36;
}

#[cfg(target_arch = "x86_64")]
mod sysn {
    pub const WRITE: u64 = 1;
    pub const EXIT: u64 = 60;
    pub const SYMLINK: u64 = 88;
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
    write_str(STDERR, b"[rust-ln] panic\n");
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

#[unsafe(no_mangle)]
pub extern "C" fn main(argc: i32, argv: *const *const u8, _envp: *const *const u8) -> i32 {
    if argc < 4 {
        write_str(STDERR, b"usage: rust-ln -s <target> <linkpath>\n");
        return 1;
    }
    let flag = unsafe { *argv.add(1) };
    let target = unsafe { *argv.add(2) };
    let linkpath = unsafe { *argv.add(3) };
    if flag.is_null() || (flag as usize) < 0x10000 {
        write_str(STDERR, b"rust-ln: missing -s flag\n");
        return 1;
    }
    if !cstr_eq(flag, b"-s") {
        write_str(STDERR, b"rust-ln: only -s (symbolic) is supported\n");
        return 1;
    }
    if target.is_null() || (target as usize) < 0x10000 ||
       linkpath.is_null() || (linkpath as usize) < 0x10000 {
        write_str(STDERR, b"rust-ln: invalid arguments\n");
        return 1;
    }

    #[cfg(target_arch = "aarch64")]
    let r = unsafe {
        syscall3(
            sysn::SYMLINKAT,
            target as u64,
            AT_FDCWD as u64,
            linkpath as u64,
        )
    };
    #[cfg(target_arch = "x86_64")]
    let r = unsafe { syscall2(sysn::SYMLINK, target as u64, linkpath as u64) };

    if r < 0 {
        write_str(STDERR, b"rust-ln: symlink failed\n");
        return 1;
    }
    0
}
