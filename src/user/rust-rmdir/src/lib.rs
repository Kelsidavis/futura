// SPDX-License-Identifier: MPL-2.0
//
// rust-rmdir — remove an EMPTY directory (POSIX rmdir(1)).
//
//   rust-rmdir <dir> [<dir>...]
//
// Per-arch syscall:
//   aarch64 -> unlinkat(AT_FDCWD, dir, AT_REMOVEDIR=0x200) (SYS=35)
//   x86_64  -> rmdir(dir)                                  (SYS=84)
//
// Same per-arch dispatch shape as rust-rm — x86_64's sysnums.h
// only exports the deprecated 1-arg rmdir, while aarch64's generic
// set drops both rmdir and unlink and routes through unlinkat with
// the AT_REMOVEDIR flag.
//
// Will not remove a non-empty directory; the kernel returns
// -ENOTEMPTY and we surface it as "rmdir failed".

#![no_std]
#![forbid(unsafe_op_in_unsafe_fn)]

use core::panic::PanicInfo;

#[cfg(target_arch = "aarch64")]
mod sysn {
    pub const WRITE: u64 = 64;
    pub const EXIT: u64 = 93;
    pub const UNLINKAT: u64 = 35;
}

#[cfg(target_arch = "x86_64")]
mod sysn {
    pub const WRITE: u64 = 1;
    pub const EXIT: u64 = 60;
    pub const RMDIR: u64 = 84;
}

#[cfg(target_arch = "aarch64")]
const AT_FDCWD: i64 = -100;
#[cfg(target_arch = "aarch64")]
const AT_REMOVEDIR: u64 = 0x200;
const STDERR: i32 = 2;

// aarch64 path uses syscall3 (unlinkat) only — no syscall1 wrapper needed.

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
    write_str(STDERR, b"[rust-rmdir] panic\n");
    unsafe {
        sys_exit(1);
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn main(argc: i32, argv: *const *const u8, _envp: *const *const u8) -> i32 {
    if argc < 2 {
        write_str(STDERR, b"usage: rust-rmdir <dir> [<dir>...]\n");
        return 1;
    }
    let mut had_error = false;
    for ai in 1..argc {
        let p = unsafe { *argv.add(ai as usize) };
        if p.is_null() || (p as usize) < 0x10000 {
            had_error = true;
            continue;
        }
        #[cfg(target_arch = "aarch64")]
        let r = unsafe {
            syscall3(sysn::UNLINKAT, AT_FDCWD as u64, p as u64, AT_REMOVEDIR)
        };
        #[cfg(target_arch = "x86_64")]
        let r = unsafe { syscall1(sysn::RMDIR, p as u64) };
        if r < 0 {
            write_str(STDERR, b"rust-rmdir: cannot remove '");
            let mut n = 0usize;
            unsafe { while *p.add(n) != 0 { n += 1; } }
            unsafe {
                let _ = syscall3(sysn::WRITE, STDERR as u64, p as u64, n as u64);
            }
            write_str(STDERR, b"'\n");
            had_error = true;
        }
    }
    if had_error { 1 } else { 0 }
}
