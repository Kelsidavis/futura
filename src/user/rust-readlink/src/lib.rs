// SPDX-License-Identifier: MPL-2.0
//
// rust-readlink — print a symlink's target.
//
//   rust-readlink <link> [<link>...]  -> each link's target, or exit 1
//
// Wraps readlinkat(AT_FDCWD, link, buf, len). Truncates at the
// 1023-byte buffer boundary; symbolic-link targets longer than that
// produce a "(truncated)" suffix on stderr but still exit 0 with the
// truncated target on stdout, mirroring GNU readlink's quiet mode.
// readlinkat does NOT NUL-terminate; we use the returned length.
//
// Multiple args: each is resolved in order; exit status is 1 if any
// argument failed (target unreadable / not a symlink).

#![no_std]
#![forbid(unsafe_op_in_unsafe_fn)]

use core::panic::PanicInfo;

#[cfg(target_arch = "aarch64")]
mod sysn {
    pub const WRITE: u64 = 64;
    pub const EXIT: u64 = 93;
    pub const READLINKAT: u64 = 78;
}

#[cfg(target_arch = "x86_64")]
mod sysn {
    pub const WRITE: u64 = 1;
    pub const EXIT: u64 = 60;
    // x86_64 sysnums.h has SYS_readlink = 89 (3-arg). We use that
    // directly because there's no SYS_readlinkat exported there.
    pub const READLINK: u64 = 89;
}

const AT_FDCWD: i64 = -100;
const STDOUT: i32 = 1;
const STDERR: i32 = 2;
const BUF: usize = 1024;

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
    write_str(STDERR, b"[rust-readlink] panic\n");
    unsafe {
        sys_exit(1);
    }
}

// Resolve one link, return true on success.
fn read_one(p: *const u8) -> bool {
    let mut buf = [0u8; BUF];

    #[cfg(target_arch = "aarch64")]
    let n = unsafe {
        syscall4(
            sysn::READLINKAT,
            AT_FDCWD as u64,
            p as u64,
            buf.as_mut_ptr() as u64,
            (buf.len() - 1) as u64,
        )
    };

    #[cfg(target_arch = "x86_64")]
    let n = unsafe {
        syscall3(
            sysn::READLINK,
            p as u64,
            buf.as_mut_ptr() as u64,
            (buf.len() - 1) as u64,
        )
    };

    if n <= 0 {
        write_str(STDERR, b"rust-readlink: not a symbolic link or unreadable\n");
        return false;
    }
    let n = n as usize;
    write_str(STDOUT, &buf[..n]);
    write_str(STDOUT, b"\n");

    if n >= buf.len() - 1 {
        write_str(STDERR, b"rust-readlink: target truncated to fit buffer\n");
    }
    true
}

#[unsafe(no_mangle)]
pub extern "C" fn main(argc: i32, argv: *const *const u8, _envp: *const *const u8) -> i32 {
    if argc == 2 {
        let first = unsafe { *argv.add(1) };
        if !first.is_null() && (first as usize) >= 0x10000 {
            let want = b"--help";
            let mut n = 0; unsafe { while *first.add(n) != 0 { n += 1; } }
            if n == want.len() {
                let mut ok = true;
                for i in 0..want.len() {
                    if unsafe { *first.add(i) } != want[i] { ok = false; break; }
                }
                if ok {
                    let help: &[u8] = b"\
Usage: rust-readlink LINK [LINK...]
Print each LINK's symbolic-link target.

  --help    show this help and exit
\0";
                    let len = help.len() - 1;
                    unsafe { let _ = syscall3(sysn::WRITE, 1, help.as_ptr() as u64, len as u64); }
                    return 0;
                }
            }
        }
    }
    if argc < 2 {
        write_str(STDERR, b"usage: rust-readlink <link> [<link>...]\n");
        return 1;
    }
    let mut had_error = false;
    for ai in 1..argc {
        let p = unsafe { *argv.add(ai as usize) };
        if p.is_null() || (p as usize) < 0x10000 {
            write_str(STDERR, b"rust-readlink: invalid argument\n");
            had_error = true;
            continue;
        }
        if !read_one(p) {
            had_error = true;
        }
    }
    if had_error { 1 } else { 0 }
}
