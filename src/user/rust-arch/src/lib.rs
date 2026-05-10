// SPDX-License-Identifier: MPL-2.0
//
// rust-arch — print the machine architecture (same as `uname -m`).
//
//   rust-arch    ->  aarch64
//
// Calls uname(2) and prints the machine field. Equivalent to
// `uname -m` but exists because GNU coreutils ships /usr/bin/arch
// and a lot of build scripts (autoconf, configure, kernel buildsys)
// reach for it directly. Bare arch is also slightly more discoverable
// than learning the -m flag.

#![no_std]
#![forbid(unsafe_op_in_unsafe_fn)]

use core::panic::PanicInfo;

#[cfg(target_arch = "aarch64")]
mod sysn {
    pub const WRITE: u64 = 64;
    pub const EXIT: u64 = 93;
    pub const UNAME: u64 = 160;
}

#[cfg(target_arch = "x86_64")]
mod sysn {
    pub const WRITE: u64 = 1;
    pub const EXIT: u64 = 60;
    pub const UNAME: u64 = 63;
}

const STDOUT: i32 = 1;
const STDERR: i32 = 2;
const UTS_LEN: usize = 65;

#[repr(C)]
struct Utsname {
    sysname: [u8; UTS_LEN],
    nodename: [u8; UTS_LEN],
    release: [u8; UTS_LEN],
    version: [u8; UTS_LEN],
    machine: [u8; UTS_LEN],
    domainname: [u8; UTS_LEN],
}

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
    write_str(STDERR, b"[rust-arch] panic\n");
    unsafe {
        sys_exit(1);
    }
}

fn field_len(field: &[u8]) -> usize {
    let mut n = 0;
    while n < field.len() && field[n] != 0 {
        n += 1;
    }
    n
}

#[unsafe(no_mangle)]
pub extern "C" fn main(argc: i32, argv: *const *const u8, _envp: *const *const u8) -> i32 {
    if argc == 2 {
        let p = unsafe { *argv.add(1) };
        if !p.is_null() && (p as usize) >= 0x10000 {
            let want = b"--help";
            let mut n = 0; unsafe { while *p.add(n) != 0 { n += 1; } }
            if n == want.len() {
                let mut ok = true;
                for i in 0..want.len() {
                    if unsafe { *p.add(i) } != want[i] { ok = false; break; }
                }
                if ok {
                    let help: &[u8] = b"\
Usage: rust-arch
Print the machine architecture (uname -m).

  --help    show this help and exit
\0";
                    let len = help.len() - 1;
                    unsafe { let _ = syscall3(sysn::WRITE, STDOUT as u64,
                                              help.as_ptr() as u64, len as u64); }
                    return 0;
                }
            }
        }
    }
    let mut uts = Utsname {
        sysname: [0; UTS_LEN],
        nodename: [0; UTS_LEN],
        release: [0; UTS_LEN],
        version: [0; UTS_LEN],
        machine: [0; UTS_LEN],
        domainname: [0; UTS_LEN],
    };
    let r = unsafe { syscall1(sysn::UNAME, &mut uts as *mut Utsname as u64) };
    if r < 0 {
        write_str(STDERR, b"rust-arch: uname() failed\n");
        return 1;
    }
    let n = field_len(&uts.machine);
    write_str(STDOUT, &uts.machine[..n]);
    write_str(STDOUT, b"\n");
    0
}
