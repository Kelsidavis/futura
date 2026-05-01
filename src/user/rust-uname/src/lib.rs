// SPDX-License-Identifier: MPL-2.0
//
// rust-uname — second user-space Rust program for Futura OS.
//
// Reads kernel/system identification via the uname(2) syscall and prints
// the canonical "uname -a" formatted line. Exercises a richer slice of
// the syscall ABI than rust-hello (uname returns a struct via pointer)
// while staying small enough to keep the build fast.
//
// Output format:  "<sysname> <nodename> <release> <version> <machine>"
//
// The crt0_arm64.S / crt0.S entry stub calls main(), so we expose
// #[unsafe(no_mangle)] pub extern "C" fn main(...) the same way
// rust-hello does.

#![no_std]
#![forbid(unsafe_op_in_unsafe_fn)]

use core::panic::PanicInfo;

/// Linux/Futura syscall numbers. Match include/user/sysnums.h.
#[cfg(target_arch = "aarch64")]
const SYS_WRITE: u64 = 64;
#[cfg(target_arch = "aarch64")]
const SYS_EXIT: u64 = 93;
#[cfg(target_arch = "aarch64")]
const SYS_UNAME: u64 = 160;

#[cfg(target_arch = "x86_64")]
const SYS_WRITE: u64 = 1;
#[cfg(target_arch = "x86_64")]
const SYS_EXIT: u64 = 60;
#[cfg(target_arch = "x86_64")]
const SYS_UNAME: u64 = 63;

/// Linux struct utsname — six 65-byte fields (sysname, nodename, release,
/// version, machine, domainname). Total 390 bytes.
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
            in("x8") SYS_EXIT,
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
            in("rax") SYS_EXIT,
            in("rdi") code,
            options(nostack, noreturn),
        );
    }
}

fn write_str(fd: i32, s: &[u8]) {
    // Best effort — short writes ignored in this small utility.
    unsafe {
        let _ = syscall3(SYS_WRITE, fd as u64, s.as_ptr() as u64, s.len() as u64);
    }
}

/// Length of a NUL-terminated field, capped at the field size.
fn field_len(field: &[u8]) -> usize {
    let mut n = 0;
    while n < field.len() && field[n] != 0 {
        n += 1;
    }
    n
}

#[panic_handler]
fn panic(_info: &PanicInfo) -> ! {
    write_str(2, b"[rust-uname] panic\n");
    unsafe {
        sys_exit(1);
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn main(_argc: i32, _argv: *const *const u8, _envp: *const *const u8) -> i32 {
    // Zero-initialize so any field the kernel doesn't write stays NUL.
    let mut uts = Utsname {
        sysname: [0; UTS_LEN],
        nodename: [0; UTS_LEN],
        release: [0; UTS_LEN],
        version: [0; UTS_LEN],
        machine: [0; UTS_LEN],
        domainname: [0; UTS_LEN],
    };

    let rc = unsafe { syscall1(SYS_UNAME, &mut uts as *mut Utsname as u64) };
    if rc < 0 {
        write_str(2, b"rust-uname: uname() failed\n");
        return 1;
    }

    // Print "<sysname> <nodename> <release> <version> <machine>\n" — same
    // shape as `uname -a` (minus the domain name, since most distros also
    // omit it from the default output).
    let fields: [&[u8]; 5] = [
        &uts.sysname[..field_len(&uts.sysname)],
        &uts.nodename[..field_len(&uts.nodename)],
        &uts.release[..field_len(&uts.release)],
        &uts.version[..field_len(&uts.version)],
        &uts.machine[..field_len(&uts.machine)],
    ];
    for (i, f) in fields.iter().enumerate() {
        if i > 0 {
            write_str(1, b" ");
        }
        if f.is_empty() {
            write_str(1, b"-");
        } else {
            write_str(1, f);
        }
    }
    write_str(1, b"\n");
    0
}
