// SPDX-License-Identifier: MPL-2.0
//
// rust-whoami — print the effective user name.
//
// Reads $USER, falling back to $LOGNAME, and finally hard-codes
// "root" since Futura currently runs every task as uid 0. Prints
// the value followed by '\n'.
//
// Doesn't call getuid(2) / getpwuid(3) — Futura's user database is
// /etc/passwd which is fine for the eventual real getpwuid wiring,
// but the env fallback already matches what /etc/profile exports
// and what GNU whoami does on a normal login session.

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

fn write_str(fd: i32, s: &[u8]) {
    unsafe {
        let _ = syscall3(sysn::WRITE, fd as u64, s.as_ptr() as u64, s.len() as u64);
    }
}

#[panic_handler]
fn panic(_info: &PanicInfo) -> ! {
    write_str(STDERR, b"[rust-whoami] panic\n");
    unsafe {
        sys_exit(1);
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

fn env_lookup(envp: *const *const u8, name: &[u8]) -> Option<*const u8> {
    if envp.is_null() {
        return None;
    }
    let mut i = 0usize;
    loop {
        let entry = unsafe { *envp.add(i) };
        if entry.is_null() {
            return None;
        }
        if (entry as usize) < 0x10000 {
            return None;
        }
        let mut ok = true;
        for j in 0..name.len() {
            if unsafe { *entry.add(j) } != name[j] {
                ok = false;
                break;
            }
        }
        if ok && unsafe { *entry.add(name.len()) } == b'=' {
            return Some(unsafe { entry.add(name.len() + 1) });
        }
        i += 1;
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn main(_argc: i32, _argv: *const *const u8, envp: *const *const u8) -> i32 {
    // Try $USER, then $LOGNAME, then "root".
    let v = env_lookup(envp, b"USER").or_else(|| env_lookup(envp, b"LOGNAME"));
    match v {
        Some(p) => {
            let n = cstr_len(p);
            unsafe {
                let _ = syscall3(sysn::WRITE, STDOUT as u64, p as u64, n as u64);
            }
            write_str(STDOUT, b"\n");
        }
        None => {
            write_str(STDOUT, b"root\n");
        }
    }
    0
}
