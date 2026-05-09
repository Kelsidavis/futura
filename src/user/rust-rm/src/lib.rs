// SPDX-License-Identifier: MPL-2.0
//
// rust-rm — seventh user-space Rust program for Futura OS.
//
// Removes the named files via unlinkat(AT_FDCWD, path, 0). With -f
// (force), missing-file errors are silently swallowed and the exit
// code stays 0 unless a different error occurs. Refuses to act on a
// directory without -r — and -r itself is intentionally not supported
// in this iteration since it would need a recursive walk and a stat
// implementation; we'd rather refuse than truncate a tree halfway.

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
    pub const UNLINK: u64 = 87;
}

const AT_FDCWD: i64 = -100;
const STDERR: i32 = 2;
const ENOENT: i64 = -2;

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
unsafe fn sys_unlink(path: *const u8) -> i64 {
    unsafe { syscall3(sysn::UNLINKAT, AT_FDCWD as u64, path as u64, 0) }
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
unsafe fn sys_unlink(path: *const u8) -> i64 {
    unsafe { syscall1(sysn::UNLINK, path as u64) }
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

fn cstr_len(p: *const u8) -> usize {
    let mut n = 0;
    unsafe {
        while *p.add(n) != 0 {
            n += 1;
        }
    }
    n
}

fn argv_get(argc: i32, argv: *const *const u8, idx: usize) -> Option<*const u8> {
    if (idx as i32) >= argc {
        return None;
    }
    unsafe {
        let p = *argv.add(idx);
        if p.is_null() { None } else { Some(p) }
    }
}

fn arg_is(p: *const u8, want: &[u8]) -> bool {
    let n = cstr_len(p);
    if n != want.len() {
        return false;
    }
    for i in 0..n {
        if unsafe { *p.add(i) } != want[i] {
            return false;
        }
    }
    true
}

#[panic_handler]
fn panic(_info: &PanicInfo) -> ! {
    write_str(STDERR, b"[rust-rm] panic\n");
    unsafe {
        sys_exit(1);
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn main(argc: i32, argv: *const *const u8, _envp: *const *const u8) -> i32 {
    let mut idx: usize = 1;
    let mut force = false;

    // -f to swallow ENOENT silently. -r/-rf are explicitly refused so
    // we don't half-delete a tree without a stat-aware walker.
    while let Some(p) = argv_get(argc, argv, idx) {
        if arg_is(p, b"-f") {
            force = true;
            idx += 1;
        } else if arg_is(p, b"-r")
            || arg_is(p, b"-R")
            || arg_is(p, b"-rf")
            || arg_is(p, b"-fr")
        {
            write_str(
                STDERR,
                b"rust-rm: recursive removal not supported - use the C 'rm -r'\n",
            );
            return 1;
        } else if arg_is(p, b"--") {
            idx += 1;
            break;
        } else {
            break;
        }
    }

    if (idx as i32) >= argc {
        write_str(STDERR, b"usage: rust-rm [-f] FILE [FILE...]\n");
        return 1;
    }

    let mut had_error = false;
    while let Some(p) = argv_get(argc, argv, idx) {
        let n = cstr_len(p);
        if n == 0 {
            if !force {
                write_str(STDERR, b"rust-rm: empty filename\n");
                had_error = true;
            }
            idx += 1;
            continue;
        }
        let rc = unsafe { sys_unlink(p) };
        if rc < 0 {
            if force && rc == ENOENT {
                // Silent swallow.
            } else {
                write_str(STDERR, b"rust-rm: cannot remove '");
                unsafe {
                    let _ = syscall3(sysn::WRITE, STDERR as u64, p as u64, n as u64);
                }
                write_str(STDERR, b"'\n");
                had_error = true;
            }
        }
        idx += 1;
    }

    if had_error { 1 } else { 0 }
}
