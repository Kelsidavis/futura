// SPDX-License-Identifier: MPL-2.0
//
// rust-pwd — third user-space Rust program for Futura OS.
//
// Reads the current working directory via the getcwd(2) syscall and
// prints it on stdout, terminated with a newline. Mirrors the syscall
// pattern established by rust-uname so the toolchain proof keeps
// growing one small program at a time.

#![no_std]
#![forbid(unsafe_op_in_unsafe_fn)]

use core::panic::PanicInfo;

#[cfg(target_arch = "aarch64")]
const SYS_WRITE: u64 = 64;
#[cfg(target_arch = "aarch64")]
const SYS_EXIT: u64 = 93;
#[cfg(target_arch = "aarch64")]
const SYS_GETCWD: u64 = 17;

#[cfg(target_arch = "x86_64")]
const SYS_WRITE: u64 = 1;
#[cfg(target_arch = "x86_64")]
const SYS_EXIT: u64 = 60;
#[cfg(target_arch = "x86_64")]
const SYS_GETCWD: u64 = 79;

const PATH_MAX: usize = 4096;

#[cfg(target_arch = "aarch64")]
#[inline(always)]
unsafe fn syscall2(nr: u64, a: u64, b: u64) -> i64 {
    let mut ret: i64;
    unsafe {
        core::arch::asm!(
            "svc #0",
            in("x8") nr,
            inout("x0") a => ret,
            in("x1") b,
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

fn cstr_len(buf: &[u8]) -> usize {
    let mut n = 0;
    while n < buf.len() && buf[n] != 0 {
        n += 1;
    }
    n
}

#[panic_handler]
fn panic(_info: &PanicInfo) -> ! {
    write_str(2, b"[rust-pwd] panic\n");
    unsafe {
        sys_exit(1);
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn main(argc: i32, argv: *const *const u8, _envp: *const *const u8) -> i32 {
    // -L/-P toggle the GNU "logical vs physical" preference. We always
    // call getcwd(2), which on Futura returns the canonical path with
    // symlinks resolved — i.e. the physical form. So -P is a no-op
    // and -L is accepted but produces the same output. Flags are
    // wired so portable scripts that pass them don't error.
    let mut idx: i32 = 1;
    while idx < argc {
        let p = unsafe { *argv.add(idx as usize) };
        if p.is_null() || (p as usize) < 0x10000 { break; }
        let mut n = 0; unsafe { while *p.add(n) != 0 { n += 1; } }
        let s = unsafe { core::slice::from_raw_parts(p, n) };
        if s == b"--help" {
            let help: &[u8] = b"\
Usage: rust-pwd [-L | -P]
Print the current working directory via getcwd(2).

  -L, --logical    accept symlinks (no-op; getcwd already canonical)
  -P, --physical   resolve all symlinks (default; matches getcwd)
      --help       show this help and exit
\0";
            let len = help.len() - 1;
            unsafe { let _ = syscall3(SYS_WRITE, 1, help.as_ptr() as u64, len as u64); }
            return 0;
        }
        if s == b"-L" || s == b"--logical" || s == b"-P" || s == b"--physical" {
            idx += 1;
            continue;
        }
        if s == b"--" { break; }
        break;
    }
    let mut buf = [0u8; PATH_MAX];

    // getcwd(buf, size). Linux returns the byte count including the
    // trailing NUL; on aarch64 generic syscalls the same convention
    // holds. A negative return indicates an error.
    let rc = unsafe { syscall2(SYS_GETCWD, buf.as_mut_ptr() as u64, buf.len() as u64) };
    if rc < 0 {
        write_str(2, b"rust-pwd: getcwd() failed\n");
        return 1;
    }

    // Trust NUL termination — that's the well-defined contract — and
    // fall back to the kernel-reported length only if the buffer
    // wasn't NUL-terminated for some reason.
    let nul = cstr_len(&buf);
    let len = if nul > 0 {
        nul
    } else if (rc as usize) > 0 && (rc as usize) <= buf.len() {
        // Some kernels include the NUL in the returned count.
        let r = rc as usize;
        if buf[r - 1] == 0 { r - 1 } else { r }
    } else {
        0
    };

    if len == 0 {
        write_str(1, b"/\n");
    } else {
        write_str(1, &buf[..len]);
        write_str(1, b"\n");
    }
    0
}
