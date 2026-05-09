// SPDX-License-Identifier: MPL-2.0
//
// rust-tee — duplicate stdin to stdout and to each named file.
//
//   rust-tee <file1> [file2] ...
//
// Reads stdin in 4 KiB chunks, writes each chunk to stdout and to
// every output file. Files are created with O_WRONLY|O_CREAT|O_TRUNC
// (mode 0644) — i.e. truncating tee, not append. Up to MAX_FILES
// targets so the fd table on the stack is fixed-size.
//
// Returns 0 on clean EOF, 1 if any read or write failed (we keep
// going past per-file write errors so a single ENOSPC on one
// destination doesn't kill the rest of the fan-out).

#![no_std]
#![forbid(unsafe_op_in_unsafe_fn)]

use core::panic::PanicInfo;

#[cfg(target_arch = "aarch64")]
mod sysn {
    pub const READ: u64 = 63;
    pub const WRITE: u64 = 64;
    pub const EXIT: u64 = 93;
    pub const OPENAT: u64 = 56;
    pub const CLOSE: u64 = 57;
}

#[cfg(target_arch = "x86_64")]
mod sysn {
    pub const READ: u64 = 0;
    pub const WRITE: u64 = 1;
    pub const EXIT: u64 = 60;
    pub const OPENAT: u64 = 257;
    pub const CLOSE: u64 = 3;
}

const AT_FDCWD: i64 = -100;
const O_WRONLY: u64 = 1;
const O_CREAT: u64 = 0o100;
const O_TRUNC: u64 = 0o1000;
const STDIN: i32 = 0;
const STDOUT: i32 = 1;
const STDERR: i32 = 2;

const BUF: usize = 4096;
const MAX_FILES: usize = 16;

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
unsafe fn syscall4(nr: u64, a: u64, b: u64, c: u64, d: u64) -> i64 {
    let mut ret: i64;
    unsafe {
        core::arch::asm!(
            "syscall",
            inout("rax") nr => ret,
            in("rdi") a,
            in("rsi") b,
            in("rdx") c,
            in("r10") d,
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
    write_str(STDERR, b"[rust-tee] panic\n");
    unsafe {
        sys_exit(1);
    }
}

// Write the entire slice or return false on any short/failing write.
fn write_all(fd: i32, mut s: &[u8]) -> bool {
    while !s.is_empty() {
        let n = unsafe { syscall3(sysn::WRITE, fd as u64, s.as_ptr() as u64, s.len() as u64) };
        if n <= 0 {
            return false;
        }
        s = &s[n as usize..];
    }
    true
}

#[unsafe(no_mangle)]
pub extern "C" fn main(argc: i32, argv: *const *const u8, _envp: *const *const u8) -> i32 {
    if argc < 2 {
        // No files — degrade to plain cat (stdin → stdout) so pipelines
        // that pipe through `tee` with no targets still work.
        let mut buf = [0u8; BUF];
        loop {
            let n = unsafe {
                syscall3(sysn::READ, STDIN as u64, buf.as_mut_ptr() as u64, buf.len() as u64)
            };
            if n < 0 { return 1; }
            if n == 0 { return 0; }
            if !write_all(STDOUT, &buf[..n as usize]) { return 1; }
        }
    }

    let mut fds = [-1i32; MAX_FILES];
    let nfiles = ((argc - 1) as usize).min(MAX_FILES);

    let mut had_open_error = false;
    for i in 0..nfiles {
        let p = unsafe { *argv.add(1 + i) };
        if p.is_null() || (p as usize) < 0x10000 {
            had_open_error = true;
            continue;
        }
        let fd = unsafe {
            syscall4(
                sysn::OPENAT,
                AT_FDCWD as u64,
                p as u64,
                O_WRONLY | O_CREAT | O_TRUNC,
                0o644,
            ) as i32
        };
        if fd < 0 {
            write_str(STDERR, b"rust-tee: cannot open output file\n");
            had_open_error = true;
        } else {
            fds[i] = fd;
        }
    }

    let mut had_write_error = had_open_error;

    let mut buf = [0u8; BUF];
    loop {
        let n = unsafe {
            syscall3(sysn::READ, STDIN as u64, buf.as_mut_ptr() as u64, buf.len() as u64)
        };
        if n < 0 {
            had_write_error = true;
            break;
        }
        if n == 0 {
            break;
        }
        let chunk = &buf[..n as usize];
        if !write_all(STDOUT, chunk) {
            had_write_error = true;
        }
        for i in 0..nfiles {
            if fds[i] >= 0 && !write_all(fds[i], chunk) {
                // Drop the bad fd so we don't keep retrying it.
                unsafe { let _ = syscall1(sysn::CLOSE, fds[i] as u64); }
                fds[i] = -1;
                had_write_error = true;
            }
        }
    }

    for i in 0..nfiles {
        if fds[i] >= 0 {
            unsafe { let _ = syscall1(sysn::CLOSE, fds[i] as u64); }
        }
    }

    if had_write_error { 1 } else { 0 }
}
