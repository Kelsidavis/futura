// SPDX-License-Identifier: MPL-2.0
//
// rust-touch — sixth user-space Rust program for Futura OS.
//
// Creates each named file if it doesn't already exist (open with
// O_CREAT and immediately close). Existing files are left untouched
// — the original GNU touch also bumps mtime, but this kernel doesn't
// reliably plumb utimensat yet, so we settle for the create-only
// subset that's still useful for ad-hoc scripting and tests.
//
// Flags:
//   -c, --no-create   skip files that don't exist (don't create them)

#![no_std]
#![forbid(unsafe_op_in_unsafe_fn)]

use core::panic::PanicInfo;

#[cfg(target_arch = "aarch64")]
mod sysn {
    pub const WRITE: u64 = 64;
    pub const EXIT: u64 = 93;
    pub const OPENAT: u64 = 56;
    pub const CLOSE: u64 = 57;
}

#[cfg(target_arch = "x86_64")]
mod sysn {
    pub const WRITE: u64 = 1;
    pub const EXIT: u64 = 60;
    pub const OPENAT: u64 = 257;
    pub const CLOSE: u64 = 3;
}

const AT_FDCWD: i64 = -100;
const O_WRONLY: u64 = 1;
const O_CREAT: u64 = 0o100;
const O_NOCTTY: u64 = 0o400;
const STDERR: i32 = 2;

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

#[panic_handler]
fn panic(_info: &PanicInfo) -> ! {
    write_str(STDERR, b"[rust-touch] panic\n");
    unsafe {
        sys_exit(1);
    }
}

fn arg_is(p: *const u8, want: &[u8]) -> bool {
    for (i, &b) in want.iter().enumerate() {
        if unsafe { *p.add(i) } != b { return false; }
    }
    unsafe { *p.add(want.len()) == 0 }
}

#[unsafe(no_mangle)]
pub extern "C" fn main(argc: i32, argv: *const *const u8, _envp: *const *const u8) -> i32 {
    if argc < 2 {
        write_str(STDERR, b"usage: rust-touch [-c] FILE [FILE...]\n");
        return 1;
    }

    let mut idx = 1usize;
    let mut no_create = false;
    while let Some(p) = argv_get(argc, argv, idx) {
        if arg_is(p, b"-c") || arg_is(p, b"--no-create") {
            no_create = true;
            idx += 1;
            continue;
        }
        if arg_is(p, b"--") { idx += 1; break; }
        if arg_is(p, b"--help") {
            let help: &[u8] = b"\
Usage: rust-touch [-c] FILE [FILE...]
Create each FILE if it doesn't exist (timestamp updates are TBD).

  -c, --no-create   skip files that don't exist (no error)
      --help            show this help and exit
\0";
            let len = help.len() - 1;
            unsafe { let _ = syscall3(sysn::WRITE, 1, help.as_ptr() as u64, len as u64); }
            return 0;
        }
        break;
    }

    if (idx as i32) >= argc {
        write_str(STDERR, b"usage: rust-touch [-c] FILE [FILE...]\n");
        return 1;
    }

    let mut had_error = false;
    while let Some(p) = argv_get(argc, argv, idx) {
        let n = cstr_len(p);
        if n == 0 {
            write_str(STDERR, b"rust-touch: empty filename\n");
            had_error = true;
            idx += 1;
            continue;
        }

        // -c skips O_CREAT entirely. Combined with O_WRONLY this means
        // we open existing files (no-op-confirming they exist) and
        // silently ignore ENOENT for missing ones.
        let flags = if no_create {
            O_WRONLY | O_NOCTTY
        } else {
            O_WRONLY | O_CREAT | O_NOCTTY
        };
        let fd = unsafe {
            syscall4(sysn::OPENAT, AT_FDCWD as u64, p as u64, flags, 0o644)
        };
        if fd < 0 {
            if no_create {
                // Missing file under -c is intentionally silent;
                // matches GNU touch -c behaviour.
            } else {
                write_str(STDERR, b"rust-touch: cannot create '");
                unsafe {
                    let _ = syscall3(sysn::WRITE, STDERR as u64, p as u64, n as u64);
                }
                write_str(STDERR, b"'\n");
                had_error = true;
            }
        } else {
            unsafe { let _ = syscall1(sysn::CLOSE, fd as u64); }
        }

        idx += 1;
    }

    if had_error { 1 } else { 0 }
}
