// SPDX-License-Identifier: MPL-2.0
//
// rust-tty — print stdin's controlling terminal path, or "not a tty".
//
//   rust-tty           prints "/dev/console" if stdin is a tty, else "not a tty"
//   rust-tty -s        no output; exit 0 if tty, 1 if not, 2 on usage error
//
// We don't have a way to look up an fd's actual /dev path (no /proc),
// so a positive isatty check just prints "/dev/console" — close enough
// to be useful in shell scripts that gate on `[ -t 0 ]`-style logic.
//
// isatty(fd) is implemented as ioctl(fd, TCGETS, &buf): success means
// the fd is a terminal. We pass a 64-byte scratch (struct termios is
// 60 bytes on Linux/aarch64 and 36 bytes on x86_64; either fits).

#![no_std]
#![forbid(unsafe_op_in_unsafe_fn)]

use core::panic::PanicInfo;

#[cfg(target_arch = "aarch64")]
mod sysn {
    pub const WRITE: u64 = 64;
    pub const EXIT:  u64 = 93;
    pub const IOCTL: u64 = 29;
}

#[cfg(target_arch = "x86_64")]
mod sysn {
    pub const WRITE: u64 = 1;
    pub const EXIT:  u64 = 60;
    pub const IOCTL: u64 = 16;
}

const STDIN: i32  = 0;
const STDOUT: i32 = 1;
const STDERR: i32 = 2;
const TCGETS: u64 = 0x5401;

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
    write_str(STDERR, b"[rust-tty] panic\n");
    unsafe { sys_exit(1); }
}

fn cstr_eq(p: *const u8, s: &[u8]) -> bool {
    for (i, &b) in s.iter().enumerate() {
        if unsafe { *p.add(i) } != b { return false; }
    }
    unsafe { *p.add(s.len()) == 0 }
}

// Probe stdin for tty-ness via ioctl(TCGETS). On success the fd is a
// terminal; on -ENOTTY (or any other negative return) it isn't.
fn isatty(fd: i32) -> bool {
    // 64 bytes covers the largest struct termios layout we need.
    let mut buf = [0u8; 64];
    let r = unsafe {
        syscall3(sysn::IOCTL, fd as u64, TCGETS, buf.as_mut_ptr() as u64)
    };
    r >= 0
}

#[unsafe(no_mangle)]
pub extern "C" fn main(argc: i32, argv: *const *const u8, _envp: *const *const u8) -> i32 {
    let mut silent = false;
    let mut idx: i32 = 1;
    while idx < argc {
        let p = unsafe { *argv.add(idx as usize) };
        if p.is_null() || (p as usize) < 0x10000 { break; }
        if cstr_eq(p, b"-s") || cstr_eq(p, b"--silent") || cstr_eq(p, b"--quiet") {
            silent = true;
            idx += 1;
            continue;
        }
        if cstr_eq(p, b"--help") {
            let help: &[u8] = b"\
Usage: rust-tty [-s]
Print the device path of stdin's controlling terminal.

  -s, --silent, --quiet   no output; exit status alone reflects tty-ness
      --help              show this help and exit

Exit status:
  0  stdin is a terminal
  1  stdin is not a terminal
  2  argument error
\0";
            let len = help.len() - 1;
            unsafe { let _ = syscall3(sysn::WRITE, STDOUT as u64,
                                      help.as_ptr() as u64, len as u64); }
            return 0;
        }
        if cstr_eq(p, b"--") { break; }
        // Unknown flag — POSIX tty rejects with exit 2.
        write_str(STDERR, b"rust-tty: unknown option\n");
        return 2;
    }

    let on_tty = isatty(STDIN);
    if !silent {
        if on_tty {
            // Without /proc/self/fd we can't recover the actual device
            // path; "/dev/console" is a reasonable best-effort label.
            write_str(STDOUT, b"/dev/console\n");
        } else {
            write_str(STDOUT, b"not a tty\n");
        }
    }
    if on_tty { 0 } else { 1 }
}
