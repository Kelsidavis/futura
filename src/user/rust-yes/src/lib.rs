// SPDX-License-Identifier: MPL-2.0
//
// rust-yes — repeatedly print "y\n" (or argv-joined-by-space + "\n").
//
//   rust-yes              -> "y\n" forever
//   rust-yes ok           -> "ok\n" forever
//   rust-yes hello world  -> "hello world\n" forever
//
// Builds the line once into a 256-byte stack buffer and writes it
// in a tight loop. Exits cleanly (status 0) on the first short or
// failing write — that's how the user normally stops it (closing
// the consumer end of the pipe → SIGPIPE / EPIPE).

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
    write_str(STDERR, b"[rust-yes] panic\n");
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

#[unsafe(no_mangle)]
pub extern "C" fn main(argc: i32, argv: *const *const u8, _envp: *const *const u8) -> i32 {
    // --help short-circuit (single-arg form).
    if argc == 2 {
        let first = unsafe { *argv.add(1) };
        if !first.is_null() && (first as usize) >= 0x10000 {
            let want = b"--help";
            let n = cstr_len(first);
            if n == want.len() {
                let mut ok = true;
                for i in 0..want.len() {
                    if unsafe { *first.add(i) } != want[i] { ok = false; break; }
                }
                if ok {
                    let help: &[u8] = b"\
Usage: rust-yes [STRING...]
Repeatedly print STRING (or 'y' if absent) followed by '\\n'.

  --help    show this help and exit
\0";
                    let len = help.len() - 1;
                    unsafe { let _ = syscall3(sysn::WRITE, 1, help.as_ptr() as u64, len as u64); }
                    return 0;
                }
            }
        }
    }
    // Build the line in a fixed buffer; truncate rather than fail if it
    // doesn't fit. coreutils' yes also does best-effort truncation.
    let mut buf = [0u8; 256];
    let mut n = 0usize;

    if argc < 2 {
        buf[0] = b'y';
        n = 1;
    } else {
        for i in 1..argc {
            let p = unsafe { *argv.add(i as usize) };
            if p.is_null() || (p as usize) < 0x10000 {
                continue;
            }
            if i > 1 {
                if n + 1 < buf.len() - 1 {
                    buf[n] = b' ';
                    n += 1;
                }
            }
            let plen = cstr_len(p);
            for j in 0..plen {
                if n + 1 >= buf.len() - 1 {
                    break;
                }
                buf[n] = unsafe { *p.add(j) };
                n += 1;
            }
        }
        if n == 0 {
            // All argv entries were invalid; fall back to "y".
            buf[0] = b'y';
            n = 1;
        }
    }

    if n + 1 < buf.len() {
        buf[n] = b'\n';
        n += 1;
    }

    let line = &buf[..n];
    loop {
        let r = unsafe {
            syscall3(sysn::WRITE, STDOUT as u64, line.as_ptr() as u64, line.len() as u64)
        };
        if r <= 0 {
            // Pipe closed / signal — clean exit, like coreutils' yes(1).
            return 0;
        }
    }
}
