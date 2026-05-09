// SPDX-License-Identifier: MPL-2.0
//
// rust-uptime — print formatted system uptime.
//
//   rust-uptime    ->   "up 0d 0h 12m 34s"
//
// Reads /proc/uptime (or falls back to clock_gettime(CLOCK_MONOTONIC))
// and pretty-prints. /proc/uptime format is
// "<seconds>.<fraction> <idle>.<fraction>\n"; we take the integer
// seconds and split into days/hours/minutes/seconds.

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
    pub const CLOCK_GETTIME: u64 = 113;
}

#[cfg(target_arch = "x86_64")]
mod sysn {
    pub const READ: u64 = 0;
    pub const WRITE: u64 = 1;
    pub const EXIT: u64 = 60;
    pub const OPENAT: u64 = 257;
    pub const CLOSE: u64 = 3;
    pub const CLOCK_GETTIME: u64 = 228;
}

const AT_FDCWD: i64 = -100;
const O_RDONLY: u64 = 0;
const STDOUT: i32 = 1;
const STDERR: i32 = 2;
const CLOCK_MONOTONIC: u64 = 1;

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
    write_str(STDERR, b"[rust-uptime] panic\n");
    unsafe {
        sys_exit(1);
    }
}

// Try /proc/uptime first; fall back to CLOCK_MONOTONIC if it
// doesn't exist or returns junk. Returns the uptime in whole seconds.
fn read_uptime_secs() -> u64 {
    let mut buf = [0u8; 64];
    let fd = unsafe {
        syscall4(sysn::OPENAT, AT_FDCWD as u64,
                 b"/proc/uptime\0".as_ptr() as u64,
                 O_RDONLY, 0) as i32
    };
    if fd >= 0 {
        let n = unsafe {
            syscall3(sysn::READ, fd as u64, buf.as_mut_ptr() as u64, buf.len() as u64)
        };
        unsafe { let _ = syscall1(sysn::CLOSE, fd as u64); }
        if n > 0 {
            // Parse the integer-seconds prefix up to '.' or ' '.
            let n = n as usize;
            let mut v: u64 = 0;
            let mut saw_digit = false;
            for i in 0..n {
                let c = buf[i];
                if c == b'.' || c == b' ' || c == b'\n' { break; }
                if !(b'0'..=b'9').contains(&c) { break; }
                v = v * 10 + (c - b'0') as u64;
                saw_digit = true;
            }
            if saw_digit {
                return v;
            }
        }
    }
    // Fallback: clock_gettime(CLOCK_MONOTONIC).
    let mut ts = [0u64; 2];
    let r = unsafe { syscall2(sysn::CLOCK_GETTIME, CLOCK_MONOTONIC, ts.as_mut_ptr() as u64) };
    if r < 0 { 0 } else { ts[0] }
}

// Print a u64 followed by a unit char and trailing space.
fn write_field(n: u64, unit: u8) {
    let mut buf = [0u8; 24];
    let mut i = buf.len();
    let mut v = n;
    if v == 0 {
        i -= 1;
        buf[i] = b'0';
    } else {
        while v > 0 {
            i -= 1;
            buf[i] = b'0' + (v % 10) as u8;
            v /= 10;
        }
    }
    write_str(STDOUT, &buf[i..]);
    let suffix = [unit, b' '];
    write_str(STDOUT, &suffix);
}

#[unsafe(no_mangle)]
pub extern "C" fn main(_argc: i32, _argv: *const *const u8, _envp: *const *const u8) -> i32 {
    let secs = read_uptime_secs();
    let days = secs / 86400;
    let hours = (secs % 86400) / 3600;
    let mins = (secs % 3600) / 60;
    let s = secs % 60;
    write_str(STDOUT, b"up ");
    write_field(days, b'd');
    write_field(hours, b'h');
    write_field(mins, b'm');
    // Last field — print without trailing space.
    let mut buf = [0u8; 24];
    let mut i = buf.len();
    let mut v = s;
    if v == 0 {
        i -= 1;
        buf[i] = b'0';
    } else {
        while v > 0 {
            i -= 1;
            buf[i] = b'0' + (v % 10) as u8;
            v /= 10;
        }
    }
    write_str(STDOUT, &buf[i..]);
    write_str(STDOUT, b"s\n");
    0
}
