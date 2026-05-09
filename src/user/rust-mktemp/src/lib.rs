// SPDX-License-Identifier: MPL-2.0
//
// rust-mktemp — create a unique temp file (or directory with -d).
//
//   rust-mktemp                         /tmp/tmp.XXXXXXXX
//   rust-mktemp -d                      /tmp/tmp.XXXXXXXX (mkdir 0700)
//   rust-mktemp <template>              user template; the trailing
//                                       run of 'X's gets substituted
//                                       with random base36 chars
//
// Substitution mixes clock_gettime(CLOCK_MONOTONIC) nanoseconds with
// the caller's pid to fill the X's. Retries up to 64 attempts on
// EEXIST (each retry stirs the entropy by a clock_gettime sample).
// Created files have mode 0600, dirs 0700, matching POSIX/GNU.

#![no_std]
#![forbid(unsafe_op_in_unsafe_fn)]

use core::panic::PanicInfo;

#[cfg(target_arch = "aarch64")]
mod sysn {
    pub const WRITE: u64 = 64;
    pub const EXIT: u64 = 93;
    pub const OPENAT: u64 = 56;
    pub const CLOSE: u64 = 57;
    pub const MKDIRAT: u64 = 34;
    pub const CLOCK_GETTIME: u64 = 113;
    pub const GETPID: u64 = 172;
}

#[cfg(target_arch = "x86_64")]
mod sysn {
    pub const WRITE: u64 = 1;
    pub const EXIT: u64 = 60;
    pub const OPENAT: u64 = 257;
    pub const CLOSE: u64 = 3;
    pub const MKDIRAT: u64 = 258;
    pub const CLOCK_GETTIME: u64 = 228;
    pub const GETPID: u64 = 39;
}

const AT_FDCWD: i64 = -100;
const O_RDWR: u64 = 2;
const O_CREAT: u64 = 0o100;
const O_EXCL: u64 = 0o200;
const STDOUT: i32 = 1;
const STDERR: i32 = 2;
const CLOCK_MONOTONIC: u64 = 1;

#[cfg(target_arch = "aarch64")]
#[inline(always)]
unsafe fn syscall0(nr: u64) -> i64 {
    let mut ret: i64;
    unsafe {
        core::arch::asm!(
            "svc #0",
            in("x8") nr,
            lateout("x0") ret,
            options(nostack),
        );
    }
    ret
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
unsafe fn syscall0(nr: u64) -> i64 {
    let mut ret: i64;
    unsafe {
        core::arch::asm!(
            "syscall",
            inout("rax") nr => ret,
            lateout("rcx") _,
            lateout("r11") _,
            options(nostack),
        );
    }
    ret
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
    write_str(STDERR, b"[rust-mktemp] panic\n");
    unsafe {
        sys_exit(1);
    }
}

fn cstr_eq(p: *const u8, s: &[u8]) -> bool {
    for (i, &b) in s.iter().enumerate() {
        if unsafe { *p.add(i) } != b {
            return false;
        }
    }
    unsafe { *p.add(s.len()) == 0 }
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

const ALPHA36: &[u8; 36] = b"0123456789abcdefghijklmnopqrstuvwxyz";

// Mix a stir into the seed to advance it between attempts.
fn stir(seed: &mut u64) {
    let mut ts = [0u64; 2];
    let r = unsafe { syscall2(sysn::CLOCK_GETTIME, CLOCK_MONOTONIC, ts.as_mut_ptr() as u64) };
    let ns = if r >= 0 { ts[1] } else { 0 };
    // xorshift step
    *seed ^= ns.wrapping_mul(0x2545_F491_4F6C_DD1D);
    let mut s = *seed;
    s ^= s << 13;
    s ^= s >> 7;
    s ^= s << 17;
    *seed = s;
}

// Substitute the trailing run of 'X' in `path[..end]` (path is NUL-
// terminated at `end`) with random base36 chars. Path is mutated
// in place.
fn substitute_xs(path: &mut [u8], end: usize, seed: &mut u64) {
    let mut x_start = end;
    while x_start > 0 && path[x_start - 1] == b'X' {
        x_start -= 1;
    }
    let mut s = *seed;
    for i in x_start..end {
        // Step before each char so consecutive X's differ.
        s ^= s << 13;
        s ^= s >> 7;
        s ^= s << 17;
        path[i] = ALPHA36[(s as usize) % 36];
    }
    *seed = s;
}

#[unsafe(no_mangle)]
pub extern "C" fn main(argc: i32, argv: *const *const u8, _envp: *const *const u8) -> i32 {
    let mut want_dir = false;
    let mut user_template: Option<*const u8> = None;
    for ai in 1..argc {
        let p = unsafe { *argv.add(ai as usize) };
        if p.is_null() || (p as usize) < 0x10000 {
            continue;
        }
        if cstr_eq(p, b"-d") {
            want_dir = true;
        } else if cstr_eq(p, b"--help") {
            let help: &[u8] = b"\
Usage: rust-mktemp [-d] [TEMPLATE]
Create a unique file (or directory with -d) and print its path.

  -d            create a directory (mode 0700) instead of a file
  TEMPLATE      path template; trailing X's are replaced with random
                ALPHA-36 chars (default /tmp/tmp.XXXXXXXX)
      --help    show this help and exit
\0";
            let len = help.len() - 1;
            unsafe { let _ = syscall3(sysn::WRITE, STDOUT as u64,
                                       help.as_ptr() as u64, len as u64); }
            return 0;
        } else if user_template.is_none() {
            user_template = Some(p);
        } else {
            write_str(STDERR, b"rust-mktemp: too many arguments\n");
            return 1;
        }
    }

    // Build path buf in place.
    let mut path = [0u8; 256];
    let end: usize;
    match user_template {
        Some(p) => {
            let n = cstr_len(p);
            if n + 1 > path.len() {
                write_str(STDERR, b"rust-mktemp: template too long\n");
                return 1;
            }
            for i in 0..n {
                path[i] = unsafe { *p.add(i) };
            }
            end = n;
        }
        None => {
            // Default template: /tmp/tmp.XXXXXXXX
            let default = b"/tmp/tmp.XXXXXXXX";
            for (i, &b) in default.iter().enumerate() {
                path[i] = b;
            }
            end = default.len();
        }
    }
    path[end] = 0;

    // Verify there's at least one trailing 'X'.
    if end == 0 || path[end - 1] != b'X' {
        write_str(STDERR, b"rust-mktemp: template must end with X's\n");
        return 1;
    }

    // Seed mixer: pid << 32 | clock-ns.
    let pid = unsafe { syscall0(sysn::GETPID) } as u64;
    let mut ts = [0u64; 2];
    let _ = unsafe { syscall2(sysn::CLOCK_GETTIME, CLOCK_MONOTONIC, ts.as_mut_ptr() as u64) };
    let mut seed: u64 = (pid << 32) ^ ts[0].wrapping_mul(1_000_000_000) ^ ts[1];
    if seed == 0 { seed = 0xdead_beef_cafe_babe; }

    for _attempt in 0..64 {
        substitute_xs(&mut path, end, &mut seed);
        let r: i64 = if want_dir {
            unsafe {
                syscall3(sysn::MKDIRAT, AT_FDCWD as u64, path.as_ptr() as u64, 0o700)
            }
        } else {
            unsafe {
                syscall4(
                    sysn::OPENAT,
                    AT_FDCWD as u64,
                    path.as_ptr() as u64,
                    O_RDWR | O_CREAT | O_EXCL,
                    0o600,
                )
            }
        };
        if r >= 0 {
            if !want_dir {
                unsafe { let _ = syscall1(sysn::CLOSE, r as u64); }
            }
            // Print the path (without NUL) plus newline.
            write_str(STDOUT, &path[..end]);
            write_str(STDOUT, b"\n");
            return 0;
        }
        // EEXIST is -17 on both arches (Linux generic). Any other
        // error means we can't make progress; bail.
        if r != -17 {
            write_str(STDERR, b"rust-mktemp: cannot create temp\n");
            return 1;
        }
        stir(&mut seed);
    }
    write_str(STDERR, b"rust-mktemp: too many collisions\n");
    1
}
