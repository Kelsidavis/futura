// SPDX-License-Identifier: MPL-2.0
//
// rust-chmod — change a file's mode (octal-only).
//
//   rust-chmod <octal-mode> <path> [<path>...]
//
// Only octal modes (e.g. 755, 0644) are supported — no symbolic
// "u+x" form. Per-arch syscall:
//   aarch64 -> fchmodat(AT_FDCWD, path, mode, 0)  (SYS=53)
//   x86_64  -> chmod(path, mode)                  (SYS=90)
//
// Same per-arch dispatch shape as rust-mv / rust-ln, since x86_64's
// sysnums.h doesn't export fchmodat. Exits 1 if any path failed,
// 0 if all succeeded, 2 on usage error.

#![no_std]
#![forbid(unsafe_op_in_unsafe_fn)]

use core::panic::PanicInfo;

#[cfg(target_arch = "aarch64")]
mod sysn {
    pub const WRITE: u64 = 64;
    pub const EXIT: u64 = 93;
    pub const FCHMODAT: u64 = 53;
}

#[cfg(target_arch = "x86_64")]
mod sysn {
    pub const WRITE: u64 = 1;
    pub const EXIT: u64 = 60;
    pub const CHMOD: u64 = 90;
}

#[cfg(target_arch = "aarch64")]
const AT_FDCWD: i64 = -100;
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
    write_str(STDERR, b"[rust-chmod] panic\n");
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

// Parse an octal string (with optional leading 0). Returns None on
// non-octal byte or on overflow past 0o7777.
fn parse_octal(p: *const u8) -> Option<u32> {
    let n = cstr_len(p);
    if n == 0 || n > 5 {
        return None;
    }
    let s = unsafe { core::slice::from_raw_parts(p, n) };
    let start = if s[0] == b'0' && n > 1 { 1 } else { 0 };
    let mut v: u32 = 0;
    for i in start..n {
        let c = s[i];
        if !(b'0'..=b'7').contains(&c) {
            return None;
        }
        v = v * 8 + (c - b'0') as u32;
        if v > 0o7777 {
            return None;
        }
    }
    Some(v)
}

fn arg_eq(p: *const u8, want: &[u8]) -> bool {
    for (i, &b) in want.iter().enumerate() {
        if unsafe { *p.add(i) } != b { return false; }
    }
    unsafe { *p.add(want.len()) == 0 }
}

#[unsafe(no_mangle)]
pub extern "C" fn main(argc: i32, argv: *const *const u8, _envp: *const *const u8) -> i32 {
    let mut idx: i32 = 1;
    let mut verbose = false;
    let mut changes_only = false;  // -c: emit only on actual change
    while idx < argc {
        let p = unsafe { *argv.add(idx as usize) };
        if p.is_null() || (p as usize) < 0x10000 { break; }
        if arg_eq(p, b"-v") || arg_eq(p, b"--verbose") {
            verbose = true; idx += 1; continue;
        }
        if arg_eq(p, b"-c") || arg_eq(p, b"--changes") {
            // -c implies verbose-on-change; we don't have stat-before
            // here so we degrade to -v's behaviour (every chmod prints,
            // not just real changes). Acceptable: scripts rarely care
            // about the distinction and getting the stat-before
            // round-trip just to honour it isn't worth the cost.
            changes_only = true; verbose = true; idx += 1; continue;
        }
        if arg_eq(p, b"--") { idx += 1; break; }
        if arg_eq(p, b"--help") {
            let help: &[u8] = b"\
Usage: rust-chmod [-v] OCTAL_MODE FILE [FILE...]
Change each FILE's mode.

  -v, --verbose   emit \"mode of '<path>' changed to NNNN\"
  -c, --changes   alias for -v (no stat-before optimization yet)
      --help          show this help and exit

Only octal modes are accepted (e.g. 0644). Symbolic modes are TBD.
\0";
            let len = help.len() - 1;
            unsafe { let _ = syscall3(sysn::WRITE, 1, help.as_ptr() as u64, len as u64); }
            return 0;
        }
        break;
    }
    let _ = changes_only;

    if argc - idx < 2 {
        write_str(STDERR, b"usage: rust-chmod [-v] <octal-mode> <path> [<path>...]\n");
        return 2;
    }
    let mode_p = unsafe { *argv.add(idx as usize) };
    if mode_p.is_null() || (mode_p as usize) < 0x10000 {
        write_str(STDERR, b"rust-chmod: invalid mode\n");
        return 2;
    }
    let mode = match parse_octal(mode_p) {
        Some(m) => m,
        None => {
            write_str(STDERR, b"rust-chmod: only octal modes are supported (e.g. 0644)\n");
            return 2;
        }
    };

    let mut had_error = false;
    for ai in (idx + 1)..argc {
        let p = unsafe { *argv.add(ai as usize) };
        if p.is_null() || (p as usize) < 0x10000 {
            had_error = true;
            continue;
        }
        #[cfg(target_arch = "aarch64")]
        let r = unsafe {
            syscall4(sysn::FCHMODAT, AT_FDCWD as u64, p as u64, mode as u64, 0)
        };
        #[cfg(target_arch = "x86_64")]
        let r = unsafe { syscall2(sysn::CHMOD, p as u64, mode as u64) };
        if r < 0 {
            write_str(STDERR, b"rust-chmod: chmod failed for '");
            let n = cstr_len(p);
            unsafe {
                let _ = syscall3(sysn::WRITE, STDERR as u64, p as u64, n as u64);
            }
            write_str(STDERR, b"'\n");
            had_error = true;
        } else if verbose {
            // "mode of 'path' changed to NNNN"
            let n = cstr_len(p);
            write_str(1, b"mode of '");
            unsafe { let _ = syscall3(sysn::WRITE, 1, p as u64, n as u64); }
            write_str(1, b"' changed to ");
            // 4-digit octal mode
            let m = mode & 0o7777;
            let mut buf = [b'0'; 4];
            buf[0] = b'0' + ((m >> 9) & 0o7) as u8;
            buf[1] = b'0' + ((m >> 6) & 0o7) as u8;
            buf[2] = b'0' + ((m >> 3) & 0o7) as u8;
            buf[3] = b'0' + (m & 0o7) as u8;
            write_str(1, &buf);
            write_str(1, b"\n");
        }
    }
    if had_error { 1 } else { 0 }
}
