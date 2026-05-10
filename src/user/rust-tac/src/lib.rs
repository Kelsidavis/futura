// SPDX-License-Identifier: MPL-2.0
//
// rust-tac — print input in reverse, line by line.
//
//   rust-tac          read stdin, output its lines in reverse
//   rust-tac <file>   read file, output its lines in reverse
//
// Slurps up to MAX_INPUT bytes into a fixed buffer, then walks
// backward emitting each newline-terminated chunk in reverse
// order. Final partial line (no trailing '\n') is emitted first
// without a trailing newline, mirroring GNU tac's behaviour on
// non-newline-terminated input.
//
// MAX_INPUT is 64 KiB — large enough for typical log slices and
// /proc/* files but bounded so the no_std binary's BSS stays
// predictable. Files larger than that are silently truncated to
// the first 64 KiB; bigger inputs would need lseek-from-end.

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
const O_RDONLY: u64 = 0;
const STDIN: i32 = 0;
const STDOUT: i32 = 1;
const STDERR: i32 = 2;
const MAX_INPUT: usize = 64 * 1024;

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

fn write_str(fd: i32, s: &[u8]) {
    let _ = write_all(fd, s);
}

#[panic_handler]
fn panic(_info: &PanicInfo) -> ! {
    write_str(STDERR, b"[rust-tac] panic\n");
    unsafe {
        sys_exit(1);
    }
}

// Static buffer to keep the binary out of large stack frames and so
// the .data initialized-zero region lands in .bss.
static mut BUF: [u8; MAX_INPUT] = [0; MAX_INPUT];

fn slurp(fd: i32) -> usize {
    let mut filled = 0usize;
    let buf_ptr = core::ptr::addr_of_mut!(BUF) as *mut u8;
    while filled < MAX_INPUT {
        let n = unsafe {
            syscall3(
                sysn::READ,
                fd as u64,
                buf_ptr.add(filled) as u64,
                (MAX_INPUT - filled) as u64,
            )
        };
        if n < 0 {
            return filled;
        }
        if n == 0 {
            break;
        }
        filled += n as usize;
    }
    filled
}

// Slurp `fd` into the static BUF, then emit lines in reverse order.
// `sep` is the line terminator — '\n' by default, NUL with -z.
// Returns true on success (clean read + writes), false on any error.
fn tac_fd(fd: i32, sep: u8) -> bool {
    let n = slurp(fd);
    if n == 0 { return true; }

    let buf = unsafe { core::slice::from_raw_parts(core::ptr::addr_of!(BUF) as *const u8, n) };
    let mut tail = n;
    let had_trailing_partial = buf[n - 1] != sep;
    if had_trailing_partial {
        let mut start = n;
        while start > 0 && buf[start - 1] != sep { start -= 1; }
        if !write_all(STDOUT, &buf[start..n]) { return false; }
        tail = start;
    }
    let mut end = tail;
    while end > 0 {
        let mut start = end - 1;
        while start > 0 && buf[start - 1] != sep { start -= 1; }
        if !write_all(STDOUT, &buf[start..end]) { return false; }
        end = start;
    }
    let _ = had_trailing_partial;
    true
}

#[unsafe(no_mangle)]
pub extern "C" fn main(argc: i32, argv: *const *const u8, _envp: *const *const u8) -> i32 {
    // Parse leading flags: --help, -z/--zero-terminated.
    let mut sep: u8 = b'\n';
    let mut idx: i32 = 1;
    while idx < argc {
        let p = unsafe { *argv.add(idx as usize) };
        if p.is_null() || (p as usize) < 0x10000 { break; }
        let want_h = b"--help";
        let mut h_ok = true;
        for i in 0..want_h.len() {
            if unsafe { *p.add(i) } != want_h[i] { h_ok = false; break; }
        }
        if h_ok && unsafe { *p.add(want_h.len()) } == 0 {
            let help: &[u8] = b"\
Usage: rust-tac [-z] [-s SEP] [FILE]...
Concatenate FILEs and print them in reverse record order. Each FILE
is slurped into a static buffer, then emitted last-record-first.
With no FILE (or FILE = '-') reads stdin.

  -s, --separator=SEP    use SEP[0] as the record separator instead of
                         newline (single byte; multi-byte unsupported)
  -z, --zero-terminated  shorthand for -s '\\0'
      --help             show this help and exit
\0";
            let len = help.len() - 1;
            unsafe { let _ = syscall3(sysn::WRITE, STDOUT as u64,
                                      help.as_ptr() as u64, len as u64); }
            return 0;
        }
        // -z
        let is_z = unsafe { *p == b'-' && *p.add(1) == b'z' && *p.add(2) == 0 };
        let want_zl = b"--zero-terminated";
        let mut zl_ok = true;
        for i in 0..want_zl.len() {
            if unsafe { *p.add(i) } != want_zl[i] { zl_ok = false; break; }
        }
        let is_zlong = zl_ok && unsafe { *p.add(want_zl.len()) } == 0;
        if is_z || is_zlong {
            sep = 0;
            idx += 1;
            continue;
        }
        // -s SEP / --separator SEP / --separator=SEP
        let mut p_n = 0usize;
        unsafe { while *p.add(p_n) != 0 { p_n += 1; } }
        let is_s = p_n == 2 && unsafe { *p == b'-' && *p.add(1) == b's' };
        let is_sep_long = p_n == 11 && unsafe {
            let want = b"--separator";
            let mut ok = true;
            for j in 0..want.len() { if *p.add(j) != want[j] { ok = false; break; } }
            ok
        };
        let is_sep_eq = p_n > 12 && unsafe {
            let want = b"--separator=";
            let mut ok = true;
            for j in 0..want.len() { if *p.add(j) != want[j] { ok = false; break; } }
            ok
        };
        if is_s || is_sep_long {
            if idx + 1 >= argc {
                write_str(STDERR, b"rust-tac: -s needs a SEP\n");
                return 1;
            }
            let sp = unsafe { *argv.add((idx + 1) as usize) };
            if sp.is_null() || (sp as usize) < 0x10000 { return 1; }
            let first = unsafe { *sp };
            // Empty SEP is treated as "no separator change" — we leave
            // sep at its current value rather than degenerate to a
            // record-per-byte mode.
            if first != 0 { sep = first; }
            idx += 2;
            continue;
        }
        if is_sep_eq {
            let first = unsafe { *p.add(12) };
            if first != 0 { sep = first; }
            idx += 1;
            continue;
        }
        // -- ends options
        if unsafe { *p == b'-' && *p.add(1) == b'-' && *p.add(2) == 0 } {
            idx += 1;
            break;
        }
        break;
    }
    if idx >= argc {
        return if tac_fd(STDIN, sep) { 0 } else { 1 };
    }
    let mut had_error = false;
    for ai in idx..argc {
        let p = unsafe { *argv.add(ai as usize) };
        if p.is_null() || (p as usize) < 0x10000 {
            had_error = true;
            continue;
        }
        // "-" reads stdin, like GNU tac.
        let mut nlen = 0usize;
        unsafe { while *p.add(nlen) != 0 { nlen += 1; } }
        let is_dash = nlen == 1 && unsafe { *p } == b'-';
        if is_dash {
            if !tac_fd(STDIN, sep) { had_error = true; }
            continue;
        }
        let fd = unsafe {
            syscall4(sysn::OPENAT, AT_FDCWD as u64, p as u64, O_RDONLY, 0) as i32
        };
        if fd < 0 {
            write_str(STDERR, b"rust-tac: cannot open '");
            unsafe { let _ = syscall3(sysn::WRITE, STDERR as u64, p as u64, nlen as u64); }
            write_str(STDERR, b"'\n");
            had_error = true;
            continue;
        }
        if !tac_fd(fd, sep) { had_error = true; }
        unsafe { let _ = syscall1(sysn::CLOSE, fd as u64); }
    }
    if had_error { 1 } else { 0 }
}
