// SPDX-License-Identifier: MPL-2.0
//
// rust-nl — number lines (cat -n shape).
//
//   rust-nl                      number stdin
//   rust-nl FILE [FILE…]         number each file in turn
//   rust-nl ... -                number stdin (in any position)
//
// Each non-empty line is prefixed with a 6-char right-aligned line
// number, a tab, then the line. Blank lines pass through unprefixed
// (matching GNU `nl` default body style "t": number text lines only).
// Multiple files share a single running line counter — same as
// `cat | nl`, which is the conventional behaviour. Lines longer than
// READ_BUF chunks have the prefix only on the chunk that ended in
// '\n' (or final flush) — the tail-fragment case is rare with 4 KiB
// chunks and not worth the bookkeeping for now.

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
const READ_BUF: usize = 4096;

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
    write_str(STDERR, b"[rust-nl] panic\n");
    unsafe {
        sys_exit(1);
    }
}

#[derive(Copy, Clone, PartialEq, Eq)]
enum BodyStyle { All, NonBlank, None }

#[derive(Copy, Clone)]
struct NlOpts {
    style: BodyStyle,
    width: u32,         // -w
    sep: [u8; 16],      // -s SEP (between number and line)
    sep_len: u32,
    increment: u64,     // -i
    start: u64,         // -v
    line_sep: u8,       // -z: NUL line terminator instead of '\n'
}

// Format a u64 right-aligned into `width` chars, then append `sep`.
fn write_lineno(n: u64, opts: &NlOpts) -> bool {
    let mut numbuf = [b'0'; 32];
    let mut k = numbuf.len();
    let mut v = n;
    if v == 0 {
        k -= 1;
        numbuf[k] = b'0';
    } else {
        while v > 0 && k > 0 {
            k -= 1;
            numbuf[k] = b'0' + (v % 10) as u8;
            v /= 10;
        }
    }
    let nlen = numbuf.len() - k;
    let want = opts.width as usize;
    let pad = if want > nlen { want - nlen } else { 0 };
    let pad_buf = [b' '; 32];
    if pad > 0 && !write_all(STDOUT, &pad_buf[..pad.min(pad_buf.len())]) {
        return false;
    }
    if !write_all(STDOUT, &numbuf[k..]) { return false; }
    write_all(STDOUT, &opts.sep[..opts.sep_len as usize])
}

struct NlState {
    at_line_start: bool,
    line_starts_blank: bool,
    line_no: u64,
}

fn nl_fd(fd: i32, st: &mut NlState, opts: &NlOpts) -> bool {
    let mut buf = [0u8; READ_BUF];
    let mut had_error = false;

    loop {
        let n = unsafe {
            syscall3(sysn::READ, fd as u64, buf.as_mut_ptr() as u64, buf.len() as u64)
        };
        if n < 0 { had_error = true; break; }
        if n == 0 { break; }
        let chunk = &buf[..n as usize];
        let mut start = 0usize;
        for i in 0..chunk.len() {
            let c = chunk[i];
            if c == opts.line_sep {
                let seg = &chunk[start..i + 1];
                let want_number = match opts.style {
                    BodyStyle::None => false,
                    BodyStyle::NonBlank => !st.line_starts_blank,
                    BodyStyle::All => true,
                };
                if !want_number || !st.at_line_start {
                    if !write_all(STDOUT, seg) { had_error = true; break; }
                } else {
                    st.line_no += opts.increment;
                    if !write_lineno(st.line_no, opts) { had_error = true; break; }
                    if !write_all(STDOUT, seg) { had_error = true; break; }
                }
                st.at_line_start = true;
                st.line_starts_blank = true;
                start = i + 1;
            } else if st.at_line_start && st.line_starts_blank {
                st.line_starts_blank = false;
            }
        }
        if had_error { break; }
        if start < chunk.len() {
            if st.at_line_start {
                let want_number = match opts.style {
                    BodyStyle::None => false,
                    BodyStyle::NonBlank => !st.line_starts_blank,
                    BodyStyle::All => true,
                };
                if want_number {
                    st.line_no += opts.increment;
                    if !write_lineno(st.line_no, opts) { had_error = true; break; }
                }
                st.at_line_start = false;
                st.line_starts_blank = false;
            }
            if !write_all(STDOUT, &chunk[start..]) { had_error = true; break; }
        }
    }
    !had_error
}

fn parse_u64_arg(p: *const u8) -> Option<u64> {
    let mut k = 0usize;
    let mut v: u64 = 0;
    let mut any = false;
    unsafe {
        while *p.add(k) != 0 {
            let c = *p.add(k);
            if !(b'0'..=b'9').contains(&c) { return None; }
            v = v.checked_mul(10)?.checked_add((c - b'0') as u64)?;
            any = true;
            k += 1;
        }
    }
    if any { Some(v) } else { None }
}

#[unsafe(no_mangle)]
pub extern "C" fn main(argc: i32, argv: *const *const u8, _envp: *const *const u8) -> i32 {
    let mut opts = NlOpts {
        line_sep: b'\n',
        style: BodyStyle::NonBlank,
        width: 6,
        sep: [0; 16],
        sep_len: 1,
        increment: 1,
        start: 1,
    };
    opts.sep[0] = b'\t';

    let mut idx: i32 = 1;
    while idx < argc {
        let p = unsafe { *argv.add(idx as usize) };
        if p.is_null() || (p as usize) < 0x10000 { break; }
        let mut nlen = 0usize;
        unsafe { while *p.add(nlen) != 0 { nlen += 1; } }

        // --help
        if nlen == 6 && unsafe {
            let want = b"--help";
            let mut ok = true;
            for i in 0..want.len() { if *p.add(i) != want[i] { ok = false; break; } }
            ok
        } {
            let help: &[u8] = b"\
Usage: rust-nl [-b STYLE] [-w WIDTH] [-s SEP] [-v N] [-i N] [FILE]...
Number text lines.

  -b STYLE   body number style: a (all), t (non-blank, default), n (none)
  -w WIDTH   line-number field width (default 6)
  -s SEP     separator between number and line (default TAB)
  -v N       initial line number (default 1)
  -i N       line-number increment (default 1)
  -z, --zero-terminated  line delimiter is NUL, not newline
      --help     show this help and exit

A '-' in the FILE list means standard input.
\0";
            let len = help.len() - 1;
            unsafe { let _ = syscall3(sysn::WRITE, STDOUT as u64,
                                      help.as_ptr() as u64, len as u64); }
            return 0;
        }

        // -z / --zero-terminated
        if (nlen == 2 && unsafe { *p == b'-' && *p.add(1) == b'z' })
            || (nlen == 17 && unsafe {
                let want = b"--zero-terminated";
                let mut ok = true;
                for j in 0..want.len() { if *p.add(j) != want[j] { ok = false; break; } }
                ok
            })
        {
            opts.line_sep = 0;
            idx += 1;
            continue;
        }
        // -b STYLE
        if nlen == 2 && unsafe { *p == b'-' && *p.add(1) == b'b' } {
            if idx + 1 >= argc {
                write_str(STDERR, b"rust-nl: -b needs a style\n");
                return 1;
            }
            let arg = unsafe { *argv.add((idx + 1) as usize) };
            if arg.is_null() || (arg as usize) < 0x10000 { return 1; }
            let style = unsafe { *arg };
            opts.style = match style {
                b'a' => BodyStyle::All,
                b't' => BodyStyle::NonBlank,
                b'n' => BodyStyle::None,
                _ => {
                    write_str(STDERR, b"rust-nl: -b expects a/t/n\n");
                    return 1;
                }
            };
            idx += 2;
            continue;
        }
        // -w WIDTH
        if nlen == 2 && unsafe { *p == b'-' && *p.add(1) == b'w' } {
            if idx + 1 >= argc { return 1; }
            let arg = unsafe { *argv.add((idx + 1) as usize) };
            if arg.is_null() || (arg as usize) < 0x10000 { return 1; }
            match parse_u64_arg(arg) {
                Some(v) if v > 0 && v < 32 => opts.width = v as u32,
                _ => {
                    write_str(STDERR, b"rust-nl: -w needs a positive width <32\n");
                    return 1;
                }
            }
            idx += 2;
            continue;
        }
        // -s SEP
        if nlen == 2 && unsafe { *p == b'-' && *p.add(1) == b's' } {
            if idx + 1 >= argc { return 1; }
            let arg = unsafe { *argv.add((idx + 1) as usize) };
            if arg.is_null() || (arg as usize) < 0x10000 { return 1; }
            let mut k = 0usize;
            unsafe {
                while *arg.add(k) != 0 && k < opts.sep.len() {
                    opts.sep[k] = *arg.add(k);
                    k += 1;
                }
            }
            opts.sep_len = k as u32;
            idx += 2;
            continue;
        }
        // -v N
        if nlen == 2 && unsafe { *p == b'-' && *p.add(1) == b'v' } {
            if idx + 1 >= argc { return 1; }
            let arg = unsafe { *argv.add((idx + 1) as usize) };
            if arg.is_null() || (arg as usize) < 0x10000 { return 1; }
            match parse_u64_arg(arg) {
                Some(v) => opts.start = v,
                None => {
                    write_str(STDERR, b"rust-nl: -v needs a non-negative integer\n");
                    return 1;
                }
            }
            idx += 2;
            continue;
        }
        // -i N
        if nlen == 2 && unsafe { *p == b'-' && *p.add(1) == b'i' } {
            if idx + 1 >= argc { return 1; }
            let arg = unsafe { *argv.add((idx + 1) as usize) };
            if arg.is_null() || (arg as usize) < 0x10000 { return 1; }
            match parse_u64_arg(arg) {
                Some(v) if v > 0 => opts.increment = v,
                _ => {
                    write_str(STDERR, b"rust-nl: -i needs a positive integer\n");
                    return 1;
                }
            }
            idx += 2;
            continue;
        }
        if nlen == 2 && unsafe { *p == b'-' && *p.add(1) == b'-' } {
            idx += 1;
            break;
        }
        break;
    }

    // Pre-bias the counter by (start - increment) so the first
    // increment lands on `start`.
    let mut st = NlState {
        at_line_start: true,
        line_starts_blank: true,
        line_no: opts.start.saturating_sub(opts.increment),
    };
    let mut had_error = false;

    if idx >= argc {
        if !nl_fd(STDIN, &mut st, &opts) { had_error = true; }
    } else {
        for ai in idx..argc {
            let p = unsafe { *argv.add(ai as usize) };
            if p.is_null() || (p as usize) < 0x10000 {
                had_error = true;
                continue;
            }
            let mut nlen = 0usize;
            unsafe { while *p.add(nlen) != 0 { nlen += 1; } }
            let is_dash = nlen == 1 && unsafe { *p } == b'-';
            if is_dash {
                if !nl_fd(STDIN, &mut st, &opts) { had_error = true; }
                continue;
            }
            let fd = unsafe {
                syscall4(sysn::OPENAT, AT_FDCWD as u64, p as u64, O_RDONLY, 0) as i32
            };
            if fd < 0 {
                write_str(STDERR, b"rust-nl: cannot open '");
                unsafe { let _ = syscall3(sysn::WRITE, STDERR as u64, p as u64, nlen as u64); }
                write_str(STDERR, b"'\n");
                had_error = true;
                continue;
            }
            if !nl_fd(fd, &mut st, &opts) { had_error = true; }
            unsafe { let _ = syscall1(sysn::CLOSE, fd as u64); }
        }
    }

    if had_error { 1 } else { 0 }
}
