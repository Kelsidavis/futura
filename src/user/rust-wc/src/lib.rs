// SPDX-License-Identifier: MPL-2.0
//
// rust-wc — ninth user-space Rust program for Futura OS.
//
// Counts newlines, whitespace-separated words, and bytes in each
// argument file (or stdin if none). Output format matches GNU wc
// when all three counts are requested:
//
//     <lines>  <words>  <bytes>  <name>
//
// Flags:
//   -l         Lines only
//   -w         Words only
//   -c         Bytes only
//
// Multiple flags combine; with no flag all three are printed.

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
const BUF_LEN: usize = 4096;

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
unsafe fn sys_open_ro(path: *const u8) -> i64 {
    unsafe { syscall4(sysn::OPENAT, AT_FDCWD as u64, path as u64, O_RDONLY, 0) }
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
unsafe fn sys_open_ro(path: *const u8) -> i64 {
    unsafe { syscall4(sysn::OPENAT, AT_FDCWD as u64, path as u64, O_RDONLY, 0) }
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

fn write_all(fd: i32, mut s: &[u8]) {
    while !s.is_empty() {
        let n = unsafe { syscall3(sysn::WRITE, fd as u64, s.as_ptr() as u64, s.len() as u64) };
        if n <= 0 {
            return;
        }
        s = &s[n as usize..];
    }
}

fn write_str(fd: i32, s: &[u8]) {
    write_all(fd, s);
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

fn arg_is(p: *const u8, want: &[u8]) -> bool {
    let n = cstr_len(p);
    if n != want.len() {
        return false;
    }
    for i in 0..n {
        if unsafe { *p.add(i) } != want[i] {
            return false;
        }
    }
    true
}

#[panic_handler]
fn panic(_info: &PanicInfo) -> ! {
    write_str(STDERR, b"[rust-wc] panic\n");
    unsafe {
        sys_exit(1);
    }
}

fn fmt_u64(mut n: u64, buf: &mut [u8]) -> usize {
    if n == 0 {
        if !buf.is_empty() {
            buf[0] = b'0';
            return 1;
        }
        return 0;
    }
    let mut tmp = [0u8; 20];
    let mut t = 0;
    while n > 0 && t < tmp.len() {
        tmp[t] = b'0' + (n % 10) as u8;
        n /= 10;
        t += 1;
    }
    let len = t.min(buf.len());
    for i in 0..len {
        buf[i] = tmp[t - 1 - i];
    }
    len
}

#[derive(Default, Clone, Copy)]
struct Counts {
    lines: u64,
    words: u64,
    bytes: u64,
    max_line: u64,
}

fn is_space(c: u8) -> bool {
    matches!(c, b' ' | b'\t' | b'\n' | b'\r' | b'\x0B' | b'\x0C')
}

fn count_fd(fd: i32, buf: &mut [u8]) -> Result<Counts, ()> {
    let mut c = Counts::default();
    let mut in_word = false;
    let mut cur_line: u64 = 0;
    loop {
        let n = unsafe {
            syscall3(
                sysn::READ,
                fd as u64,
                buf.as_mut_ptr() as u64,
                buf.len() as u64,
            )
        };
        if n == 0 {
            break;
        }
        if n < 0 {
            return Err(());
        }
        let n = n as usize;
        c.bytes += n as u64;
        for &b in &buf[..n] {
            if b == b'\n' {
                c.lines += 1;
                if cur_line > c.max_line { c.max_line = cur_line; }
                cur_line = 0;
            } else {
                cur_line += 1;
            }
            if is_space(b) {
                in_word = false;
            } else if !in_word {
                in_word = true;
                c.words += 1;
            }
        }
    }
    // Trailing line without newline still counts toward max line length.
    if cur_line > c.max_line { c.max_line = cur_line; }
    Ok(c)
}

fn print_counts(c: Counts, show: u8, name: Option<&[u8]>) {
    let mut numbuf = [0u8; 24];
    let mut wrote = false;
    if show & 1 != 0 {
        let n = fmt_u64(c.lines, &mut numbuf);
        write_all(STDOUT, &numbuf[..n]);
        wrote = true;
    }
    if show & 2 != 0 {
        if wrote {
            write_str(STDOUT, b"  ");
        }
        let n = fmt_u64(c.words, &mut numbuf);
        write_all(STDOUT, &numbuf[..n]);
        wrote = true;
    }
    if show & 4 != 0 {
        if wrote {
            write_str(STDOUT, b"  ");
        }
        let n = fmt_u64(c.bytes, &mut numbuf);
        write_all(STDOUT, &numbuf[..n]);
        wrote = true;
    }
    if show & 8 != 0 {
        if wrote {
            write_str(STDOUT, b"  ");
        }
        let n = fmt_u64(c.max_line, &mut numbuf);
        write_all(STDOUT, &numbuf[..n]);
        wrote = true;
    }
    let _ = wrote;
    if let Some(name) = name {
        write_str(STDOUT, b"  ");
        write_all(STDOUT, name);
    }
    write_str(STDOUT, b"\n");
}

#[unsafe(no_mangle)]
pub extern "C" fn main(argc: i32, argv: *const *const u8, _envp: *const *const u8) -> i32 {
    // --total=MODE controls the trailing "total" line. Auto matches
    // GNU wc's default (printed only for 2+ files).
    #[derive(Copy, Clone, PartialEq, Eq)]
    enum TotalMode { Auto, Always, Only, Never }
    let mut total_mode = TotalMode::Auto;
    let mut idx: usize = 1;
    let mut show: u8 = 0;
    while let Some(p) = argv_get(argc, argv, idx) {
        if arg_is(p, b"-l") {
            show |= 1;
            idx += 1;
        } else if arg_is(p, b"-w") {
            show |= 2;
            idx += 1;
        } else if arg_is(p, b"-c") {
            show |= 4;
            idx += 1;
        } else if arg_is(p, b"-m") {
            // For ASCII inputs `-m` (chars) equals `-c` (bytes).
            show |= 4;
            idx += 1;
        } else if arg_is(p, b"-L") || arg_is(p, b"--max-line-length") {
            show |= 8;
            idx += 1;
        } else if arg_is(p, b"--total=auto") {
            total_mode = TotalMode::Auto;   idx += 1;
        } else if arg_is(p, b"--total=always") {
            total_mode = TotalMode::Always; idx += 1;
        } else if arg_is(p, b"--total=only") {
            total_mode = TotalMode::Only;   idx += 1;
        } else if arg_is(p, b"--total=never") {
            total_mode = TotalMode::Never;  idx += 1;
        } else if arg_is(p, b"--") {
            idx += 1;
            break;
        } else if arg_is(p, b"--help") {
            let help: &[u8] = b"\
Usage: rust-wc [OPTION]... [FILE]...
Print newline, word, and byte counts for each FILE. Without -l/-w/-c
all three are shown. With multiple FILEs, also print a total.

  -l        count lines (newlines)
  -w        count whitespace-separated words
  -c        count bytes
  -m        count chars (same as -c for ASCII inputs)
  -L, --max-line-length   length of the longest line
      --total=MODE        when to print total: auto|always|only|never
                          (auto = only with multiple FILEs)
      --help    show this help and exit

A single '-' in the FILE list means standard input.
\0";
            let len = help.len() - 1;
            unsafe { let _ = syscall3(sysn::WRITE, STDOUT as u64,
                                       help.as_ptr() as u64, len as u64); }
            return 0;
        } else {
            break;
        }
    }
    if show == 0 {
        show = 1 | 2 | 4;
    }

    let mut buf = [0u8; BUF_LEN];
    let mut total = Counts::default();
    let mut had_error = false;

    if (idx as i32) >= argc {
        match count_fd(STDIN, &mut buf) {
            Ok(c) => print_counts(c, show, None),
            Err(_) => {
                write_str(STDERR, b"rust-wc: read error on stdin\n");
                had_error = true;
            }
        }
    } else {
        let mut file_count = 0;
        let mut start = idx;
        while let Some(_) = argv_get(argc, argv, start) {
            file_count += 1;
            start += 1;
        }

        let stdin_label: &[u8] = b"-";  // GNU wc keeps the literal "-" in its label
        while let Some(p) = argv_get(argc, argv, idx) {
            let n = cstr_len(p);
            // "-" reads stdin and is labelled as such in the per-line
            // output (matches GNU wc).
            let is_dash = n == 1 && unsafe { *p } == b'-';
            let (fd, opened_owned, name): (i32, bool, &[u8]) = if is_dash {
                (STDIN, false, stdin_label)
            } else {
                let f = unsafe { sys_open_ro(p) };
                if f < 0 {
                    write_str(STDERR, b"rust-wc: cannot open '");
                    unsafe {
                        let _ = syscall3(sysn::WRITE, STDERR as u64, p as u64, n as u64);
                    }
                    write_str(STDERR, b"'\n");
                    had_error = true;
                    idx += 1;
                    continue;
                }
                (f as i32, true, unsafe { core::slice::from_raw_parts(p, n) })
            };
            match count_fd(fd, &mut buf) {
                Ok(c) => {
                    total.lines += c.lines;
                    total.words += c.words;
                    total.bytes += c.bytes;
                    if c.max_line > total.max_line { total.max_line = c.max_line; }
                    if total_mode != TotalMode::Only {
                        print_counts(c, show, Some(name));
                    }
                }
                Err(_) => {
                    write_str(STDERR, b"rust-wc: read error\n");
                    had_error = true;
                }
            }
            if opened_owned {
                unsafe { let _ = syscall1(sysn::CLOSE, fd as u64); }
            }
            idx += 1;
        }

        let want_total = match total_mode {
            TotalMode::Auto   => file_count > 1,
            TotalMode::Always => true,
            TotalMode::Only   => true,
            TotalMode::Never  => false,
        };
        if want_total {
            print_counts(total, show, Some(b"total"));
        }
    }

    if had_error { 1 } else { 0 }
}
