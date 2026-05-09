// SPDX-License-Identifier: MPL-2.0
//
// rust-grep — fifteenth user-space Rust program for Futura OS.
//
// Plain substring (not regex) search across files / stdin. Output
// format follows the GNU grep default:
//
//     <name>:<line>     when more than one file (or -H always-print)
//     <line>            when one file (or stdin)
//
// Flags:
//   -n         Prefix matches with line numbers (1-based).
//   -i         Case-insensitive ASCII match.
//   -v         Invert: print non-matching lines.
//   -H         Always print the file name (default for >1 file).
//   -h         Never print the file name.

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
const LINE_BUF: usize = 4096;

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

fn to_lower(b: u8) -> u8 {
    if b.is_ascii_uppercase() { b + 32 } else { b }
}

fn line_matches(line: &[u8], pat: &[u8], icase: bool) -> bool {
    if pat.is_empty() {
        return true;
    }
    if pat.len() > line.len() {
        return false;
    }
    let last = line.len() - pat.len();
    for i in 0..=last {
        let mut ok = true;
        for j in 0..pat.len() {
            let a = if icase { to_lower(line[i + j]) } else { line[i + j] };
            let b = if icase { to_lower(pat[j]) } else { pat[j] };
            if a != b {
                ok = false;
                break;
            }
        }
        if ok {
            return true;
        }
    }
    false
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

#[panic_handler]
fn panic(_info: &PanicInfo) -> ! {
    write_str(STDERR, b"[rust-grep] panic\n");
    unsafe {
        sys_exit(1);
    }
}

#[derive(Clone, Copy)]
struct Opts {
    show_lineno: bool,
    icase: bool,
    invert: bool,
    show_name: ShowName,
    // Output-mode flags. At most one of count/list/quiet should be set;
    // if multiple are given, precedence is quiet > list > count to match
    // GNU grep ("-q wins over -l wins over -c").
    count: bool,    // -c   print "<file>:<count>" per file
    list: bool,     // -l   print "<file>" if any match, then stop file
    quiet: bool,    // -q   no output at all, exit on first match
}

#[derive(Clone, Copy, PartialEq)]
enum ShowName {
    Auto,   // default: prefix when more than one file
    Always, // -H
    Never,  // -h
}

fn emit_match(name: Option<&[u8]>, lineno: u64, line: &[u8], opts: &Opts) {
    let prefix_name = match opts.show_name {
        ShowName::Always => name,
        ShowName::Never => None,
        ShowName::Auto => name,
    };
    if let Some(n) = prefix_name {
        write_all(STDOUT, n);
        write_all(STDOUT, b":");
    }
    if opts.show_lineno {
        let mut buf = [0u8; 24];
        let len = fmt_u64(lineno, &mut buf);
        write_all(STDOUT, &buf[..len]);
        write_all(STDOUT, b":");
    }
    write_all(STDOUT, line);
    if line.last().copied() != Some(b'\n') {
        write_all(STDOUT, b"\n");
    }
}

fn grep_fd(
    fd: i32,
    name: Option<&[u8]>,
    pat: &[u8],
    opts: &Opts,
    scratch: &mut [u8],
) -> Result<u64, ()> {
    let mut line = [0u8; LINE_BUF];
    let mut line_len = 0usize;
    let mut lineno: u64 = 0;
    let mut count: u64 = 0;
    let mut overflow = false;
    // -q / -l only need to know "did anything match yet"; once we've
    // proven that, more reads add nothing. Short-circuit by returning
    // early so a multi-GB log file isn't rescanned for nothing.
    let stop_after_first = opts.quiet || opts.list;
    let suppress_lines = opts.quiet || opts.list || opts.count;
    loop {
        let n = unsafe {
            syscall3(
                sysn::READ,
                fd as u64,
                scratch.as_mut_ptr() as u64,
                scratch.len() as u64,
            )
        };
        if n == 0 {
            break;
        }
        if n < 0 {
            return Err(());
        }
        let bytes = n as usize;
        for i in 0..bytes {
            let b = scratch[i];
            if line_len < line.len() {
                line[line_len] = b;
                line_len += 1;
            } else {
                overflow = true;
            }
            if b == b'\n' {
                lineno += 1;
                if !overflow {
                    let body = &line[..line_len];
                    let m = line_matches(body, pat, opts.icase);
                    if m != opts.invert {
                        if !suppress_lines {
                            emit_match(name, lineno, body, opts);
                        }
                        count += 1;
                        if stop_after_first { return Ok(count); }
                    }
                }
                line_len = 0;
                overflow = false;
            }
        }
    }
    // Trailing partial line (no newline at EOF).
    if line_len > 0 {
        lineno += 1;
        let body = &line[..line_len];
        let m = line_matches(body, pat, opts.icase);
        if m != opts.invert {
            if !suppress_lines {
                emit_match(name, lineno, body, opts);
            }
            count += 1;
        }
    }
    Ok(count)
}

#[unsafe(no_mangle)]
pub extern "C" fn main(argc: i32, argv: *const *const u8, _envp: *const *const u8) -> i32 {
    let mut idx: usize = 1;
    let mut opts = Opts {
        show_lineno: false,
        icase: false,
        invert: false,
        show_name: ShowName::Auto,
        count: false,
        list: false,
        quiet: false,
    };

    while let Some(p) = argv_get(argc, argv, idx) {
        if arg_is(p, b"-n") {
            opts.show_lineno = true;
            idx += 1;
        } else if arg_is(p, b"-i") {
            opts.icase = true;
            idx += 1;
        } else if arg_is(p, b"-v") {
            opts.invert = true;
            idx += 1;
        } else if arg_is(p, b"-H") {
            opts.show_name = ShowName::Always;
            idx += 1;
        } else if arg_is(p, b"-h") {
            opts.show_name = ShowName::Never;
            idx += 1;
        } else if arg_is(p, b"-c") {
            opts.count = true;
            idx += 1;
        } else if arg_is(p, b"-l") {
            opts.list = true;
            idx += 1;
        } else if arg_is(p, b"-q") || arg_is(p, b"--quiet") || arg_is(p, b"--silent") {
            opts.quiet = true;
            idx += 1;
        } else if arg_is(p, b"--") {
            idx += 1;
            break;
        } else {
            break;
        }
    }

    let pat_ptr = match argv_get(argc, argv, idx) {
        Some(p) => p,
        None => {
            write_str(STDERR, b"usage: rust-grep [-niHhvclq] PATTERN [FILE...]\n");
            return 2;
        }
    };
    let pat_len = cstr_len(pat_ptr);
    let pat = unsafe { core::slice::from_raw_parts(pat_ptr, pat_len) };
    idx += 1;

    let mut scratch = [0u8; READ_BUF];
    let mut had_match = false;
    let mut had_error = false;

    let emit_count_line = |name: Option<&[u8]>, count: u64, show_name: bool| {
        if let Some(n) = name { if show_name {
            write_all(STDOUT, n);
            write_all(STDOUT, b":");
        }}
        let mut buf = [0u8; 24];
        let len = fmt_u64(count, &mut buf);
        write_all(STDOUT, &buf[..len]);
        write_all(STDOUT, b"\n");
    };

    if (idx as i32) >= argc {
        match grep_fd(STDIN, None, pat, &opts, &mut scratch) {
            Ok(c) => {
                if c > 0 { had_match = true; }
                if !opts.quiet {
                    if opts.list {
                        if c > 0 { write_all(STDOUT, b"(standard input)\n"); }
                    } else if opts.count {
                        emit_count_line(None, c, false);
                    }
                }
            }
            Err(_) => had_error = true,
        }
    } else {
        let mut file_count: i32 = 0;
        let mut probe = idx;
        while argv_get(argc, argv, probe).is_some() {
            file_count += 1;
            probe += 1;
        }
        let auto_name = file_count > 1;
        // Auto becomes Always or Never depending on file_count, but only
        // if user didn't override.
        let effective = if opts.show_name == ShowName::Auto {
            if auto_name { ShowName::Always } else { ShowName::Never }
        } else {
            opts.show_name
        };
        let show_name_count = effective == ShowName::Always;
        let opts2 = Opts { show_name: effective, ..opts };

        while let Some(p) = argv_get(argc, argv, idx) {
            let n = cstr_len(p);
            let fd = unsafe { sys_open_ro(p) };
            if fd < 0 {
                write_str(STDERR, b"rust-grep: cannot open '");
                unsafe {
                    let _ = syscall3(sysn::WRITE, STDERR as u64, p as u64, n as u64);
                }
                write_str(STDERR, b"'\n");
                had_error = true;
                idx += 1;
                continue;
            }
            let name = unsafe { core::slice::from_raw_parts(p, n) };
            match grep_fd(fd as i32, Some(name), pat, &opts2, &mut scratch) {
                Ok(c) => {
                    if c > 0 { had_match = true; }
                    if !opts.quiet {
                        if opts.list {
                            if c > 0 {
                                write_all(STDOUT, name);
                                write_all(STDOUT, b"\n");
                            }
                        } else if opts.count {
                            emit_count_line(Some(name), c, show_name_count);
                        }
                    }
                }
                Err(_) => had_error = true,
            }
            unsafe {
                let _ = syscall1(sysn::CLOSE, fd as u64);
            }
            idx += 1;
            // Quiet mode: bail as soon as anything has matched anywhere.
            if opts.quiet && had_match { break; }
        }
    }

    // Standard grep exit codes: 0 = match, 1 = no match, 2 = error.
    if had_error { 2 } else if had_match { 0 } else { 1 }
}
