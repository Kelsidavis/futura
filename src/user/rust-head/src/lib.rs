// SPDX-License-Identifier: MPL-2.0
//
// rust-head — thirteenth user-space Rust program for Futura OS.
//
// Prints the first N lines of each file (or stdin if no files).
// Default is 10 lines like GNU head. Pass `-n NUM` to override.
// Reads in 4 KiB chunks and counts '\n' bytes; once N have been
// emitted on the current file, the rest of that file is skipped.
//
// Header printing for multiple files defaults to "auto" (only when
// >1 file). `-q` (or `--quiet`/`--silent`) suppresses headers always;
// `-v` (`--verbose`) forces them on even for a single file.

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
const DEFAULT_LINES: u64 = 10;

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

fn parse_u64(p: *const u8) -> Option<u64> {
    let n = cstr_len(p);
    if n == 0 {
        return None;
    }
    let mut v: u64 = 0;
    for i in 0..n {
        let b = unsafe { *p.add(i) };
        if !(b'0'..=b'9').contains(&b) {
            return None;
        }
        v = v.checked_mul(10)?.checked_add((b - b'0') as u64)?;
    }
    Some(v)
}

#[panic_handler]
fn panic(_info: &PanicInfo) -> ! {
    write_str(STDERR, b"[rust-head] panic\n");
    unsafe {
        sys_exit(1);
    }
}

// Pump fd -> stdout, stopping after `limit` newlines.
// Returns Ok(())/Err(()) — on read error returns Err.
fn head_fd(fd: i32, limit: u64, buf: &mut [u8]) -> Result<(), ()> {
    let mut printed: u64 = 0;
    while printed < limit {
        let n = unsafe {
            syscall3(
                sysn::READ,
                fd as u64,
                buf.as_mut_ptr() as u64,
                buf.len() as u64,
            )
        };
        if n == 0 {
            return Ok(());
        }
        if n < 0 {
            return Err(());
        }
        let bytes = n as usize;
        // Walk buf, count '\n', stop at the chunk boundary that hits the limit.
        let mut emit_to = 0usize;
        for i in 0..bytes {
            emit_to = i + 1;
            if buf[i] == b'\n' {
                printed += 1;
                if printed >= limit {
                    break;
                }
            }
        }
        if !write_all(STDOUT, &buf[..emit_to]) {
            return Err(());
        }
    }
    Ok(())
}

// Byte-mode equivalent of head_fd: pump up to `limit` bytes total to
// stdout. Used by `head -c N`.
fn head_fd_bytes(fd: i32, limit: u64, buf: &mut [u8]) -> Result<(), ()> {
    let mut sent: u64 = 0;
    while sent < limit {
        let want = (limit - sent).min(buf.len() as u64) as usize;
        let n = unsafe {
            syscall3(sysn::READ, fd as u64, buf.as_mut_ptr() as u64, want as u64)
        };
        if n == 0 { return Ok(()); }
        if n < 0  { return Err(()); }
        if !write_all(STDOUT, &buf[..n as usize]) { return Err(()); }
        sent += n as u64;
    }
    Ok(())
}

#[derive(Copy, Clone, PartialEq, Eq)]
enum HeaderMode { Auto, Quiet, Verbose }

#[unsafe(no_mangle)]
pub extern "C" fn main(argc: i32, argv: *const *const u8, _envp: *const *const u8) -> i32 {
    let mut idx: usize = 1;
    let mut limit: u64 = DEFAULT_LINES;
    let mut byte_limit: Option<u64> = None;
    let mut hmode = HeaderMode::Auto;

    // Parse `-n N`, `-c N`, and `-N` (GNU shorthand).
    while let Some(p) = argv_get(argc, argv, idx) {
        if arg_is(p, b"--help") {
            let help: &[u8] = b"\
Usage: rust-head [OPTION]... [FILE]...
Print the first 10 lines of each FILE to standard output. With more
than one FILE, precede each with a header. With no FILE, read stdin.

  -c, --bytes=NUM        print the first NUM bytes (instead of lines)
  -n, --lines=NUM        print the first NUM lines (default: 10)
  -q, --quiet, --silent  never print headers
  -v, --verbose          always print headers
      --help             show this help and exit

A single '-' in the FILE list means standard input.
\0";
            let len = help.len() - 1;
            unsafe { let _ = syscall3(sysn::WRITE, STDOUT as u64,
                                       help.as_ptr() as u64, len as u64); }
            return 0;
        }
        if arg_is(p, b"-q") || arg_is(p, b"--quiet") || arg_is(p, b"--silent") {
            hmode = HeaderMode::Quiet;
            idx += 1;
            continue;
        }
        if arg_is(p, b"-v") || arg_is(p, b"--verbose") {
            hmode = HeaderMode::Verbose;
            idx += 1;
            continue;
        }
        if arg_is(p, b"-c") {
            idx += 1;
            match argv_get(argc, argv, idx) {
                Some(np) => match parse_u64(np) {
                    Some(v) => {
                        byte_limit = Some(v);
                        idx += 1;
                    }
                    None => {
                        write_str(STDERR, b"rust-head: -c needs a non-negative integer\n");
                        return 1;
                    }
                },
                None => {
                    write_str(STDERR, b"rust-head: -c needs an argument\n");
                    return 1;
                }
            }
            continue;
        }
        if arg_is(p, b"-n") {
            idx += 1;
            match argv_get(argc, argv, idx) {
                Some(np) => match parse_u64(np) {
                    Some(v) => {
                        limit = v;
                        idx += 1;
                    }
                    None => {
                        write_str(STDERR, b"rust-head: -n needs a non-negative integer\n");
                        return 1;
                    }
                },
                None => {
                    write_str(STDERR, b"rust-head: -n needs an argument\n");
                    return 1;
                }
            }
        } else if arg_is(p, b"--") {
            idx += 1;
            break;
        } else {
            // -<NUM> shorthand: GNU `head -5` means head -n 5.
            // Bounds-check: must be at least 2 bytes (`-` + a digit) and
            // start with `-` followed by a digit. Without the explicit
            // length check, an empty argv string lets us read past its
            // NUL terminator into adjacent memory.
            let n = cstr_len(p);
            if n >= 2 && unsafe { *p } == b'-'
                && (b'0'..=b'9').contains(&unsafe { *p.add(1) })
            {
                // Skip the leading '-' for parse_u64.
                let mut tmp = [0u8; 32];
                if n - 1 >= tmp.len() {
                    write_str(STDERR, b"rust-head: numeric arg too long\n");
                    return 1;
                }
                for i in 1..n {
                    tmp[i - 1] = unsafe { *p.add(i) };
                }
                tmp[n - 1] = 0;
                match parse_u64(tmp.as_ptr()) {
                    Some(v) => {
                        limit = v;
                        idx += 1;
                    }
                    None => break,
                }
            } else {
                break;
            }
        }
    }

    let mut buf = [0u8; BUF_LEN];
    let mut had_error = false;

    let run = |fd: i32, buf: &mut [u8]| -> Result<(), ()> {
        match byte_limit {
            Some(b) => head_fd_bytes(fd, b, buf),
            None    => head_fd(fd, limit, buf),
        }
    };

    if (idx as i32) >= argc {
        if run(STDIN, &mut buf).is_err() {
            had_error = true;
        }
    } else {
        // Count files first to decide whether to print "==> name <==" headers.
        let mut file_count: i32 = 0;
        let mut probe = idx;
        while argv_get(argc, argv, probe).is_some() {
            file_count += 1;
            probe += 1;
        }

        let mut first = true;
        let stdin_label: &[u8] = b"standard input";
        while let Some(p) = argv_get(argc, argv, idx) {
            let n = cstr_len(p);
            // "-" reads stdin; the header label is the conventional
            // "==> standard input <==".
            let is_dash = n == 1 && unsafe { *p } == b'-';
            let (fd, opened_owned, header_ptr, header_len) = if is_dash {
                (STDIN, false, stdin_label.as_ptr(), stdin_label.len())
            } else {
                let f = unsafe { sys_open_ro(p) };
                if f < 0 {
                    write_str(STDERR, b"rust-head: cannot open '");
                    unsafe {
                        let _ = syscall3(sysn::WRITE, STDERR as u64, p as u64, n as u64);
                    }
                    write_str(STDERR, b"'\n");
                    had_error = true;
                    idx += 1;
                    continue;
                }
                (f as i32, true, p, n)
            };
            let show_header = match hmode {
                HeaderMode::Quiet => false,
                HeaderMode::Verbose => true,
                HeaderMode::Auto => file_count > 1,
            };
            if show_header {
                if !first {
                    write_str(STDOUT, b"\n");
                }
                write_str(STDOUT, b"==> ");
                unsafe {
                    let _ = syscall3(sysn::WRITE, STDOUT as u64, header_ptr as u64, header_len as u64);
                }
                write_str(STDOUT, b" <==\n");
            }
            first = false;
            if run(fd, &mut buf).is_err() {
                had_error = true;
            }
            if opened_owned {
                unsafe { let _ = syscall1(sysn::CLOSE, fd as u64); }
            }
            idx += 1;
        }
    }

    if had_error { 1 } else { 0 }
}
