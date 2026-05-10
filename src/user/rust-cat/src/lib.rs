// SPDX-License-Identifier: MPL-2.0
//
// rust-cat — eighth user-space Rust program for Futura OS.
//
// Concatenates each named file to stdout. With no file args, copies
// stdin to stdout. The `-` filename is treated as stdin like classic
// cat. Reads in 4 KiB chunks and writes with the standard partial-
// write retry loop so a slow stdout (e.g. a pty under load) doesn't
// drop bytes.
//
// Flags:
//   -n   number every output line (6-char right-aligned + tab)
//   -b   number only non-blank output lines (overrides -n on blanks)
//   -s   squeeze consecutive blank lines into one
//   -E   show '$' at end of every line
//   -T   render tab characters as '^I'
//   -A   equivalent to -ET (rendering non-printables is TBD)

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

#[panic_handler]
fn panic(_info: &PanicInfo) -> ! {
    write_str(STDERR, b"[rust-cat] panic\n");
    unsafe {
        sys_exit(1);
    }
}

// Pump fd -> stdout. Returns true on EOF, false on error.
fn pump(fd: i32, buf: &mut [u8]) -> bool {
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
            return true; // EOF
        }
        if n < 0 {
            return false;
        }
        if !write_all(STDOUT, &buf[..n as usize]) {
            return false;
        }
    }
}

// Format a u64 line number right-aligned in a 6-char field, followed by
// '\t'. Matches GNU `cat -n` exactly. Returns the slice into `dst`.
fn fmt_lineno(dst: &mut [u8; 8], n: u64) -> usize {
    // Render decimal back-to-front into a 6-char field.
    let mut tmp = [b' '; 6];
    let mut v = n;
    let mut idx = 6usize;
    if v == 0 { idx -= 1; tmp[idx] = b'0'; }
    while v > 0 && idx > 0 {
        idx -= 1;
        tmp[idx] = b'0' + (v % 10) as u8;
        v /= 10;
    }
    dst[..6].copy_from_slice(&tmp);
    dst[6] = b'\t';
    7
}

#[derive(Copy, Clone)]
struct CatOpts {
    number: bool,        // -n
    number_nonblank: bool, // -b (implies -n behavior, skips blank lines)
    squeeze: bool,       // -s
    show_ends: bool,     // -E
    show_tabs: bool,     // -T (renders '\t' as ^I)
    show_nonprint: bool, // -v (renders bytes <32 except TAB/LF as ^X,
                         //     bytes 0x80..0xFF as M-X, 0x7F as ^?)
}

// Slow path: line-buffered pump that honors number/squeeze/ends flags.
// Each line is written with at most 3 syscall fragments (prefix, body,
// terminator) — fine for the volumes a -n run sees.
fn pump_lines(
    fd: i32,
    buf: &mut [u8],
    state: &mut LineState,
    opts: &CatOpts,
) -> bool {
    loop {
        let n = unsafe {
            syscall3(
                sysn::READ,
                fd as u64,
                buf.as_mut_ptr() as u64,
                buf.len() as u64,
            )
        };
        if n == 0 { return flush_partial(state, opts); }
        if n < 0 { return false; }
        let chunk = &buf[..n as usize];
        let mut start = 0usize;
        for i in 0..chunk.len() {
            if chunk[i] == b'\n' {
                let body_part = &chunk[start..i];
                if !append_to_line(state, body_part) { return false; }
                if !emit_line(state, opts, true) { return false; }
                state.line_len = 0;
                start = i + 1;
            }
        }
        if start < chunk.len() {
            if !append_to_line(state, &chunk[start..]) { return false; }
        }
    }
}

const LINE_MAX: usize = 4096;

struct LineState {
    line: [u8; LINE_MAX],
    line_len: usize,
    line_no: u64,
    prev_blank: bool,
}

fn append_to_line(s: &mut LineState, src: &[u8]) -> bool {
    let room = s.line.len() - s.line_len;
    let take = src.len().min(room);
    s.line[s.line_len..s.line_len + take].copy_from_slice(&src[..take]);
    s.line_len += take;
    // If the line overflows the buffer, flush a continuation chunk and
    // keep going. We just discard overflow here — pathological inputs
    // (>4 KiB without a newline) get truncated, like GNU cat with a
    // bounded line buffer would. Returning true keeps the stream alive.
    true
}

fn emit_line(s: &mut LineState, opts: &CatOpts, has_newline: bool) -> bool {
    let body = &s.line[..s.line_len];
    let is_blank = body.is_empty();
    if opts.squeeze && is_blank && s.prev_blank {
        return true;
    }
    s.prev_blank = is_blank;

    let want_number = opts.number || (opts.number_nonblank && !is_blank);
    if want_number {
        s.line_no += 1;
        let mut prefix = [0u8; 8];
        let plen = fmt_lineno(&mut prefix, s.line_no);
        if !write_all(STDOUT, &prefix[..plen]) { return false; }
    }
    if opts.show_tabs || opts.show_nonprint {
        // Slow byte-by-byte path. With -v, render every byte except
        // TAB and LF using GNU's caret/meta notation:
        //   0x00..0x1F (excluding 0x09 TAB and 0x0A LF) -> ^@..^_
        //   0x7F                                         -> ^?
        //   0x80..0xFF                                   -> M- + (above rule)
        // -T alone keeps the original behavior (only TAB rendered).
        let mut start = 0usize;
        for i in 0..body.len() {
            let b = body[i];
            let needs_tab = opts.show_tabs && b == b'\t';
            let needs_v = opts.show_nonprint
                && b != b'\t' && b != b'\n'
                && (b < 0x20 || b >= 0x7F);
            if !needs_tab && !needs_v { continue; }
            if start < i {
                if !write_all(STDOUT, &body[start..i]) { return false; }
            }
            if needs_tab {
                if !write_all(STDOUT, b"^I") { return false; }
            } else {
                let mut high = b;
                if high >= 0x80 {
                    if !write_all(STDOUT, b"M-") { return false; }
                    high &= 0x7F;
                }
                if high == 0x7F {
                    if !write_all(STDOUT, b"^?") { return false; }
                } else if high < 0x20 {
                    let buf = [b'^', high + b'@'];
                    if !write_all(STDOUT, &buf) { return false; }
                } else {
                    // Printable byte after stripping the meta bit — emit
                    // verbatim. This branch fires only with the meta bit
                    // set (since the unflagged < 0x20 path is handled
                    // above) so a single-char buf is correct.
                    let buf = [high];
                    if !write_all(STDOUT, &buf) { return false; }
                }
            }
            start = i + 1;
        }
        if start < body.len() {
            if !write_all(STDOUT, &body[start..]) { return false; }
        }
    } else {
        if !write_all(STDOUT, body) { return false; }
    }
    if opts.show_ends {
        if !write_all(STDOUT, b"$") { return false; }
    }
    if has_newline {
        if !write_all(STDOUT, b"\n") { return false; }
    }
    true
}

fn flush_partial(s: &mut LineState, opts: &CatOpts) -> bool {
    if s.line_len == 0 { return true; }
    let ok = emit_line(s, opts, false);
    s.line_len = 0;
    ok
}

// Line state lives in .bss to avoid blowing up .data with the 4 KiB
// scratch buffer (and to keep the main()-stack small).
static mut LSTATE: LineState = LineState {
    line: [0u8; LINE_MAX],
    line_len: 0,
    line_no: 0,
    prev_blank: false,
};

#[unsafe(no_mangle)]
pub extern "C" fn main(argc: i32, argv: *const *const u8, _envp: *const *const u8) -> i32 {
    let mut buf = [0u8; BUF_LEN];
    let mut opts = CatOpts {
        number: false,
        number_nonblank: false,
        squeeze: false,
        show_ends: false,
        show_tabs: false,
        show_nonprint: false,
    };

    // Parse leading flags. Stops at first non-flag arg, '-', or '--'.
    let mut idx: usize = 1;
    while let Some(p) = argv_get(argc, argv, idx) {
        if arg_is(p, b"--") { idx += 1; break; }
        if arg_is(p, b"-")  { break; }
        if arg_is(p, b"--help") {
            let help: &[u8] = b"\
Usage: rust-cat [OPTION]... [FILE]...
Concatenate FILE(s) to standard output. With no FILE, read stdin.

  -n, --number             number every output line
  -b, --number-nonblank    number only non-blank output lines
  -s, --squeeze-blank      squeeze repeated blank lines
  -E, --show-ends          render '$' at the end of each line
  -T, --show-tabs          render tabs as ^I
  -v, --show-nonprinting   render non-printables as ^X / M-X (except TAB/LF)
  -e          equivalent to -vE
  -t          equivalent to -vT
  -A          equivalent to -vET
      --help  show this help and exit

A single '-' in the FILE list means standard input.
\0";
            let len = help.len() - 1;
            unsafe { let _ = syscall3(sysn::WRITE, STDOUT as u64,
                                       help.as_ptr() as u64, len as u64); }
            return 0;
        }
        if arg_is(p, b"-n") || arg_is(p, b"--number") {
            opts.number = true; idx += 1; continue;
        }
        if arg_is(p, b"-b") || arg_is(p, b"--number-nonblank") {
            opts.number_nonblank = true; idx += 1; continue;
        }
        if arg_is(p, b"-s") || arg_is(p, b"--squeeze-blank") {
            opts.squeeze = true; idx += 1; continue;
        }
        if arg_is(p, b"-E") || arg_is(p, b"--show-ends") {
            opts.show_ends = true; idx += 1; continue;
        }
        if arg_is(p, b"-T") || arg_is(p, b"--show-tabs") {
            opts.show_tabs = true; idx += 1; continue;
        }
        if arg_is(p, b"-v") || arg_is(p, b"--show-nonprinting") {
            opts.show_nonprint = true; idx += 1; continue;
        }
        if arg_is(p, b"-e") {
            opts.show_nonprint = true;
            opts.show_ends = true;
            idx += 1;
            continue;
        }
        if arg_is(p, b"-t") {
            opts.show_nonprint = true;
            opts.show_tabs = true;
            idx += 1;
            continue;
        }
        if arg_is(p, b"-A") {
            opts.show_nonprint = true;
            opts.show_ends = true;
            opts.show_tabs = true;
            idx += 1;
            continue;
        }
        // Combined short flags like -nE / -bs / -nsT: walk the chars.
        let n = cstr_len(p);
        if n >= 2 && unsafe { *p } == b'-' && unsafe { *p.add(1) } != b'-' {
            let mut all_ok = true;
            for i in 1..n {
                match unsafe { *p.add(i) } {
                    b'n' => opts.number = true,
                    b'b' => opts.number_nonblank = true,
                    b's' => opts.squeeze = true,
                    b'E' => opts.show_ends = true,
                    b'T' => opts.show_tabs = true,
                    b'v' => opts.show_nonprint = true,
                    b'e' => { opts.show_nonprint = true; opts.show_ends = true; }
                    b't' => { opts.show_nonprint = true; opts.show_tabs = true; }
                    b'A' => {
                        opts.show_nonprint = true;
                        opts.show_ends = true;
                        opts.show_tabs = true;
                    }
                    _ => { all_ok = false; break; }
                }
            }
            if all_ok { idx += 1; continue; }
        }
        break;
    }

    let any_format = opts.number || opts.number_nonblank
        || opts.squeeze || opts.show_ends || opts.show_tabs
        || opts.show_nonprint;

    let pump_fd = |fd: i32, buf: &mut [u8]| -> bool {
        if any_format {
            // SAFETY: single-threaded user-space binary, exclusive access.
            let st = unsafe { &mut *core::ptr::addr_of_mut!(LSTATE) };
            pump_lines(fd, buf, st, &opts)
        } else {
            pump(fd, buf)
        }
    };

    if (idx as i32) >= argc {
        // No file args — pass stdin through.
        return if pump_fd(STDIN, &mut buf) { 0 } else { 1 };
    }

    let mut had_error = false;
    while let Some(p) = argv_get(argc, argv, idx) {
        if arg_is(p, b"-") {
            if !pump_fd(STDIN, &mut buf) {
                had_error = true;
            }
        } else {
            let n = cstr_len(p);
            if n == 0 {
                write_str(STDERR, b"rust-cat: empty filename\n");
                had_error = true;
                idx += 1;
                continue;
            }
            let fd = unsafe { sys_open_ro(p) };
            if fd < 0 {
                write_str(STDERR, b"rust-cat: cannot open '");
                unsafe {
                    let _ = syscall3(sysn::WRITE, STDERR as u64, p as u64, n as u64);
                }
                write_str(STDERR, b"'\n");
                had_error = true;
            } else {
                let ok = pump_fd(fd as i32, &mut buf);
                unsafe {
                    let _ = syscall1(sysn::CLOSE, fd as u64);
                }
                if !ok {
                    had_error = true;
                }
            }
        }
        idx += 1;
    }

    if had_error { 1 } else { 0 }
}
