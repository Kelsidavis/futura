// SPDX-License-Identifier: MPL-2.0
//
// rust-cut — split each input line on a delimiter and emit selected
// fields.
//
//   rust-cut -d <delim> -f <list>
//
// <delim> is a single byte (e.g. ',', ':', '\t' via -d $'\t').
// <list> is a comma-separated set of 1-based field numbers, e.g.
// "1,3,5". Ranges (1-3) are TBD.
//
// Reads stdin if no FILE args; otherwise processes each FILE in turn,
// matching `cut -d , -f 1 a b c`. Lines
// without the delimiter are passed through unchanged (matching
// GNU cut's default unless -s is given; -s isn't implemented yet).

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
const LINE_BUF: usize = 8192;
const MAX_FIELDS: usize = 32;

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
    write_str(STDERR, b"[rust-cut] panic\n");
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

// Parse "1,3,5" into a sorted, dedup'd list of 1-based field numbers.
// Returns None on any parse error or overflow.
fn parse_fields(p: *const u8, out: &mut [u32; MAX_FIELDS]) -> Option<usize> {
    let mut n = 0usize;
    unsafe { while *p.add(n) != 0 { n += 1; } }
    let s = unsafe { core::slice::from_raw_parts(p, n) };
    if s.is_empty() {
        return None;
    }
    let mut count = 0usize;
    let mut start = 0usize;
    for i in 0..=s.len() {
        let at_end = i == s.len();
        if at_end || s[i] == b',' {
            let tok = &s[start..i];
            if tok.is_empty() {
                return None;
            }
            let mut v: u64 = 0;
            for &c in tok {
                if !(b'0'..=b'9').contains(&c) {
                    return None;
                }
                v = v * 10 + (c - b'0') as u64;
                if v > u32::MAX as u64 {
                    return None;
                }
            }
            if v == 0 {
                return None; // 1-based
            }
            if count >= MAX_FIELDS {
                return None;
            }
            out[count] = v as u32;
            count += 1;
            start = i + 1;
        }
    }
    // Sort ascending for deterministic output (we then dedup).
    for i in 1..count {
        let mut j = i;
        while j > 0 && out[j - 1] > out[j] {
            out.swap(j - 1, j);
            j -= 1;
        }
    }
    let mut w = 1usize;
    for r in 1..count {
        if out[r] != out[w - 1] {
            out[w] = out[r];
            w += 1;
        }
    }
    Some(w)
}

// Emit selected fields from `line`, splitting on `delim`, joining with
// `delim` between emitted fields.
fn emit_line(line: &[u8], delim: u8, fields: &[u32]) -> bool {
    if fields.is_empty() {
        return write_all(STDOUT, b"\n");
    }
    // Walk the line and collect [start..end) for each field.
    let mut idx_field: u32 = 1;
    let mut field_start = 0usize;
    let mut printed_any = false;
    let mut field_present = false;
    for (i, &b) in line.iter().enumerate() {
        if b == delim {
            field_present = true;
            if fields.contains(&idx_field) {
                if printed_any {
                    if !write_all(STDOUT, &[delim]) { return false; }
                }
                if !write_all(STDOUT, &line[field_start..i]) { return false; }
                printed_any = true;
            }
            idx_field += 1;
            field_start = i + 1;
        }
    }
    // Last field (after the last delim, or the whole line if no delim).
    if !field_present {
        // No delim in line: GNU cut default emits the whole line.
        if !write_all(STDOUT, line) { return false; }
    } else if fields.contains(&idx_field) {
        if printed_any {
            if !write_all(STDOUT, &[delim]) { return false; }
        }
        if !write_all(STDOUT, &line[field_start..]) { return false; }
    }
    write_all(STDOUT, b"\n")
}

#[unsafe(no_mangle)]
pub extern "C" fn main(argc: i32, argv: *const *const u8, _envp: *const *const u8) -> i32 {
    let mut delim: Option<u8> = None;
    let mut fields = [0u32; MAX_FIELDS];
    let mut nfields = 0usize;
    let mut idx: i32 = 1;

    while idx < argc {
        let p = unsafe { *argv.add(idx as usize) };
        if p.is_null() || (p as usize) < 0x10000 {
            idx += 1;
            continue;
        }
        if cstr_eq(p, b"-d") {
            if idx + 1 >= argc {
                write_str(STDERR, b"rust-cut: -d needs a delimiter\n");
                return 2;
            }
            let arg = unsafe { *argv.add((idx + 1) as usize) };
            if arg.is_null() || (arg as usize) < 0x10000 {
                return 2;
            }
            // Single byte delimiter.
            let b = unsafe { *arg };
            if b == 0 {
                return 2;
            }
            delim = Some(b);
            idx += 2;
        } else if cstr_eq(p, b"-f") {
            if idx + 1 >= argc {
                write_str(STDERR, b"rust-cut: -f needs a list\n");
                return 2;
            }
            let arg = unsafe { *argv.add((idx + 1) as usize) };
            if arg.is_null() || (arg as usize) < 0x10000 {
                return 2;
            }
            match parse_fields(arg, &mut fields) {
                Some(n) => nfields = n,
                None => {
                    write_str(STDERR, b"rust-cut: invalid -f list (1-based, comma-separated, no ranges yet)\n");
                    return 2;
                }
            }
            idx += 2;
        } else if cstr_eq(p, b"--") {
            idx += 1;
            break;
        } else {
            // First non-flag token starts the FILE list.
            break;
        }
    }
    let delim = match delim {
        Some(d) => d,
        None => {
            write_str(STDERR, b"rust-cut: -d <delim> required\n");
            return 2;
        }
    };
    if nfields == 0 {
        write_str(STDERR, b"rust-cut: -f <list> required\n");
        return 2;
    }
    let fields_slice = &fields[..nfields];

    if idx >= argc {
        return if cut_fd(STDIN, delim, fields_slice) { 0 } else { 1 };
    }
    let mut had_error = false;
    while idx < argc {
        let p = unsafe { *argv.add(idx as usize) };
        idx += 1;
        if p.is_null() || (p as usize) < 0x10000 {
            had_error = true;
            continue;
        }
        let mut nlen = 0usize;
        unsafe { while *p.add(nlen) != 0 { nlen += 1; } }
        let is_dash = nlen == 1 && unsafe { *p } == b'-';
        if is_dash {
            if !cut_fd(STDIN, delim, fields_slice) { had_error = true; }
            continue;
        }
        let fd = unsafe {
            syscall4(sysn::OPENAT, AT_FDCWD as u64, p as u64, O_RDONLY, 0) as i32
        };
        if fd < 0 {
            write_str(STDERR, b"rust-cut: cannot open '");
            unsafe { let _ = syscall3(sysn::WRITE, STDERR as u64, p as u64, nlen as u64); }
            write_str(STDERR, b"'\n");
            had_error = true;
            continue;
        }
        if !cut_fd(fd, delim, fields_slice) { had_error = true; }
        unsafe { let _ = syscall1(sysn::CLOSE, fd as u64); }
    }
    if had_error { 1 } else { 0 }
}

fn cut_fd(fd: i32, delim: u8, fields_slice: &[u32]) -> bool {
    let mut rbuf = [0u8; READ_BUF];
    let mut line = [0u8; LINE_BUF];
    let mut len = 0usize;
    let mut had_error = false;
    'outer: loop {
        let n = unsafe {
            syscall3(sysn::READ, fd as u64, rbuf.as_mut_ptr() as u64, rbuf.len() as u64)
        };
        if n < 0 { had_error = true; break; }
        if n == 0 { break; }
        let chunk = &rbuf[..n as usize];
        for &c in chunk {
            if c == b'\n' {
                if !emit_line(&line[..len], delim, fields_slice) {
                    had_error = true;
                    break 'outer;
                }
                len = 0;
            } else if len < LINE_BUF {
                line[len] = c;
                len += 1;
            }
            // Else: line too long; truncate silently (rare).
        }
    }
    if !had_error && len > 0 {
        if !emit_line(&line[..len], delim, fields_slice) { had_error = true; }
    }
    !had_error
}
