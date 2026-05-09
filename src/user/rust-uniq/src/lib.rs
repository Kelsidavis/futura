// SPDX-License-Identifier: MPL-2.0
//
// rust-uniq — collapse adjacent duplicate lines from stdin.
//
//   rust-uniq          collapse adjacent duplicates
//   rust-uniq -c       prefix each output line with its run length
//   rust-uniq -d       only print lines that are duplicated (run > 1)
//   rust-uniq -u       only print lines that occur exactly once
//
// Stream-style: keeps just the previous line (up to MAX_LINE bytes)
// and a run counter. No allocator, fixed-size buffers. Lines longer
// than MAX_LINE are split — each chunk is treated as its own "line"
// for comparison purposes, which matches GNU uniq's behaviour with
// very long lines on a constrained reader.

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

const MAX_LINE: usize = 4096;
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
    write_str(STDERR, b"[rust-uniq] panic\n");
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

fn slice_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    for i in 0..a.len() {
        if a[i] != b[i] {
            return false;
        }
    }
    true
}

#[inline(always)]
fn to_lower(b: u8) -> u8 {
    if b >= b'A' && b <= b'Z' { b + 32 } else { b }
}

fn slice_eq_icase(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() { return false; }
    for i in 0..a.len() {
        if to_lower(a[i]) != to_lower(b[i]) { return false; }
    }
    true
}

#[derive(Copy, Clone)]
struct Mode {
    show_count: bool,
    only_dups: bool,
    only_uniq: bool,
    icase: bool,
    skip_chars: usize,           // -s N: skip first N chars before compare
    cmp_chars: Option<usize>,    // -w N: compare at most first N chars (after skip)
}

// Slice the comparison window out of a line per -s/-w. Lines shorter
// than the skip prefix collapse to an empty window, which (correctly)
// makes every such line equal to every other under uniq.
fn cmp_window<'a>(line: &'a [u8], skip: usize, take: Option<usize>) -> &'a [u8] {
    if skip >= line.len() { return &line[..0]; }
    let rest = &line[skip..];
    match take {
        Some(n) => &rest[..n.min(rest.len())],
        None => rest,
    }
}

// Print one accumulated line according to mode.
fn emit(mode: Mode, line: &[u8], count: u64) -> bool {
    if mode.only_dups && count < 2 {
        return true;
    }
    if mode.only_uniq && count != 1 {
        return true;
    }
    if mode.show_count {
        // 7-char right-aligned count + space + line, like GNU uniq -c.
        let mut buf = [b' '; 8];
        let mut n = count;
        let mut i = 7usize;
        if n == 0 {
            buf[7] = b'0';
        } else {
            while n > 0 && i > 0 {
                i -= 1;
                buf[i] = b'0' + (n % 10) as u8;
                n /= 10;
            }
        }
        if !write_all(STDOUT, &buf) {
            return false;
        }
        if !write_all(STDOUT, b" ") {
            return false;
        }
    }
    if !write_all(STDOUT, line) {
        return false;
    }
    write_all(STDOUT, b"\n")
}

#[unsafe(no_mangle)]
pub extern "C" fn main(argc: i32, argv: *const *const u8, _envp: *const *const u8) -> i32 {
    let mut mode = Mode {
        show_count: false,
        only_dups: false,
        only_uniq: false,
        icase: false,
        skip_chars: 0,
        cmp_chars: None,
    };
    let mut input_fd: i32 = STDIN;
    let mut input_path: Option<*const u8> = None;
    let mut i = 1;
    while i < argc {
        let p = unsafe { *argv.add(i as usize) };
        if p.is_null() || (p as usize) < 0x10000 {
            i += 1;
            continue;
        }
        if cstr_eq(p, b"-c") {
            mode.show_count = true;
        } else if cstr_eq(p, b"-d") {
            mode.only_dups = true;
        } else if cstr_eq(p, b"-u") {
            mode.only_uniq = true;
        } else if cstr_eq(p, b"-i") {
            mode.icase = true;
        } else if cstr_eq(p, b"-s") || cstr_eq(p, b"-w") {
            // -s N (skip first N chars) / -w N (compare at most N chars).
            // Both take a non-negative integer in the next argv slot.
            let kind = unsafe { *p.add(1) };  // 's' or 'w'
            if i + 1 >= argc {
                write_str(STDERR, b"rust-uniq: -s / -w needs a non-negative integer\n");
                return 2;
            }
            let np = unsafe { *argv.add((i + 1) as usize) };
            if np.is_null() || (np as usize) < 0x10000 {
                return 2;
            }
            let mut nn = 0usize;
            unsafe { while *np.add(nn) != 0 { nn += 1; } }
            let mut v: usize = 0;
            let mut ok = nn > 0;
            for k in 0..nn {
                let c = unsafe { *np.add(k) };
                if !(b'0'..=b'9').contains(&c) { ok = false; break; }
                let (mv, of1) = v.overflowing_mul(10);
                let (av, of2) = mv.overflowing_add((c - b'0') as usize);
                if of1 || of2 { ok = false; break; }
                v = av;
            }
            if !ok {
                write_str(STDERR, b"rust-uniq: invalid -s / -w value\n");
                return 2;
            }
            if kind == b's' { mode.skip_chars = v; }
            else            { mode.cmp_chars = Some(v); }
            i += 2;
            continue;
        } else if cstr_eq(p, b"--help") {
            let help: &[u8] = b"\
Usage: rust-uniq [OPTION]... [INPUT]
Filter adjacent matching lines from INPUT (or standard input).

  -c          prefix lines with their occurrence count
  -d          show only duplicated lines
  -u          show only unique lines
  -i          ignore case while comparing
  -s N        skip first N chars before comparing
  -w N        compare at most N chars (after -s skip)
      --help  show this help and exit

A '-' as INPUT means standard input.
\0";
            let len = help.len() - 1;
            unsafe { let _ = syscall3(sysn::WRITE, STDOUT as u64,
                                       help.as_ptr() as u64, len as u64); }
            return 0;
        } else if cstr_eq(p, b"--") {
            i += 1;
            // Next non-null token is the INPUT file (if any).
            if i < argc {
                let q = unsafe { *argv.add(i as usize) };
                if !q.is_null() && (q as usize) >= 0x10000 {
                    input_path = Some(q);
                }
            }
            break;
        } else {
            // First non-flag token is the INPUT file. GNU uniq accepts
            // [INPUT [OUTPUT]]; we only honour INPUT for now (OUTPUT
            // would need O_WRONLY/O_CREAT plumbing for marginal benefit).
            input_path = Some(p);
            break;
        }
        i += 1;
    }
    if mode.only_dups && mode.only_uniq {
        // GNU uniq treats -d -u as "print nothing" (each line falls
        // foul of one of the two filters). Mirror that.
    }

    if let Some(p) = input_path {
        // "-" still means stdin (matches GNU uniq).
        let mut nlen = 0usize;
        unsafe { while *p.add(nlen) != 0 { nlen += 1; } }
        let is_dash = nlen == 1 && unsafe { *p } == b'-';
        if !is_dash {
            let f = unsafe {
                syscall4(sysn::OPENAT, AT_FDCWD as u64, p as u64, O_RDONLY, 0) as i32
            };
            if f < 0 {
                write_str(STDERR, b"rust-uniq: cannot open '");
                unsafe { let _ = syscall3(sysn::WRITE, STDERR as u64, p as u64, nlen as u64); }
                write_str(STDERR, b"'\n");
                return 1;
            }
            input_fd = f;
        }
    }

    // State for the running line.
    let mut prev = [0u8; MAX_LINE];
    let mut prev_len = 0usize;
    let mut prev_valid = false;
    let mut count: u64 = 0;

    // Line accumulator for the line currently being built.
    let mut cur = [0u8; MAX_LINE];
    let mut cur_len = 0usize;

    let mut rbuf = [0u8; READ_BUF];
    let mut had_error = false;

    'outer: loop {
        let n = unsafe {
            syscall3(sysn::READ, input_fd as u64, rbuf.as_mut_ptr() as u64, rbuf.len() as u64)
        };
        if n < 0 {
            had_error = true;
            break;
        }
        if n == 0 {
            break;
        }
        let chunk = &rbuf[..n as usize];
        let mut start = 0usize;
        for i in 0..chunk.len() {
            if chunk[i] == b'\n' {
                // Append [start..i] to cur, then flush this line.
                let take = i - start;
                let copy = take.min(cur.len() - cur_len);
                cur[cur_len..cur_len + copy].copy_from_slice(&chunk[start..start + copy]);
                cur_len += copy;
                let line = &cur[..cur_len];
                let l_win = cmp_window(line, mode.skip_chars, mode.cmp_chars);
                let p_win = cmp_window(&prev[..prev_len], mode.skip_chars, mode.cmp_chars);
                let same = if mode.icase {
                    slice_eq_icase(l_win, p_win)
                } else {
                    slice_eq(l_win, p_win)
                };
                if prev_valid && same {
                    count += 1;
                } else {
                    if prev_valid {
                        if !emit(mode, &prev[..prev_len], count) {
                            had_error = true;
                            break 'outer;
                        }
                    }
                    let new_len = line.len().min(prev.len());
                    prev[..new_len].copy_from_slice(&line[..new_len]);
                    prev_len = new_len;
                    prev_valid = true;
                    count = 1;
                }
                cur_len = 0;
                start = i + 1;
            }
        }
        // Trailing fragment carries over.
        if start < chunk.len() {
            let take = chunk.len() - start;
            let copy = take.min(cur.len() - cur_len);
            cur[cur_len..cur_len + copy].copy_from_slice(&chunk[start..start + copy]);
            cur_len += copy;
        }
    }

    // Flush any line that didn't end with newline (treat its bytes as
    // the final line).
    if cur_len > 0 {
        let line = &cur[..cur_len];
        let l_win = cmp_window(line, mode.skip_chars, mode.cmp_chars);
        let p_win = cmp_window(&prev[..prev_len], mode.skip_chars, mode.cmp_chars);
        let same = if mode.icase {
            slice_eq_icase(l_win, p_win)
        } else {
            slice_eq(l_win, p_win)
        };
        if prev_valid && same {
            count += 1;
        } else {
            if prev_valid {
                if !emit(mode, &prev[..prev_len], count) {
                    had_error = true;
                }
            }
            let new_len = line.len().min(prev.len());
            prev[..new_len].copy_from_slice(&line[..new_len]);
            prev_len = new_len;
            prev_valid = true;
            count = 1;
        }
    }

    if prev_valid && !had_error {
        if !emit(mode, &prev[..prev_len], count) {
            had_error = true;
        }
    }

    if input_fd != STDIN {
        unsafe { let _ = syscall1(sysn::CLOSE, input_fd as u64); }
    }
    if had_error { 1 } else { 0 }
}
