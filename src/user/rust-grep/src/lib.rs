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
    pub const GETDENTS64: u64 = 61;
}

#[cfg(target_arch = "x86_64")]
mod sysn {
    pub const READ: u64 = 0;
    pub const WRITE: u64 = 1;
    pub const EXIT: u64 = 60;
    pub const OPENAT: u64 = 257;
    pub const CLOSE: u64 = 3;
    pub const GETDENTS64: u64 = 217;
}

const AT_FDCWD: i64 = -100;
const O_RDONLY: u64 = 0;
const O_DIRECTORY: u64 = 0o200_000;
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

fn is_word_byte(b: u8) -> bool {
    b.is_ascii_alphanumeric() || b == b'_'
}

fn line_matches(line: &[u8], pat: &[u8], icase: bool, word: bool, line_match: bool) -> bool {
    // Strip a single trailing '\n' from the body for `-x`'s
    // "whole-line" comparison — newline is part of the line in our
    // accumulator but isn't part of what the user types as the
    // pattern.
    let body: &[u8] = if line_match && line.last() == Some(&b'\n') {
        &line[..line.len() - 1]
    } else {
        line
    };
    if line_match {
        if pat.len() != body.len() { return false; }
        for j in 0..pat.len() {
            let a = if icase { to_lower(body[j]) } else { body[j] };
            let b = if icase { to_lower(pat[j]) } else { pat[j] };
            if a != b { return false; }
        }
        return true;
    }
    if pat.is_empty() {
        return true;
    }
    if pat.len() > body.len() {
        return false;
    }
    let last = body.len() - pat.len();
    for i in 0..=last {
        let mut ok = true;
        for j in 0..pat.len() {
            let a = if icase { to_lower(body[i + j]) } else { body[i + j] };
            let b = if icase { to_lower(pat[j]) } else { pat[j] };
            if a != b {
                ok = false;
                break;
            }
        }
        if !ok { continue; }
        if word {
            // Boundaries on both sides must NOT be word-bytes.
            let left_ok = i == 0 || !is_word_byte(body[i - 1]);
            let right_ok = i + pat.len() >= body.len()
                || !is_word_byte(body[i + pat.len()]);
            if !(left_ok && right_ok) { continue; }
        }
        return true;
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
    word: bool,
    line_match: bool,   // -x: pattern must match the whole line
    recursive: bool,    // -r: walk directories
    show_name: ShowName,
    // Output-mode flags. At most one of count/list/quiet should be set;
    // if multiple are given, precedence is quiet > list > count to match
    // GNU grep ("-q wins over -l wins over -c").
    count: bool,    // -c   print "<file>:<count>" per file
    list: bool,         // -l   print "<file>" if any match, then stop file
    list_no_match: bool,// -L   print "<file>" only if NO line matched
    quiet: bool,        // -q   no output at all, exit on first match
    max_count: u64,     // -m N (0 = unlimited)
    only_matching: bool,// -o   emit only the matched portion(s)
    after_ctx: u32,     // -A N: print N lines after each match
    before_ctx: u32,    // -B N: print N lines before each match (capped)
    null_term: bool,    // -Z/-z: NUL-terminate filenames in -l / -L output
}

const CTX_CAP: usize = 16;        // max before-context lines
const CTX_LINE: usize = 1024;     // max bytes captured per context line

#[derive(Clone, Copy, PartialEq)]
enum ShowName {
    Auto,   // default: prefix when more than one file
    Always, // -H
    Never,  // -h
}

fn emit_prefix(name: Option<&[u8]>, lineno: u64, opts: &Opts) {
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
}

fn emit_match(name: Option<&[u8]>, lineno: u64, line: &[u8], opts: &Opts) {
    emit_prefix(name, lineno, opts);
    write_all(STDOUT, line);
    if line.last().copied() != Some(b'\n') {
        write_all(STDOUT, b"\n");
    }
}

// Like emit_match but uses '-' instead of ':' between name/lineno —
// the GNU grep convention for -A/-B/-C context lines.
fn emit_context(name: Option<&[u8]>, lineno: u64, line: &[u8], opts: &Opts) {
    let prefix_name = match opts.show_name {
        ShowName::Always => name,
        ShowName::Never => None,
        ShowName::Auto => name,
    };
    if let Some(n) = prefix_name {
        write_all(STDOUT, n);
        write_all(STDOUT, b"-");
    }
    if opts.show_lineno {
        let mut buf = [0u8; 24];
        let len = fmt_u64(lineno, &mut buf);
        write_all(STDOUT, &buf[..len]);
        write_all(STDOUT, b"-");
    }
    write_all(STDOUT, line);
    if line.last().copied() != Some(b'\n') {
        write_all(STDOUT, b"\n");
    }
}

// Scan `line` for every non-overlapping fixed-string match of `pat`
// (honoring -i and -w boundaries) and emit each matched span on its
// own output line — the GNU grep -o shape. Returns the number of
// matches emitted, used by -m N to bound per-file output.
fn emit_matches_only(name: Option<&[u8]>, lineno: u64, line: &[u8],
                      pat: &[u8], opts: &Opts) -> u64 {
    if pat.is_empty() { return 0; }
    // Trim a single trailing newline so it never leaks into a -o emit.
    let body: &[u8] = if line.last() == Some(&b'\n') {
        &line[..line.len() - 1]
    } else {
        line
    };
    if pat.len() > body.len() { return 0; }
    let mut emitted: u64 = 0;
    let mut i = 0usize;
    while i + pat.len() <= body.len() {
        let mut ok = true;
        for j in 0..pat.len() {
            let a = if opts.icase { to_lower(body[i + j]) } else { body[i + j] };
            let b = if opts.icase { to_lower(pat[j]) } else { pat[j] };
            if a != b { ok = false; break; }
        }
        if ok && opts.word {
            let left_ok = i == 0 || !is_word_byte(body[i - 1]);
            let right_ok = i + pat.len() >= body.len()
                || !is_word_byte(body[i + pat.len()]);
            if !(left_ok && right_ok) { ok = false; }
        }
        if ok {
            emit_prefix(name, lineno, opts);
            write_all(STDOUT, &body[i..i + pat.len()]);
            write_all(STDOUT, b"\n");
            emitted += 1;
            i += pat.len();   // non-overlapping
        } else {
            i += 1;
        }
    }
    emitted
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
    // -A NUM: lines remaining to emit as after-context.
    let mut after_remaining: u32 = 0;
    // -B NUM: ring buffer of the last `before_ctx` non-matching lines.
    // Each slot stores up to CTX_LINE bytes (longer lines are truncated
    // for the context display only — the matched line itself uses the
    // full LINE_BUF emit path).
    let mut before_ring: [[u8; CTX_LINE]; CTX_CAP] = [[0u8; CTX_LINE]; CTX_CAP];
    let mut before_lens: [usize; CTX_CAP] = [0; CTX_CAP];
    let mut before_lns:  [u64; CTX_CAP]   = [0; CTX_CAP];
    let mut before_filled: usize = 0;
    let mut before_head:   usize = 0;
    let bcap = (opts.before_ctx as usize).min(CTX_CAP);
    // -q / -l only need to know "did anything match yet"; once we've
    // proven that, more reads add nothing. Short-circuit by returning
    // early so a multi-GB log file isn't rescanned for nothing.
    let stop_after_first = opts.quiet || opts.list || opts.list_no_match;
    let suppress_lines = opts.quiet || opts.list || opts.list_no_match || opts.count;
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
                    let m = line_matches(body, pat, opts.icase, opts.word, opts.line_match);
                    let is_match = m != opts.invert;
                    if is_match {
                        // Flush the before-context ring oldest-first.
                        if !suppress_lines && before_filled > 0 {
                            let start_slot = if before_filled < bcap {
                                0
                            } else {
                                before_head
                            };
                            for k in 0..before_filled {
                                let slot = (start_slot + k) % bcap.max(1);
                                let len = before_lens[slot];
                                let ln = before_lns[slot];
                                emit_context(name, ln, &before_ring[slot][..len], opts);
                            }
                            before_filled = 0;
                            before_head = 0;
                        }
                        if !suppress_lines {
                            if opts.only_matching && !opts.invert {
                                let _ = emit_matches_only(name, lineno, body, pat, opts);
                            } else {
                                emit_match(name, lineno, body, opts);
                            }
                        }
                        count += 1;
                        after_remaining = opts.after_ctx;
                        if stop_after_first { return Ok(count); }
                        if opts.max_count > 0 && count >= opts.max_count {
                            return Ok(count);
                        }
                    } else if after_remaining > 0 && !suppress_lines {
                        emit_context(name, lineno, body, opts);
                        after_remaining -= 1;
                    } else if bcap > 0 {
                        // Push into the before-context ring (truncated
                        // to CTX_LINE bytes for the snapshot — matched
                        // lines themselves still use the full path).
                        let slot = before_head;
                        let take = body.len().min(CTX_LINE);
                        before_ring[slot][..take].copy_from_slice(&body[..take]);
                        before_lens[slot] = take;
                        before_lns[slot] = lineno;
                        before_head = (slot + 1) % bcap;
                        if before_filled < bcap { before_filled += 1; }
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
        let m = line_matches(body, pat, opts.icase, opts.word, opts.line_match);
        if m != opts.invert {
            if !suppress_lines {
                if opts.only_matching && !opts.invert {
                    let _ = emit_matches_only(name, lineno, body, pat, opts);
                } else {
                    emit_match(name, lineno, body, opts);
                }
            }
            count += 1;
        }
    }
    Ok(count)
}

const PATH_MAX: usize = 1024;
const REC_MAX_DEPTH: usize = 32;

fn emit_count_line(name: Option<&[u8]>, count: u64, show_name: bool) {
    if let Some(n) = name { if show_name {
        write_all(STDOUT, n);
        write_all(STDOUT, b":");
    }}
    let mut buf = [0u8; 24];
    let len = fmt_u64(count, &mut buf);
    write_all(STDOUT, &buf[..len]);
    write_all(STDOUT, b"\n");
}

// Returns (had_match, had_error). Walks each non-./.. entry of the
// directory at `path_buf[..path_len]`, recursing into subdirectories
// up to REC_MAX_DEPTH and grepping every regular file (or symlink to
// one) with `grep_one_path`.
fn grep_walk_dir(
    path_buf: &mut [u8; PATH_MAX],
    path_len: usize,
    depth: usize,
    pat: &[u8],
    opts: &Opts,
    scratch: &mut [u8],
    show_name_count: bool,
) -> (bool, bool) {
    if depth >= REC_MAX_DEPTH {
        return (false, false);
    }
    let dfd = unsafe {
        syscall4(sysn::OPENAT, AT_FDCWD as u64, path_buf.as_ptr() as u64,
                 O_RDONLY | O_DIRECTORY, 0)
    };
    if dfd < 0 { return (false, true); }
    let dir_fd = dfd as i32;

    let mut had_match = false;
    let mut had_error = false;
    let mut buf = [0u8; 4096];
    'read: loop {
        let n = unsafe {
            syscall3(sysn::GETDENTS64, dir_fd as u64,
                     buf.as_mut_ptr() as u64, buf.len() as u64)
        };
        if n < 0 { had_error = true; break; }
        if n == 0 { break; }
        let bytes = n as usize;
        let mut off = 0usize;
        while off < bytes {
            if off + 19 > bytes { break; }
            let lo = buf[off + 16] as usize;
            let hi = buf[off + 17] as usize;
            let reclen = lo | (hi << 8);
            if reclen < 19 || off + reclen > bytes { break; }
            let dtype = buf[off + 18];
            let name_start = off + 19;
            let mut name_end = name_start;
            while name_end < off + reclen && buf[name_end] != 0 {
                name_end += 1;
            }
            let name = &buf[name_start..name_end];
            let nlen = name.len();
            let is_dot = nlen == 1 && name[0] == b'.';
            let is_dotdot = nlen == 2 && name[0] == b'.' && name[1] == b'.';
            if is_dot || is_dotdot { off += reclen; continue; }

            let need_sep = path_len > 0 && path_buf[path_len - 1] != b'/';
            let total = path_len + (if need_sep { 1 } else { 0 }) + nlen;
            if total + 1 > path_buf.len() {
                had_error = true;
                break 'read;
            }
            let mut pos = path_len;
            if need_sep { path_buf[pos] = b'/'; pos += 1; }
            for i in 0..nlen { path_buf[pos + i] = name[i]; }
            path_buf[pos + nlen] = 0;
            let child_len = pos + nlen;

            // Linux dirent d_type: 4=DIR, 8=REG, 10=LNK, others ignored.
            // For symlinks (and DT_UNKNOWN, since some filesystems
            // don't fill d_type), probe with O_DIRECTORY to decide
            // whether to descend or treat as file. Without this, a
            // symlink-to-directory would be opened as a regular file
            // and grep_fd would error on -EISDIR.
            let mut walk_as_dir = dtype == 4;
            let mut grep_as_file = dtype == 8;
            if dtype == 10 || dtype == 0 {
                let probe = unsafe {
                    syscall4(sysn::OPENAT, AT_FDCWD as u64, path_buf.as_ptr() as u64,
                             O_RDONLY | O_DIRECTORY, 0)
                };
                if probe >= 0 {
                    unsafe { let _ = syscall1(sysn::CLOSE, probe as u64); }
                    walk_as_dir = true;
                } else {
                    grep_as_file = true;
                }
            }
            if walk_as_dir {
                let (m, e) = grep_walk_dir(path_buf, child_len, depth + 1,
                                            pat, opts, scratch, show_name_count);
                if m { had_match = true; }
                if e { had_error = true; }
            } else if grep_as_file {
                let (m, e) = grep_one_file(path_buf, child_len, pat, opts,
                                            scratch, show_name_count);
                if m { had_match = true; }
                if e { had_error = true; }
            }

            // Restore parent path.
            path_buf[path_len] = 0;

            if opts.quiet && had_match { break 'read; }
            off += reclen;
        }
    }
    unsafe { let _ = syscall1(sysn::CLOSE, dir_fd as u64); }
    (had_match, had_error)
}

// Open and grep a single file path. Used by both the non-recursive
// argv loop and the recursive walker. Returns (had_match, had_error).
fn grep_one_file(
    path_buf: &[u8],
    path_len: usize,
    pat: &[u8],
    opts: &Opts,
    scratch: &mut [u8],
    show_name_count: bool,
) -> (bool, bool) {
    let path_ptr = path_buf.as_ptr();
    let f = unsafe { sys_open_ro(path_ptr) };
    if f < 0 {
        write_str(STDERR, b"rust-grep: cannot open '");
        unsafe {
            let _ = syscall3(sysn::WRITE, STDERR as u64,
                             path_ptr as u64, path_len as u64);
        }
        write_str(STDERR, b"'\n");
        return (false, true);
    }
    let name = &path_buf[..path_len];
    let mut had_match = false;
    let mut had_error = false;
    match grep_fd(f as i32, Some(name), pat, opts, scratch) {
        Ok(c) => {
            if c > 0 { had_match = true; }
            if !opts.quiet {
                let term: &[u8] = if opts.null_term { b"\0" } else { b"\n" };
                if opts.list {
                    if c > 0 {
                        write_all(STDOUT, name);
                        write_all(STDOUT, term);
                    }
                } else if opts.list_no_match {
                    if c == 0 {
                        write_all(STDOUT, name);
                        write_all(STDOUT, term);
                    }
                } else if opts.count {
                    emit_count_line(Some(name), c, show_name_count);
                }
            }
        }
        Err(_) => had_error = true,
    }
    unsafe { let _ = syscall1(sysn::CLOSE, f as u64); }
    (had_match, had_error)
}

#[unsafe(no_mangle)]
pub extern "C" fn main(argc: i32, argv: *const *const u8, _envp: *const *const u8) -> i32 {
    let mut idx: usize = 1;
    let mut opts = Opts {
        show_lineno: false,
        icase: false,
        invert: false,
        word: false,
        line_match: false,
        recursive: false,
        show_name: ShowName::Auto,
        count: false,
        list: false,
        list_no_match: false,
        quiet: false,
        max_count: 0,
        only_matching: false,
        after_ctx: 0,
        before_ctx: 0,
        null_term: false,
    };

    let mut e_pattern: Option<*const u8> = None;
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
        } else if arg_is(p, b"-w") || arg_is(p, b"--word-regexp") {
            opts.word = true;
            idx += 1;
        } else if arg_is(p, b"-x") || arg_is(p, b"--line-regexp") {
            opts.line_match = true;
            idx += 1;
        } else if arg_is(p, b"-o") || arg_is(p, b"--only-matching") {
            opts.only_matching = true;
            idx += 1;
        } else if arg_is(p, b"-r") || arg_is(p, b"-R") || arg_is(p, b"--recursive") {
            opts.recursive = true;
            // Recursive search implies one-file-per-line so the filename
            // is meaningful; force show_name to Always unless the user
            // already overrode with -h.
            if opts.show_name == ShowName::Auto {
                opts.show_name = ShowName::Always;
            }
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
        } else if arg_is(p, b"-l") || arg_is(p, b"--files-with-matches") {
            opts.list = true;
            idx += 1;
        } else if arg_is(p, b"-L") || arg_is(p, b"--files-without-match") {
            opts.list_no_match = true;
            idx += 1;
        } else if arg_is(p, b"-A") || arg_is(p, b"--after-context")
                  || arg_is(p, b"-B") || arg_is(p, b"--before-context")
                  || arg_is(p, b"-C") || arg_is(p, b"--context") {
            // -A/-B/-C all take a non-negative integer; record which
            // flag we matched so we can dispatch below.
            let kind: u8 = if arg_is(p, b"-A") || arg_is(p, b"--after-context") { b'A' }
                else if arg_is(p, b"-B") || arg_is(p, b"--before-context") { b'B' }
                else { b'C' };
            idx += 1;
            match argv_get(argc, argv, idx) {
                Some(np) => {
                    let n = cstr_len(np);
                    let mut v: u32 = 0;
                    let mut ok = n > 0;
                    for k in 0..n {
                        let c = unsafe { *np.add(k) };
                        if !(b'0'..=b'9').contains(&c) { ok = false; break; }
                        v = match v.checked_mul(10).and_then(|x| x.checked_add((c - b'0') as u32)) {
                            Some(x) => x,
                            None => { ok = false; break; }
                        };
                    }
                    if !ok {
                        write_str(STDERR, b"rust-grep: invalid context value\n");
                        return 2;
                    }
                    match kind {
                        b'A' => opts.after_ctx = v,
                        b'B' => opts.before_ctx = v,
                        _    => { opts.after_ctx = v; opts.before_ctx = v; }
                    }
                    idx += 1;
                }
                None => {
                    write_str(STDERR, b"rust-grep: context flag needs an argument\n");
                    return 2;
                }
            }
        } else if arg_is(p, b"-m") || arg_is(p, b"--max-count") {
            // -m N: stop after N matches per file. 0 disables.
            idx += 1;
            match argv_get(argc, argv, idx) {
                Some(np) => {
                    let n = cstr_len(np);
                    if n == 0 {
                        write_str(STDERR, b"rust-grep: -m needs a non-negative integer\n");
                        return 2;
                    }
                    let mut v: u64 = 0;
                    let mut ok = true;
                    for k in 0..n {
                        let c = unsafe { *np.add(k) };
                        if !(b'0'..=b'9').contains(&c) { ok = false; break; }
                        v = match v.checked_mul(10).and_then(|x| x.checked_add((c - b'0') as u64)) {
                            Some(x) => x,
                            None => { ok = false; break; }
                        };
                    }
                    if !ok {
                        write_str(STDERR, b"rust-grep: invalid -m value\n");
                        return 2;
                    }
                    opts.max_count = v;
                    idx += 1;
                }
                None => {
                    write_str(STDERR, b"rust-grep: -m needs an argument\n");
                    return 2;
                }
            }
        } else if arg_is(p, b"-Z") || arg_is(p, b"--null") {
            opts.null_term = true;
            idx += 1;
        } else if arg_is(p, b"-q") || arg_is(p, b"--quiet") || arg_is(p, b"--silent") {
            opts.quiet = true;
            idx += 1;
        } else if arg_is(p, b"-F") || arg_is(p, b"--fixed-strings") {
            // Already fixed-string by default; accept the flag for
            // GNU-script portability (no behaviour change).
            idx += 1;
        } else if arg_is(p, b"-e") {
            // -e PATTERN — useful when PATTERN starts with `-`. Only
            // the last -e wins for now (single-pattern grep).
            idx += 1;
            match argv_get(argc, argv, idx) {
                Some(pp) => { e_pattern = Some(pp); idx += 1; }
                None => {
                    write_str(STDERR, b"rust-grep: -e needs a pattern\n");
                    return 2;
                }
            }
        } else if arg_is(p, b"--") {
            idx += 1;
            break;
        } else if arg_is(p, b"--help") {
            // GNU grep --help text, trimmed to flags we actually
            // implement. Stdout, exit 0 — matches conventional --help.
            let help: &[u8] = b"\
Usage: rust-grep [OPTION]... PATTERN [FILE]...
Search for PATTERN in each FILE (or standard input).

Pattern selection and interpretation:
  -e, --pattern PAT     use PAT as the pattern
  -F, --fixed-strings   PATTERN is a fixed string (default; accepted as no-op)
  -i, --ignore-case     case-insensitive match
  -w, --word-regexp     match only whole words
  -x, --line-regexp     match only whole lines
  -v, --invert-match    select non-matching lines

Output control:
  -n, --line-number     prefix each line with its 1-based line number
  -c, --count           print only a count of matching lines per FILE
  -l, --files-with-matches    print only names of FILEs containing matches
  -L, --files-without-match   print only names of FILEs containing no match
  -q, --quiet, --silent       suppress output, exit 0 on first match
  -h, --no-filename     never prefix lines with filename
  -H, --with-filename   always prefix lines with filename
  -r, -R, --recursive   recurse into directories
  -A, --after-context NUM   print NUM lines of trailing context
  -B, --before-context NUM  print NUM lines of leading context (capped at 16)
  -C, --context NUM         shorthand for -A NUM -B NUM
  -m, --max-count NUM   stop after NUM matches per file
  -o, --only-matching   print only the matched portion of each line
  -Z, --null            NUL-terminate filenames in -l / -L output
      --help            show this help and exit
\0";
            let len = help.len() - 1;  // strip the trailing NUL
            unsafe {
                let _ = syscall3(sysn::WRITE, STDOUT as u64,
                                 help.as_ptr() as u64, len as u64);
            }
            return 0;
        } else {
            break;
        }
    }

    // -e PATTERN takes precedence over a positional one; without -e
    // the next positional is the pattern.
    let pat_ptr = match e_pattern {
        Some(p) => p,
        None => match argv_get(argc, argv, idx) {
            Some(p) => { idx += 1; p }
            None => {
                write_str(STDERR, b"usage: rust-grep [-niHhvclqF] [-e PAT] PATTERN [FILE...]\n");
                return 2;
            }
        },
    };
    let pat_len = cstr_len(pat_ptr);
    let pat = unsafe { core::slice::from_raw_parts(pat_ptr, pat_len) };

    let mut scratch = [0u8; READ_BUF];
    let mut had_match = false;
    let mut had_error = false;

    // emit_count_line is a free fn (not a closure) so grep_one_file —
    // which lives outside main — can also call it.

    if (idx as i32) >= argc {
        match grep_fd(STDIN, None, pat, &opts, &mut scratch) {
            Ok(c) => {
                if c > 0 { had_match = true; }
                if !opts.quiet {
                    let label: &[u8] = if opts.null_term {
                        b"(standard input)\0"
                    } else {
                        b"(standard input)\n"
                    };
                    if opts.list {
                        if c > 0 { write_all(STDOUT, label); }
                    } else if opts.list_no_match {
                        if c == 0 { write_all(STDOUT, label); }
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
            // "-" reads stdin; the conventional GNU label in headers/
            // counts is "(standard input)".
            let is_dash = n == 1 && unsafe { *p } == b'-';
            // -r: if this argv entry is a directory, walk it instead
            // of treating it as a file. Otherwise fall through to the
            // existing single-file path.
            if opts.recursive && !is_dash && n > 0 && n + 1 <= PATH_MAX {
                let probe = unsafe {
                    syscall4(sysn::OPENAT, AT_FDCWD as u64, p as u64,
                             O_RDONLY | O_DIRECTORY, 0)
                };
                if probe >= 0 {
                    unsafe { let _ = syscall1(sysn::CLOSE, probe as u64); }
                    let mut path_buf = [0u8; PATH_MAX];
                    for i in 0..n { path_buf[i] = unsafe { *p.add(i) }; }
                    path_buf[n] = 0;
                    let (m, e) = grep_walk_dir(&mut path_buf, n, 0,
                                                pat, &opts2, &mut scratch,
                                                show_name_count);
                    if m { had_match = true; }
                    if e { had_error = true; }
                    idx += 1;
                    if opts.quiet && had_match { break; }
                    continue;
                }
            }
            let (fd_i32, opened_owned) = if is_dash {
                (STDIN, false)
            } else {
                let f = unsafe { sys_open_ro(p) };
                if f < 0 {
                    write_str(STDERR, b"rust-grep: cannot open '");
                    unsafe {
                        let _ = syscall3(sysn::WRITE, STDERR as u64, p as u64, n as u64);
                    }
                    write_str(STDERR, b"'\n");
                    had_error = true;
                    idx += 1;
                    continue;
                }
                (f as i32, true)
            };
            let stdin_name: &[u8] = b"(standard input)";
            let name: &[u8] = if is_dash {
                stdin_name
            } else {
                unsafe { core::slice::from_raw_parts(p, n) }
            };
            match grep_fd(fd_i32, Some(name), pat, &opts2, &mut scratch) {
                Ok(c) => {
                    if c > 0 { had_match = true; }
                    if !opts.quiet {
                        let term: &[u8] = if opts.null_term { b"\0" } else { b"\n" };
                        if opts.list {
                            if c > 0 {
                                write_all(STDOUT, name);
                                write_all(STDOUT, term);
                            }
                        } else if opts.list_no_match {
                            if c == 0 {
                                write_all(STDOUT, name);
                                write_all(STDOUT, term);
                            }
                        } else if opts.count {
                            emit_count_line(Some(name), c, show_name_count);
                        }
                    }
                }
                Err(_) => had_error = true,
            }
            if opened_owned {
                unsafe { let _ = syscall1(sysn::CLOSE, fd_i32 as u64); }
            }
            idx += 1;
            // Quiet mode: bail as soon as anything has matched anywhere.
            if opts.quiet && had_match { break; }
        }
    }

    // Standard grep exit codes: 0 = match, 1 = no match, 2 = error.
    if had_error { 2 } else if had_match { 0 } else { 1 }
}
