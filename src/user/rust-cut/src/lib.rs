// SPDX-License-Identifier: MPL-2.0
//
// rust-cut — split each input line on a delimiter and emit selected
// fields.
//
//   rust-cut -d <delim> -f <list>
//
// <delim> is a single byte (e.g. ',', ':', '\t' via -d $'\t').
// <list> is a comma-separated set of 1-based field numbers, e.g.
// "1,3,5". Range forms supported: "1-3", "-3" (1..=3), "5-"
// (5..=MAX_FIELDS). Mixed lists like "1,3-5,8-" all work.
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
    // Parse one decimal token; returns None on failure. Empty input
    // is allowed at this layer so the caller can interpret "" / "-"
    // / "5-" as open-ended ranges.
    fn parse_one(tok: &[u8]) -> Option<u32> {
        if tok.is_empty() { return None; }
        let mut v: u64 = 0;
        for &c in tok {
            if !(b'0'..=b'9').contains(&c) { return None; }
            v = v * 10 + (c - b'0') as u64;
            if v > u32::MAX as u64 { return None; }
        }
        if v == 0 { return None; }   // 1-based
        Some(v as u32)
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
            // Range form: "A-B", "A-" (open right), "-B" (open left,
            // i.e. starting from 1).
            let mut dash = tok.len();
            for k in 0..tok.len() {
                if tok[k] == b'-' { dash = k; break; }
            }
            if dash < tok.len() {
                let lo_tok = &tok[..dash];
                let hi_tok = &tok[dash + 1..];
                let lo: u32 = if lo_tok.is_empty() { 1 } else {
                    match parse_one(lo_tok) { Some(v) => v, None => return None }
                };
                // Open-right "5-" expands to lo..=MAX_FIELDS — not
                // unbounded since we have a fixed-size out[] buffer.
                // GNU cut allows it but our static window is bounded.
                let hi: u32 = if hi_tok.is_empty() {
                    MAX_FIELDS as u32
                } else {
                    match parse_one(hi_tok) { Some(v) => v, None => return None }
                };
                if hi < lo { return None; }
                let mut v = lo;
                while v <= hi {
                    if count >= MAX_FIELDS { return None; }
                    out[count] = v;
                    count += 1;
                    if v == u32::MAX { break; }
                    v += 1;
                }
            } else {
                let v = match parse_one(tok) { Some(v) => v, None => return None };
                if count >= MAX_FIELDS { return None; }
                out[count] = v;
                count += 1;
            }
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

// Emit selected byte positions from `line` (1-based). Positions past
// the line length are silently skipped. Used by -c / -b mode.
// With complement = true, emits positions NOT in the list instead.
fn emit_chars(line: &[u8], positions: &[u32], complement: bool, term: u8) -> bool {
    if !complement {
        for &pos in positions {
            let i = pos as usize;
            if i == 0 || i > line.len() { continue; }
            if !write_all(STDOUT, &line[i - 1..i]) { return false; }
        }
    } else {
        // Walk every byte; emit those whose 1-based position is NOT in
        // the positions list.
        for i in 1..=line.len() {
            let p = i as u32;
            let mut hit = false;
            for &q in positions { if q == p { hit = true; break; } }
            if !hit {
                if !write_all(STDOUT, &line[i - 1..i]) { return false; }
            }
        }
    }
    write_all(STDOUT, &[term])
}

// Emit selected fields from `line`, splitting on `delim`. The `out_delim`
// slice is what we emit between fields on output (defaults to the input
// delim; --output-delimiter=STR replaces it). `suppress_no_delim` skips
// lines that contain no delimiter (matches GNU cut -s).
fn emit_line(line: &[u8], delim: u8, fields: &[u32],
             suppress_no_delim: bool, complement: bool,
             out_delim: &[u8], term: u8) -> bool {
    if fields.is_empty() && !complement {
        return write_all(STDOUT, &[term]);
    }
    let want = |idx: u32| -> bool {
        let in_list = fields.contains(&idx);
        if complement { !in_list } else { in_list }
    };
    let mut idx_field: u32 = 1;
    let mut field_start = 0usize;
    let mut printed_any = false;
    let mut field_present = false;
    if suppress_no_delim {
        let mut has = false;
        for &b in line { if b == delim { has = true; break; } }
        if !has { return true; }
    }
    for (i, &b) in line.iter().enumerate() {
        if b == delim {
            field_present = true;
            if want(idx_field) {
                if printed_any {
                    if !write_all(STDOUT, out_delim) { return false; }
                }
                if !write_all(STDOUT, &line[field_start..i]) { return false; }
                printed_any = true;
            }
            idx_field += 1;
            field_start = i + 1;
        }
    }
    if !field_present {
        if !write_all(STDOUT, line) { return false; }
    } else if want(idx_field) {
        if printed_any {
            if !write_all(STDOUT, out_delim) { return false; }
        }
        if !write_all(STDOUT, &line[field_start..]) { return false; }
    }
    write_all(STDOUT, &[term])
}

#[unsafe(no_mangle)]
pub extern "C" fn main(argc: i32, argv: *const *const u8, _envp: *const *const u8) -> i32 {
    let mut delim: Option<u8> = None;
    let mut fields = [0u32; MAX_FIELDS];
    let mut nfields = 0usize;
    let mut suppress = false;
    let mut chars_mode = false;
    let mut complement = false;
    let mut zero_term = false;
    let mut out_delim_p: Option<*const u8> = None;
    let mut idx: i32 = 1;

    while idx < argc {
        let p = unsafe { *argv.add(idx as usize) };
        if p.is_null() || (p as usize) < 0x10000 {
            idx += 1;
            continue;
        }
        if cstr_eq(p, b"--help") {
            let help: &[u8] = b"\
Usage: rust-cut -d DELIM -f LIST [-s] [FILE]...
Print selected fields from each line.

  -d DELIM   single-byte field delimiter (use with -f)
  -f LIST    1-based field list, supports comma + range forms:
             1,3,5  /  1-3  /  -3 (1..=3)  /  5- (5 to MAX)
  -c LIST    1-based byte-position list (-b is an alias)
  -b LIST    same as -c
  -s         suppress lines that contain no DELIM (with -f)
      --complement   invert the LIST: emit positions/fields not in it
      --output-delimiter=STR  string to put between fields on output
  -z, --zero-terminated       line delimiter is NUL, not newline
      --help     show this help and exit

A '-' in the FILE list means standard input.
\0";
            let len = help.len() - 1;
            unsafe { let _ = syscall3(sysn::WRITE, STDOUT as u64,
                                       help.as_ptr() as u64, len as u64); }
            return 0;
        }
        if cstr_eq(p, b"-s") {
            suppress = true;
            idx += 1;
            continue;
        }
        if cstr_eq(p, b"--complement") {
            complement = true;
            idx += 1;
            continue;
        }
        if cstr_eq(p, b"-z") || cstr_eq(p, b"--zero-terminated") {
            zero_term = true;
            idx += 1;
            continue;
        }
        if cstr_eq(p, b"--output-delimiter") {
            if idx + 1 >= argc {
                write_str(STDERR, b"rust-cut: --output-delimiter needs an argument\n");
                return 2;
            }
            let arg = unsafe { *argv.add((idx + 1) as usize) };
            if arg.is_null() || (arg as usize) < 0x10000 { return 2; }
            out_delim_p = Some(arg);
            idx += 2;
            continue;
        }
        // --output-delimiter=STR (long form with embedded =)
        let p_n = {
            let mut k = 0usize;
            unsafe { while *p.add(k) != 0 { k += 1; } }
            k
        };
        if p_n >= 19 && unsafe {
            let want = b"--output-delimiter=";
            let mut ok = true;
            for i in 0..want.len() { if *p.add(i) != want[i] { ok = false; break; } }
            ok
        } {
            out_delim_p = Some(unsafe { p.add(19) });
            idx += 1;
            continue;
        }
        // --bytes=LIST / --characters=LIST (long forms with embedded =)
        let p_n = {
            let mut k = 0usize;
            unsafe { while *p.add(k) != 0 { k += 1; } }
            k
        };
        if (p_n > 8 && unsafe {
            let want = b"--bytes=";
            let mut ok = true;
            for j in 0..want.len() { if *p.add(j) != want[j] { ok = false; break; } }
            ok
        }) || (p_n > 13 && unsafe {
            let want = b"--characters=";
            let mut ok = true;
            for j in 0..want.len() { if *p.add(j) != want[j] { ok = false; break; } }
            ok
        }) {
            let off = if p_n > 13 && unsafe { *p.add(2) == b'c' } { 13 } else { 8 };
            let arg = unsafe { p.add(off) };
            match parse_fields(arg, &mut fields) {
                Some(n) => nfields = n,
                None => {
                    write_str(STDERR, b"rust-cut: invalid --bytes/--characters list\n");
                    return 2;
                }
            }
            chars_mode = true;
            idx += 1;
            continue;
        }
        // --fields=LIST (long form with embedded =)
        if p_n > 9 && unsafe {
            let want = b"--fields=";
            let mut ok = true;
            for j in 0..want.len() { if *p.add(j) != want[j] { ok = false; break; } }
            ok
        } {
            let arg = unsafe { p.add(9) };
            match parse_fields(arg, &mut fields) {
                Some(n) => nfields = n,
                None => {
                    write_str(STDERR, b"rust-cut: invalid --fields list\n");
                    return 2;
                }
            }
            idx += 1;
            continue;
        }
        // --delimiter=DELIM (long form with embedded =)
        if p_n > 12 && unsafe {
            let want = b"--delimiter=";
            let mut ok = true;
            for j in 0..want.len() { if *p.add(j) != want[j] { ok = false; break; } }
            ok
        } {
            let dp = unsafe { p.add(12) };
            let b = unsafe { *dp };
            if b == 0 { return 2; }
            delim = Some(b);
            idx += 1;
            continue;
        }
        if cstr_eq(p, b"-c") || cstr_eq(p, b"-b")
            || cstr_eq(p, b"--characters") || cstr_eq(p, b"--bytes") {
            // -c LIST / -b LIST: byte-position cut. Same payload as -f
            // but applied to raw positions instead of delim-separated
            // fields. (-c and -b are identical for ASCII inputs.)
            if idx + 1 >= argc {
                write_str(STDERR, b"rust-cut: -c / -b needs a list\n");
                return 2;
            }
            let arg = unsafe { *argv.add((idx + 1) as usize) };
            if arg.is_null() || (arg as usize) < 0x10000 {
                return 2;
            }
            match parse_fields(arg, &mut fields) {
                Some(n) => nfields = n,
                None => {
                    write_str(STDERR, b"rust-cut: invalid -c / -b list\n");
                    return 2;
                }
            }
            chars_mode = true;
            idx += 2;
            continue;
        }
        if cstr_eq(p, b"-d") || cstr_eq(p, b"--delimiter") {
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
        } else if cstr_eq(p, b"-f") || cstr_eq(p, b"--fields") {
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
    if nfields == 0 {
        write_str(STDERR, b"rust-cut: -c / -b LIST or -f LIST required\n");
        return 2;
    }
    let mode = if chars_mode {
        CutMode::Chars
    } else {
        match delim {
            Some(d) => CutMode::Fields { delim: d, suppress },
            None => {
                write_str(STDERR, b"rust-cut: -d <delim> required when using -f\n");
                return 2;
            }
        }
    };
    let fields_slice = &fields[..nfields];
    let sep: u8 = if zero_term { 0 } else { b'\n' };

    // Output delimiter: if --output-delimiter wasn't set, fall back to
    // the input delimiter (single byte) so existing behavior is
    // preserved. -c/-b mode never uses out_delim.
    let mut od_buf = [0u8; 256];
    let mut od_len = 0usize;
    if let Some(p) = out_delim_p {
        let mut k = 0usize;
        unsafe {
            while *p.add(k) != 0 && k < od_buf.len() {
                od_buf[k] = *p.add(k);
                k += 1;
            }
        }
        od_len = k;
    } else if let CutMode::Fields { delim: d, .. } = mode {
        od_buf[0] = d;
        od_len = 1;
    }
    let out_delim = &od_buf[..od_len];

    if idx >= argc {
        return if cut_fd(STDIN, mode, fields_slice, complement, out_delim, sep) { 0 } else { 1 };
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
            if !cut_fd(STDIN, mode, fields_slice, complement, out_delim, sep) { had_error = true; }
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
        if !cut_fd(fd, mode, fields_slice, complement, out_delim, sep) { had_error = true; }
        unsafe { let _ = syscall1(sysn::CLOSE, fd as u64); }
    }
    if had_error { 1 } else { 0 }
}

// CutMode picks between -f (delim/fields) and -c/-b (raw positions).
#[derive(Copy, Clone)]
enum CutMode { Fields { delim: u8, suppress: bool }, Chars }

fn cut_fd(fd: i32, mode: CutMode, list: &[u32], complement: bool,
          out_delim: &[u8], sep: u8) -> bool {
    let mut rbuf = [0u8; READ_BUF];
    let mut line = [0u8; LINE_BUF];
    let mut len = 0usize;
    let mut had_error = false;
    let emit = |line: &[u8]| -> bool {
        match mode {
            CutMode::Fields { delim, suppress } =>
                emit_line(line, delim, list, suppress, complement, out_delim, sep),
            CutMode::Chars => emit_chars(line, list, complement, sep),
        }
    };
    'outer: loop {
        let n = unsafe {
            syscall3(sysn::READ, fd as u64, rbuf.as_mut_ptr() as u64, rbuf.len() as u64)
        };
        if n < 0 { had_error = true; break; }
        if n == 0 { break; }
        let chunk = &rbuf[..n as usize];
        for &c in chunk {
            if c == sep {
                if !emit(&line[..len]) {
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
        if !emit(&line[..len]) { had_error = true; }
    }
    !had_error
}
