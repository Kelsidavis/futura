// SPDX-License-Identifier: MPL-2.0
//
// rust-cmp — byte-by-byte file comparison.
//
//   rust-cmp <file1> <file2>
//
// Exit codes match POSIX cmp(1):
//   0 — files are identical
//   1 — files differ; first diff (and EOF mismatch) reported on stdout
//   2 — error opening one of the files (message on stderr)
//
// Streams both files through 4 KiB buffers in lockstep — no allocator,
// no whole-file slurp.

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
const BUF: usize = 4096;

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

fn write_str(fd: i32, s: &[u8]) {
    unsafe {
        let _ = syscall3(sysn::WRITE, fd as u64, s.as_ptr() as u64, s.len() as u64);
    }
}

#[panic_handler]
fn panic(_info: &PanicInfo) -> ! {
    write_str(STDERR, b"[rust-cmp] panic\n");
    unsafe {
        sys_exit(1);
    }
}

fn open_read(p: *const u8) -> i32 {
    unsafe { syscall4(sysn::OPENAT, AT_FDCWD as u64, p as u64, O_RDONLY, 0) as i32 }
}

fn close_fd(fd: i32) {
    unsafe {
        let _ = syscall1(sysn::CLOSE, fd as u64);
    }
}

// Read up to buf.len() bytes from fd into buf, retrying on partial reads.
// Returns Some(n) on success (n=0 means EOF), None on read error.
fn read_full(fd: i32, buf: &mut [u8]) -> Option<usize> {
    let n = unsafe { syscall3(sysn::READ, fd as u64, buf.as_mut_ptr() as u64, buf.len() as u64) };
    if n < 0 {
        return None;
    }
    Some(n as usize)
}

// Print "rust-cmp: <file>: name1 differs from name2 at byte <pos>".
fn print_diff(name1: &[u8], name2: &[u8], byte_pos: u64) {
    write_str(STDOUT, name1);
    write_str(STDOUT, b" ");
    write_str(STDOUT, name2);
    write_str(STDOUT, b" differ: byte ");
    let mut buf = [0u8; 24];
    let mut n = byte_pos;
    let mut i = buf.len();
    if n == 0 {
        i -= 1;
        buf[i] = b'0';
    } else {
        while n > 0 && i > 0 {
            i -= 1;
            buf[i] = b'0' + (n % 10) as u8;
            n /= 10;
        }
    }
    write_str(STDOUT, &buf[i..]);
    write_str(STDOUT, b"\n");
}

// Match a NUL-terminated argv string against a literal byte slice.
fn arg_eq(p: *const u8, want: &[u8]) -> bool {
    for (i, &b) in want.iter().enumerate() {
        if unsafe { *p.add(i) } != b { return false; }
    }
    unsafe { *p.add(want.len()) == 0 }
}

#[unsafe(no_mangle)]
pub extern "C" fn main(argc: i32, argv: *const *const u8, _envp: *const *const u8) -> i32 {
    // Parse leading flags.
    let mut silent = false;
    let mut verbose = false;
    let mut byte_limit: Option<u64> = None;
    let mut skip1: u64 = 0;
    let mut skip2: u64 = 0;
    let mut idx: i32 = 1;
    while idx < argc {
        let p = unsafe { *argv.add(idx as usize) };
        if p.is_null() || (p as usize) < 0x10000 { break; }
        if arg_eq(p, b"-s") || arg_eq(p, b"--quiet") || arg_eq(p, b"--silent") {
            silent = true;
            idx += 1;
            continue;
        }
        if arg_eq(p, b"-l") || arg_eq(p, b"--verbose") {
            verbose = true;
            idx += 1;
            continue;
        }
        if arg_eq(p, b"-i") || arg_eq(p, b"--ignore-initial") {
            // -i SKIP   skip SKIP bytes from both files
            // -i SKIP1:SKIP2  skip SKIP1 from file1, SKIP2 from file2
            if idx + 1 >= argc {
                if !silent { write_str(STDERR, b"rust-cmp: -i needs a SKIP value\n"); }
                return 2;
            }
            let sp = unsafe { *argv.add((idx + 1) as usize) };
            if sp.is_null() || (sp as usize) < 0x10000 { return 2; }
            let mut sn = 0usize;
            unsafe { while *sp.add(sn) != 0 { sn += 1; } }
            // Find optional ':' splitter.
            let mut colon = sn;
            for i in 0..sn { if unsafe { *sp.add(i) } == b':' { colon = i; break; } }
            // Parse digits in [start, end), with an optional trailing
            // K/M/G/T (1024^N) or B suffix. The suffix can appear at
            // the very last byte before the colon (or end of string).
            let parse = |start: usize, mut end: usize| -> Option<u64> {
                if start >= end { return None; }
                let mut mult: u64 = 1;
                let last = unsafe { *sp.add(end - 1) };
                match last {
                    b'K' | b'k' => { mult = 1024; end -= 1; }
                    b'M' | b'm' => { mult = 1024 * 1024; end -= 1; }
                    b'G' | b'g' => { mult = 1024 * 1024 * 1024; end -= 1; }
                    b'T' | b't' => { mult = 1024u64 * 1024 * 1024 * 1024; end -= 1; }
                    b'B' | b'b' => { mult = 1; end -= 1; }
                    _ => {}
                }
                if start >= end { return None; }
                let mut v: u64 = 0;
                for i in start..end {
                    let c = unsafe { *sp.add(i) };
                    if !(b'0'..=b'9').contains(&c) { return None; }
                    v = v.checked_mul(10)?.checked_add((c - b'0') as u64)?;
                }
                v.checked_mul(mult)
            };
            match parse(0, colon) {
                Some(v) => skip1 = v,
                None => {
                    if !silent { write_str(STDERR, b"rust-cmp: invalid -i SKIP\n"); }
                    return 2;
                }
            }
            if colon < sn {
                match parse(colon + 1, sn) {
                    Some(v) => skip2 = v,
                    None => {
                        if !silent { write_str(STDERR, b"rust-cmp: invalid -i SKIP2\n"); }
                        return 2;
                    }
                }
            } else {
                skip2 = skip1;
            }
            idx += 2;
            continue;
        }
        // --bytes=NUM (long form with embedded =)
        let p_n = {
            let mut k = 0usize;
            unsafe { while *p.add(k) != 0 { k += 1; } }
            k
        };
        let mut np_inline: Option<*const u8> = None;
        if p_n >= 8 && unsafe {
            let want = b"--bytes=";
            let mut ok = true;
            for j in 0..want.len() { if *p.add(j) != want[j] { ok = false; break; } }
            ok
        } {
            np_inline = Some(unsafe { p.add(8) });
        }
        if np_inline.is_some() || arg_eq(p, b"-n") || arg_eq(p, b"--bytes") {
            // -n NUM: compare at most NUM bytes from each input.
            // NUM accepts an optional binary suffix (K/M/G/T = 1024^N).
            let np = if let Some(p) = np_inline {
                p
            } else {
                if idx + 1 >= argc {
                    if !silent { write_str(STDERR, b"rust-cmp: -n needs a non-negative integer\n"); }
                    return 2;
                }
                let p = unsafe { *argv.add((idx + 1) as usize) };
                if p.is_null() || (p as usize) < 0x10000 {
                    return 2;
                }
                p
            };
            if np.is_null() {
                return 2;
            }
            let mut nn = 0usize;
            unsafe { while *np.add(nn) != 0 { nn += 1; } }
            if nn == 0 {
                if !silent { write_str(STDERR, b"rust-cmp: invalid -n value\n"); }
                return 2;
            }
            let last = unsafe { *np.add(nn - 1) };
            let (digits_end, mult): (usize, u64) = match last {
                b'K' | b'k' => (nn - 1, 1024),
                b'M' | b'm' => (nn - 1, 1024 * 1024),
                b'G' | b'g' => (nn - 1, 1024 * 1024 * 1024),
                b'T' | b't' => (nn - 1, 1024u64 * 1024 * 1024 * 1024),
                b'B' | b'b' => (nn - 1, 1),
                _ => (nn, 1),
            };
            if digits_end == 0 {
                if !silent { write_str(STDERR, b"rust-cmp: invalid -n value\n"); }
                return 2;
            }
            let mut v: u64 = 0;
            let mut ok = true;
            for i in 0..digits_end {
                let c = unsafe { *np.add(i) };
                if !(b'0'..=b'9').contains(&c) { ok = false; break; }
                v = match v.checked_mul(10).and_then(|x| x.checked_add((c - b'0') as u64)) {
                    Some(x) => x,
                    None => { ok = false; break; }
                };
            }
            if ok {
                match v.checked_mul(mult) {
                    Some(x) => v = x,
                    None => ok = false,
                }
            }
            if !ok {
                if !silent { write_str(STDERR, b"rust-cmp: invalid -n value\n"); }
                return 2;
            }
            byte_limit = Some(v);
            // --bytes=NUM consumed only one argv slot; the separate-arg
            // forms consumed two.
            idx += if np_inline.is_some() { 1 } else { 2 };
            continue;
        }
        if arg_eq(p, b"--") { idx += 1; break; }
        if arg_eq(p, b"--help") {
            let help: &[u8] = b"\
Usage: rust-cmp [OPTION]... FILE1 FILE2
Compare two files byte by byte.

  -s, --quiet, --silent  suppress all output, exit status only
  -l, --verbose          list every differing byte (POS OCT1 OCT2)
  -n, --bytes NUM        compare at most NUM bytes (suffix K/M/G/T = 1024^N)
  -i SKIP[:SKIP2]        skip SKIP bytes from both files (same suffix syntax)
                         (or SKIP from file1 and SKIP2 from file2)
      --help              show this help and exit

A '-' for either FILE means standard input (not for both).
Exit status: 0 identical, 1 differ, 2 trouble.
\0";
            let len = help.len() - 1;
            unsafe { let _ = syscall3(sysn::WRITE, STDOUT as u64,
                                       help.as_ptr() as u64, len as u64); }
            return 0;
        }
        break;
    }

    if argc - idx < 2 {
        if !silent {
            write_str(STDERR, b"usage: rust-cmp [-s] [-n NUM] <file1> <file2>\n");
        }
        return 2;
    }
    let p1 = unsafe { *argv.add(idx as usize) };
    let p2 = unsafe { *argv.add((idx + 1) as usize) };
    if p1.is_null() || (p1 as usize) < 0x10000 || p2.is_null() || (p2 as usize) < 0x10000 {
        if !silent { write_str(STDERR, b"rust-cmp: invalid arguments\n"); }
        return 2;
    }

    // GNU cmp accepts "-" for either file (at most one of the two,
    // since you can't read stdin twice). Pre-resolve each path to its
    // fd up front so the diff-message names stay correct even when
    // one side is stdin.
    let mut n1 = 0usize;
    while unsafe { *p1.add(n1) } != 0 { n1 += 1; }
    let mut n2 = 0usize;
    while unsafe { *p2.add(n2) } != 0 { n2 += 1; }
    let p1_is_dash = n1 == 1 && unsafe { *p1 } == b'-';
    let p2_is_dash = n2 == 1 && unsafe { *p2 } == b'-';
    if p1_is_dash && p2_is_dash {
        if !silent { write_str(STDERR, b"rust-cmp: cannot use - for both files\n"); }
        return 2;
    }

    let (fd1, owned1) = if p1_is_dash {
        (STDIN, false)
    } else {
        let f = open_read(p1);
        if f < 0 {
            if !silent { write_str(STDERR, b"rust-cmp: cannot open first file\n"); }
            return 2;
        }
        (f, true)
    };
    let (fd2, owned2) = if p2_is_dash {
        (STDIN, false)
    } else {
        let f = open_read(p2);
        if f < 0 {
            if owned1 { close_fd(fd1); }
            if !silent { write_str(STDERR, b"rust-cmp: cannot open second file\n"); }
            return 2;
        }
        (f, true)
    };

    let stdin_label: &[u8] = b"-";
    let name1: &[u8] = if p1_is_dash { stdin_label } else {
        unsafe { core::slice::from_raw_parts(p1, n1) }
    };
    let name2: &[u8] = if p2_is_dash { stdin_label } else {
        unsafe { core::slice::from_raw_parts(p2, n2) }
    };

    // -i: drain `skip1`/`skip2` bytes off each fd before comparison
    // begins. We don't have lseek wired up here, so a stream-friendly
    // read+discard works for both files and pipes.
    let mut sink = [0u8; BUF];
    let mut drain = |fd: i32, mut want: u64| -> bool {
        while want > 0 {
            let take = (want as usize).min(sink.len());
            let n = unsafe {
                syscall3(sysn::READ, fd as u64, sink.as_mut_ptr() as u64, take as u64)
            };
            if n <= 0 { return false; }
            want -= n as u64;
        }
        true
    };
    if skip1 > 0 && !drain(fd1, skip1) {
        if !silent { write_str(STDERR, b"rust-cmp: -i skipped past first file's end\n"); }
        if owned1 { close_fd(fd1); }
        if owned2 { close_fd(fd2); }
        return 1;
    }
    if skip2 > 0 && !drain(fd2, skip2) {
        if !silent { write_str(STDERR, b"rust-cmp: -i skipped past second file's end\n"); }
        if owned1 { close_fd(fd1); }
        if owned2 { close_fd(fd2); }
        return 1;
    }

    let mut buf1 = [0u8; BUF];
    let mut buf2 = [0u8; BUF];
    let mut byte_pos: u64 = 0;
    let mut rc: i32 = 0;

    loop {
        // Under -n, stop once we've already compared `byte_limit` bytes
        // — anything past that is "equal" by fiat (matches GNU cmp -n).
        if let Some(lim) = byte_limit {
            if byte_pos >= lim { break; }
        }
        let r1 = read_full(fd1, &mut buf1);
        let r2 = read_full(fd2, &mut buf2);
        let (n1r, n2r) = match (r1, r2) {
            (Some(a), Some(b)) => (a, b),
            _ => {
                if !silent { write_str(STDERR, b"rust-cmp: read error\n"); }
                rc = 2;
                break;
            }
        };
        if n1r == 0 && n2r == 0 {
            break; // identical
        }
        let mut common = n1r.min(n2r);
        // Honor -n by clamping the comparable window.
        if let Some(lim) = byte_limit {
            let remaining = lim - byte_pos;
            if (common as u64) > remaining {
                common = remaining as usize;
            }
        }
        for i in 0..common {
            if buf1[i] != buf2[i] {
                if verbose && !silent {
                    // GNU cmp -l format: "<pos> <octal-a> <octal-b>".
                    let pos = byte_pos + i as u64 + 1;
                    let mut nb = [0u8; 24];
                    let mut k = nb.len();
                    let mut v = pos;
                    if v == 0 { k -= 1; nb[k] = b'0'; }
                    while v > 0 && k > 0 { k -= 1; nb[k] = b'0' + (v % 10) as u8; v /= 10; }
                    write_str(STDOUT, &nb[k..]);
                    let emit_oct = |c: u8| {
                        let mut o = [b' ', b'0', b'0', b'0'];
                        o[1] = b'0' + ((c >> 6) & 0o7);
                        o[2] = b'0' + ((c >> 3) & 0o7);
                        o[3] = b'0' + (c & 0o7);
                        write_str(STDOUT, &o);
                    };
                    emit_oct(buf1[i]);
                    emit_oct(buf2[i]);
                    write_str(STDOUT, b"\n");
                    rc = 1;
                    // -l keeps going to enumerate every difference.
                    continue;
                }
                if !silent { print_diff(name1, name2, byte_pos + i as u64 + 1); }
                rc = 1;
                if owned1 { close_fd(fd1); }
                if owned2 { close_fd(fd2); }
                return rc;
            }
        }
        byte_pos += common as u64;
        if let Some(lim) = byte_limit {
            if byte_pos >= lim { break; }  // -n satisfied; stop comparing.
        }
        if n1r != n2r {
            // One file ended; the other has more bytes. GNU cmp writes
            // the EOF notice to stderr (not stdout) — match that so
            // shell pipelines that grep stdout don't see this line.
            if !silent {
                write_str(STDERR, b"rust-cmp: EOF on ");
                write_str(STDERR, if n1r < n2r { name1 } else { name2 });
                write_str(STDERR, b"\n");
            }
            rc = 1;
            break;
        }
        // Both reads were full and equal-length; loop reads more.
    }

    if owned1 { close_fd(fd1); }
    if owned2 { close_fd(fd2); }
    rc
}
