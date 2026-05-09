// SPDX-License-Identifier: MPL-2.0
//
// rust-tr — translate characters from stdin.
//
//   rust-tr SET1 SET2     replace each byte in SET1 with the
//                          corresponding byte in SET2 (last byte
//                          repeats if SET2 is shorter)
//   rust-tr -d SET1       delete every byte in SET1 from stdin
//
// Sets support 'a-z' style ranges and a few escape sequences:
//   \\ \n \r \t \0 \\\\
// No octal/hex escapes yet, no character classes ([:upper:] etc),
// no -s (squeeze) or -c (complement). Common case 'tr a-z A-Z' or
// 'tr -d "\\r"' works.

#![no_std]
#![forbid(unsafe_op_in_unsafe_fn)]

use core::panic::PanicInfo;

#[cfg(target_arch = "aarch64")]
mod sysn {
    pub const READ: u64 = 63;
    pub const WRITE: u64 = 64;
    pub const EXIT: u64 = 93;
}

#[cfg(target_arch = "x86_64")]
mod sysn {
    pub const READ: u64 = 0;
    pub const WRITE: u64 = 1;
    pub const EXIT: u64 = 60;
}

const STDIN: i32 = 0;
const STDOUT: i32 = 1;
const STDERR: i32 = 2;
const READ_BUF: usize = 4096;

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
    write_str(STDERR, b"[rust-tr] panic\n");
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

fn cstr_len(p: *const u8) -> usize {
    let mut n = 0;
    unsafe {
        while *p.add(n) != 0 {
            n += 1;
        }
    }
    n
}

// Expand a SET argument into an actual byte sequence in `out`.
// Returns the count written. Supports:
//   X-Y      range from X to Y inclusive
//   \\X      escape (\\, \n, \r, \t, \0)
fn expand_set(p: *const u8, out: &mut [u8; 1024]) -> Option<usize> {
    let n = cstr_len(p);
    let s = unsafe { core::slice::from_raw_parts(p, n) };
    let mut w = 0usize;
    let mut i = 0usize;
    while i < n {
        // Decode a possibly-escaped byte at position i.
        let (b, adv) = if s[i] == b'\\' && i + 1 < n {
            let e = s[i + 1];
            let v = match e {
                b'\\' => b'\\',
                b'n' => b'\n',
                b'r' => b'\r',
                b't' => b'\t',
                b'0' => 0,
                other => other,
            };
            (v, 2)
        } else {
            (s[i], 1)
        };
        // Look ahead for a range "b-c".
        let next_dash = i + adv < n && s[i + adv] == b'-';
        let (b2, adv2) = if next_dash && i + adv + 1 < n {
            let j = i + adv + 1;
            if s[j] == b'\\' && j + 1 < n {
                let e = s[j + 1];
                let v = match e {
                    b'\\' => b'\\',
                    b'n' => b'\n',
                    b'r' => b'\r',
                    b't' => b'\t',
                    b'0' => 0,
                    other => other,
                };
                (Some(v), 2)
            } else {
                (Some(s[j]), 1)
            }
        } else {
            (None, 0)
        };
        if let Some(b2_val) = b2 {
            // Range from b to b2_val inclusive (ascending only — descending is rare and
            // GNU tr expands "z-a" to a single empty range; we follow that here).
            if b <= b2_val {
                let mut c = b;
                loop {
                    if w >= out.len() { return None; }
                    out[w] = c; w += 1;
                    if c == b2_val { break; }
                    c += 1;
                }
            }
            i += adv + 1 + adv2;
        } else {
            if w >= out.len() { return None; }
            out[w] = b; w += 1;
            i += adv;
        }
    }
    Some(w)
}

#[unsafe(no_mangle)]
pub extern "C" fn main(argc: i32, argv: *const *const u8, _envp: *const *const u8) -> i32 {
    let mut delete = false;
    let mut squeeze = false;
    let mut complement = false;
    let mut idx: i32 = 1;
    while idx < argc {
        let p = unsafe { *argv.add(idx as usize) };
        if p.is_null() || (p as usize) < 0x10000 {
            idx += 1;
            continue;
        }
        if cstr_eq(p, b"-d") { delete = true; idx += 1; continue; }
        if cstr_eq(p, b"-s") { squeeze = true; idx += 1; continue; }
        if cstr_eq(p, b"-c") || cstr_eq(p, b"-C") || cstr_eq(p, b"--complement") {
            complement = true; idx += 1; continue;
        }
        if cstr_eq(p, b"-ds") || cstr_eq(p, b"-sd") {
            delete = true; squeeze = true; idx += 1; continue;
        }
        if cstr_eq(p, b"-cd") || cstr_eq(p, b"-dc") {
            delete = true; complement = true; idx += 1; continue;
        }
        if cstr_eq(p, b"-cs") || cstr_eq(p, b"-sc") {
            squeeze = true; complement = true; idx += 1; continue;
        }
        if cstr_eq(p, b"-cds") || cstr_eq(p, b"-csd") || cstr_eq(p, b"-dcs")
            || cstr_eq(p, b"-dsc") || cstr_eq(p, b"-scd") || cstr_eq(p, b"-sdc") {
            delete = true; squeeze = true; complement = true; idx += 1; continue;
        }
        if cstr_eq(p, b"--help") {
            let help: &[u8] = b"\
Usage: rust-tr [OPTION]... SET1 [SET2]
Translate, squeeze, and/or delete bytes from stdin to stdout.

  -d        delete bytes in SET1 (no translation)
  -s        squeeze runs of bytes in the last set to one byte each
  -c, -C, --complement   use the complement of SET1 wherever SET1
                         membership is consulted
      --help    show this help and exit

Sets accept literal bytes, 'a-z' style ranges, and '\\n' '\\t' '\\r'
'\\0' '\\\\' escapes.
\0";
            let len = help.len() - 1;
            unsafe { let _ = syscall3(sysn::WRITE, 1, help.as_ptr() as u64, len as u64); }
            return 0;
        }
        break;
    }
    // -d alone needs SET1; -d -s needs SET1 (the squeeze set falls
    // back to SET2-style empty); without -d we want SET1+SET2 unless
    // -s is set, in which case SET2 is optional.
    let pos_args = argc - idx;
    let valid = if delete {
        pos_args == 1 || (squeeze && pos_args == 2)
    } else if squeeze {
        pos_args == 1 || pos_args == 2
    } else {
        pos_args == 2
    };
    if !valid {
        write_str(STDERR, b"usage: rust-tr [-d] [-s] SET1 [SET2]\n");
        return 1;
    }
    let s1_p = unsafe { *argv.add(idx as usize) };
    let mut s1 = [0u8; 1024];
    let s1_n = match expand_set(s1_p, &mut s1) {
        Some(n) => n,
        None => {
            write_str(STDERR, b"rust-tr: SET1 too large\n");
            return 1;
        }
    };

    // Build 256-entry table.
    let mut tbl: [u8; 256] = [0; 256];
    for i in 0..256 { tbl[i] = i as u8; }
    let mut delmap: [bool; 256] = [false; 256];
    let mut squeezemap: [bool; 256] = [false; 256];
    // Direct SET1 membership map — needed for complement-aware tbl
    // construction (every byte NOT in SET1 maps to SET2[last]).
    let mut s1_member: [bool; 256] = [false; 256];
    for i in 0..s1_n { s1_member[s1[i] as usize] = true; }

    let mut s2_buf = [0u8; 1024];
    let mut s2_n = 0usize;
    let mut have_s2 = false;
    if !delete && pos_args == 2 {
        let s2_p = unsafe { *argv.add((idx + 1) as usize) };
        s2_n = match expand_set(s2_p, &mut s2_buf) {
            Some(n) => n,
            None => {
                write_str(STDERR, b"rust-tr: SET2 too large\n");
                return 1;
            }
        };
        if s2_n == 0 {
            write_str(STDERR, b"rust-tr: SET2 must be non-empty\n");
            return 1;
        }
        if complement {
            // Map every byte NOT in SET1 to SET2's last byte (GNU
            // semantics for `tr -c SET1 SET2`).
            let last = s2_buf[s2_n - 1];
            for c in 0..256 {
                if !s1_member[c] { tbl[c] = last; }
            }
        } else {
            for i in 0..s1_n {
                let mapped = if i < s2_n { s2_buf[i] } else { s2_buf[s2_n - 1] };
                tbl[s1[i] as usize] = mapped;
            }
        }
        have_s2 = true;
    } else if delete && pos_args == 2 {
        // -d -s SET1 SET2: delete SET1, squeeze SET2 in output.
        let s2_p = unsafe { *argv.add((idx + 1) as usize) };
        s2_n = match expand_set(s2_p, &mut s2_buf) {
            Some(n) => n,
            None => {
                write_str(STDERR, b"rust-tr: SET2 too large\n");
                return 1;
            }
        };
        have_s2 = true;
    }
    if delete {
        // -d: delete bytes in SET1 (or NOT in SET1 with -c).
        for c in 0..256 {
            let in_s1 = s1_member[c];
            delmap[c] = if complement { !in_s1 } else { in_s1 };
        }
    }
    if squeeze {
        // The squeeze set is SET2 if it's present, else SET1. -c only
        // applies to the SET1 fallback (GNU tr's documented rule).
        if have_s2 {
            for i in 0..s2_n { squeezemap[s2_buf[i] as usize] = true; }
        } else {
            for c in 0..256 {
                let in_s1 = s1_member[c];
                squeezemap[c] = if complement { !in_s1 } else { in_s1 };
            }
        }
    }

    let mut buf = [0u8; READ_BUF];
    let mut out = [0u8; READ_BUF];
    let mut had_error = false;
    let mut last_emitted: i32 = -1;  // -1 = "no previous byte yet"
    loop {
        let n = unsafe {
            syscall3(sysn::READ, STDIN as u64, buf.as_mut_ptr() as u64, buf.len() as u64)
        };
        if n < 0 {
            had_error = true;
            break;
        }
        if n == 0 {
            break;
        }
        let chunk = &buf[..n as usize];
        let mut w = 0usize;
        for &c in chunk {
            if delete && delmap[c as usize] { continue; }
            let mapped: u8 = if delete { c } else { tbl[c as usize] };
            // -s: skip a byte that's in the squeeze set AND matches
            // the previous emitted byte.
            if squeeze && squeezemap[mapped as usize]
                && last_emitted as i32 == mapped as i32 {
                continue;
            }
            out[w] = mapped;
            w += 1;
            last_emitted = mapped as i32;
            // out is at least READ_BUF, same length as buf in non-delete
            // mode; in delete mode w <= chunk len. Always fits.
        }
        if !write_all(STDOUT, &out[..w]) {
            had_error = true;
            break;
        }
    }
    if had_error { 1 } else { 0 }
}
