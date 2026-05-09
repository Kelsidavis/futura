// SPDX-License-Identifier: MPL-2.0
//
// rust-base64 — encode or decode base64 (RFC 4648).
//
//   rust-base64           encode stdin to base64 (76-col wrapped)
//   rust-base64 -d        decode base64 from stdin
//
// Encoded output is wrapped at 76 columns (matching GNU base64).
// Decoded input ignores whitespace (\n \r space tab).
// Standard alphabet only — no -url variant yet.
//
// Stream-style: 3 KiB input chunk → 4 KiB encoded chunk per round.
// No allocator.

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
// Multiples of 3 in / 4 out fit cleanly; 3*1024 = 3 KiB → 4 KiB out.
const ENC_IN_CHUNK: usize = 3 * 1024;
const ENC_OUT_CHUNK: usize = 4 * 1024;
const DEC_IN_CHUNK: usize = 4096;
const DEC_OUT_CHUNK: usize = 4096; // worst case = 3/4 of in

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
    write_str(STDERR, b"[rust-base64] panic\n");
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

const ALPHABET: &[u8; 64] =
    b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

// Encode `inp` (any length) into `out`, returning the number of
// output bytes written (always inp.len()/3*4, plus 4 for any
// 1- or 2-byte tail). Caller must ensure out has room.
fn encode_block(inp: &[u8], out: &mut [u8]) -> usize {
    let mut i = 0usize;
    let mut o = 0usize;
    while i + 3 <= inp.len() {
        let a = inp[i] as u32;
        let b = inp[i + 1] as u32;
        let c = inp[i + 2] as u32;
        let v = (a << 16) | (b << 8) | c;
        out[o] = ALPHABET[((v >> 18) & 0x3f) as usize];
        out[o + 1] = ALPHABET[((v >> 12) & 0x3f) as usize];
        out[o + 2] = ALPHABET[((v >> 6) & 0x3f) as usize];
        out[o + 3] = ALPHABET[(v & 0x3f) as usize];
        i += 3;
        o += 4;
    }
    let rem = inp.len() - i;
    if rem == 1 {
        let a = inp[i] as u32;
        let v = a << 16;
        out[o] = ALPHABET[((v >> 18) & 0x3f) as usize];
        out[o + 1] = ALPHABET[((v >> 12) & 0x3f) as usize];
        out[o + 2] = b'=';
        out[o + 3] = b'=';
        o += 4;
    } else if rem == 2 {
        let a = inp[i] as u32;
        let b = inp[i + 1] as u32;
        let v = (a << 16) | (b << 8);
        out[o] = ALPHABET[((v >> 18) & 0x3f) as usize];
        out[o + 1] = ALPHABET[((v >> 12) & 0x3f) as usize];
        out[o + 2] = ALPHABET[((v >> 6) & 0x3f) as usize];
        out[o + 3] = b'=';
        o += 4;
    }
    o
}

fn alphabet_index(c: u8) -> Option<u32> {
    match c {
        b'A'..=b'Z' => Some((c - b'A') as u32),
        b'a'..=b'z' => Some(26 + (c - b'a') as u32),
        b'0'..=b'9' => Some(52 + (c - b'0') as u32),
        b'+' => Some(62),
        b'/' => Some(63),
        _ => None,
    }
}

// `wrap` of 0 disables wrapping entirely (GNU base64 -w 0). Otherwise
// a newline is inserted every `wrap` output bytes.
fn encode(fd: i32, wrap: u32) -> i32 {
    let mut buf = [0u8; ENC_IN_CHUNK];
    let mut out = [0u8; ENC_OUT_CHUNK];
    let mut col: u32 = 0;
    loop {
        // Fill the input buffer up to ENC_IN_CHUNK so we always
        // process whole 3-byte groups (except for the final partial).
        let mut filled = 0usize;
        while filled < ENC_IN_CHUNK {
            let n = unsafe {
                syscall3(
                    sysn::READ,
                    fd as u64,
                    buf.as_mut_ptr().add(filled) as u64,
                    (ENC_IN_CHUNK - filled) as u64,
                )
            };
            if n < 0 { return 1; }
            if n == 0 { break; }
            filled += n as usize;
        }
        if filled == 0 { break; }

        // ENC_IN_CHUNK is a multiple of 3, so a fully-filled buffer
        // produces 0 trailing pads. A partial fill (the EOF case)
        // produces 1 or 2 pads from encode_block's tail handling.
        let n_out = encode_block(&buf[..filled], &mut out);

        if wrap == 0 {
            if !write_all(STDOUT, &out[..n_out]) { return 1; }
        } else {
            // Wrap output at `wrap` columns.
            let mut written = 0usize;
            while written < n_out {
                let avail = (wrap - col) as usize;
                let take = avail.min(n_out - written);
                if !write_all(STDOUT, &out[written..written + take]) { return 1; }
                col += take as u32;
                written += take;
                if col == wrap {
                    if !write_all(STDOUT, b"\n") { return 1; }
                    col = 0;
                }
            }
        }
        if filled < ENC_IN_CHUNK { break; }
    }
    // Flush a trailing partial line on wrapped output. With wrap == 0
    // we never started a "line" — but we still want a final newline
    // so the output ends cleanly the way GNU base64 does.
    if wrap == 0 {
        if !write_all(STDOUT, b"\n") { return 1; }
    } else if col != 0 {
        if !write_all(STDOUT, b"\n") { return 1; }
    }
    0
}

fn decode(fd: i32, ignore_garbage: bool) -> i32 {
    let mut buf = [0u8; DEC_IN_CHUNK];
    let mut out = [0u8; DEC_OUT_CHUNK];
    // 4-byte accumulator across read boundaries.
    let mut quad = [0u32; 4];
    let mut q_len = 0usize;
    let mut had_pad = false;
    loop {
        let n = unsafe {
            syscall3(sysn::READ, fd as u64, buf.as_mut_ptr() as u64, buf.len() as u64)
        };
        if n < 0 { return 1; }
        if n == 0 { break; }
        let chunk = &buf[..n as usize];
        let mut o = 0usize;
        for &c in chunk {
            // Skip whitespace.
            if c == b'\n' || c == b'\r' || c == b' ' || c == b'\t' { continue; }
            if c == b'=' {
                had_pad = true;
                // Use 0x40 (out-of-alphabet) as a pad sentinel so
                // pad_count_for() can recover how many trailing pads
                // were in the 4-byte group. ALPHABET only emits
                // values 0..63, so 0x40 is safely reserved.
                quad[q_len] = 0x40;
                q_len += 1;
            } else if !had_pad {
                match alphabet_index(c) {
                    Some(v) => {
                        quad[q_len] = v;
                        q_len += 1;
                    }
                    None => {
                        if ignore_garbage { continue; }
                        write_str(STDERR, b"rust-base64: invalid input byte\n");
                        return 1;
                    }
                }
            } else {
                // Non-pad byte after pad: with -i silently skip; without it,
                // bail because data continuing past padding indicates a
                // corrupted stream.
                if ignore_garbage { continue; }
                write_str(STDERR, b"rust-base64: data after padding\n");
                return 1;
            }
            if q_len == 4 {
                let pads = pad_count_for(quad);
                // Mask sentinel back to 0 for the bit-pack arithmetic
                // — we already know how many pads above.
                let q0 = quad[0] & 0x3f;
                let q1 = quad[1] & 0x3f;
                let q2 = quad[2] & 0x3f;
                let q3 = quad[3] & 0x3f;
                let v = (q0 << 18) | (q1 << 12) | (q2 << 6) | q3;
                out[o] = ((v >> 16) & 0xff) as u8;
                if pads < 2 { out[o + 1] = ((v >> 8) & 0xff) as u8; }
                if pads < 1 { out[o + 2] = (v & 0xff) as u8; }
                o += 3 - pads;
                q_len = 0;
                if o + 3 > out.len() {
                    if !write_all(STDOUT, &out[..o]) { return 1; }
                    o = 0;
                }
            }
        }
        if o > 0 {
            if !write_all(STDOUT, &out[..o]) { return 1; }
        }
    }
    let _ = had_pad;
    let _ = q_len;
    0
}

// '=' was inserted as 0x40 (out-of-alphabet sentinel). Trailing pads
// are at quad[3] (1 pad) or quad[2..=3] (2 pads); base64 doesn't put
// pads anywhere else.
fn pad_count_for(quad: [u32; 4]) -> usize {
    let mut pads = 0;
    for i in (0..4).rev() {
        if quad[i] == 0x40 { pads += 1; } else { break; }
    }
    pads
}

// Parse a small decimal u32 (0..=10000 range covers reasonable wrap
// widths). Returns None on a non-digit or overflow.
fn parse_u32_small(p: *const u8) -> Option<u32> {
    let mut n = 0usize;
    unsafe { while *p.add(n) != 0 { n += 1; } }
    if n == 0 { return None; }
    let mut v: u32 = 0;
    for i in 0..n {
        let c = unsafe { *p.add(i) };
        if !(b'0'..=b'9').contains(&c) { return None; }
        v = v.checked_mul(10)?.checked_add((c - b'0') as u32)?;
        if v > 10_000 { return None; }
    }
    Some(v)
}

#[unsafe(no_mangle)]
pub extern "C" fn main(argc: i32, argv: *const *const u8, _envp: *const *const u8) -> i32 {
    let mut do_decode = false;
    let mut ignore_garbage = false;
    let mut wrap: u32 = 76;  // GNU default
    let mut input_path: Option<*const u8> = None;
    let mut idx: i32 = 1;
    while idx < argc {
        let p = unsafe { *argv.add(idx as usize) };
        if p.is_null() || (p as usize) < 0x10000 {
            idx += 1;
            continue;
        }
        if cstr_eq(p, b"-d") || cstr_eq(p, b"--decode") {
            do_decode = true;
            idx += 1;
        } else if cstr_eq(p, b"-i") || cstr_eq(p, b"--ignore-garbage") {
            ignore_garbage = true;
            idx += 1;
        } else if cstr_eq(p, b"-w") || cstr_eq(p, b"--wrap") {
            if idx + 1 >= argc {
                write_str(STDERR, b"rust-base64: -w needs a column count (0 disables wrapping)\n");
                return 1;
            }
            let wp = unsafe { *argv.add((idx + 1) as usize) };
            if wp.is_null() || (wp as usize) < 0x10000 {
                return 1;
            }
            match parse_u32_small(wp) {
                Some(v) => wrap = v,
                None => {
                    write_str(STDERR, b"rust-base64: invalid -w value\n");
                    return 1;
                }
            }
            idx += 2;
        } else if cstr_eq(p, b"--") {
            idx += 1;
            if idx < argc {
                let q = unsafe { *argv.add(idx as usize) };
                if !q.is_null() && (q as usize) >= 0x10000 {
                    input_path = Some(q);
                }
            }
            break;
        } else {
            // First non-flag positional arg is the FILE (matches GNU
            // base64's `[FILE]` shape).
            input_path = Some(p);
            break;
        }
    }

    let mut fd: i32 = STDIN;
    if let Some(p) = input_path {
        let mut nlen = 0usize;
        unsafe { while *p.add(nlen) != 0 { nlen += 1; } }
        let is_dash = nlen == 1 && unsafe { *p } == b'-';
        if !is_dash {
            let f = unsafe {
                syscall4(sysn::OPENAT, AT_FDCWD as u64, p as u64, O_RDONLY, 0) as i32
            };
            if f < 0 {
                write_str(STDERR, b"rust-base64: cannot open '");
                unsafe { let _ = syscall3(sysn::WRITE, STDERR as u64, p as u64, nlen as u64); }
                write_str(STDERR, b"'\n");
                return 1;
            }
            fd = f;
        }
    }

    let rc = if do_decode { decode(fd, ignore_garbage) } else { encode(fd, wrap) };
    if fd != STDIN {
        unsafe { let _ = syscall1(sysn::CLOSE, fd as u64); }
    }
    rc
}
