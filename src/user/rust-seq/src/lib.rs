// SPDX-License-Identifier: MPL-2.0
//
// rust-seq — print an arithmetic progression of integers.
//
//   rust-seq <last>                1..=last  (start=1, step=1)
//   rust-seq <first> <last>        first..=last (step=1)
//   rust-seq <first> <step> <last> first, first+step, … bounded by last
//   rust-seq -s SEP …              join with SEP instead of '\n'
//
// Integer-only — no float support yet (-f format / decimal step).
// Step may be negative for descending sequences. Empty sequence
// (first > last with positive step, or first < last with negative
// step) emits nothing and exits 0.
//
// `-s SEP` follows the GNU seq convention: the separator is placed
// between numbers and a single trailing newline is added at the end
// (so `seq -s , 1 3` prints "1,2,3\n", not "1,2,3,").

#![no_std]
#![forbid(unsafe_op_in_unsafe_fn)]

use core::panic::PanicInfo;

#[cfg(target_arch = "aarch64")]
mod sysn {
    pub const WRITE: u64 = 64;
    pub const EXIT: u64 = 93;
}

#[cfg(target_arch = "x86_64")]
mod sysn {
    pub const WRITE: u64 = 1;
    pub const EXIT: u64 = 60;
}

const STDOUT: i32 = 1;
const STDERR: i32 = 2;

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

fn write_str(fd: i32, s: &[u8]) {
    unsafe {
        let _ = syscall3(sysn::WRITE, fd as u64, s.as_ptr() as u64, s.len() as u64);
    }
}

#[panic_handler]
fn panic(_info: &PanicInfo) -> ! {
    write_str(STDERR, b"[rust-seq] panic\n");
    unsafe {
        sys_exit(1);
    }
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

fn parse_i64(p: *const u8) -> Option<i64> {
    let n = cstr_len(p);
    if n == 0 {
        return None;
    }
    let s = unsafe { core::slice::from_raw_parts(p, n) };
    let (mut i, neg) = if s[0] == b'-' { (1, true) }
                      else if s[0] == b'+' { (1, false) }
                      else { (0, false) };
    if i == n {
        return None;
    }
    let mut v: i64 = 0;
    while i < n {
        let c = s[i];
        if !(b'0'..=b'9').contains(&c) {
            return None;
        }
        let d = (c - b'0') as i64;
        // Build using i64 arithmetic; checked to avoid silent overflow.
        v = match v.checked_mul(10).and_then(|x| x.checked_add(d)) {
            Some(x) => x,
            None => return None,
        };
        i += 1;
    }
    Some(if neg { -v } else { v })
}

// Render n into buf, return its length.
fn fmt_i64(n: i64, buf: &mut [u8; 24]) -> usize {
    let mut i = buf.len();
    let neg = n < 0;
    // Handle i64::MIN safely by working in u64 magnitude.
    let mut mag: u64 = if neg { (n as i128).unsigned_abs() as u64 } else { n as u64 };
    let _ = n;
    if mag == 0 {
        i -= 1;
        buf[i] = b'0';
    } else {
        while mag > 0 {
            i -= 1;
            buf[i] = b'0' + (mag % 10) as u8;
            mag /= 10;
        }
    }
    if neg {
        i -= 1;
        buf[i] = b'-';
    }
    buf.len() - i
}

fn write_num(n: i64) -> bool {
    let mut buf = [0u8; 24];
    let len = fmt_i64(n, &mut buf);
    let off = buf.len() - len;
    let r = unsafe {
        syscall3(sysn::WRITE, STDOUT as u64, buf[off..].as_ptr() as u64, len as u64)
    };
    r > 0
}

// Render n with leading zeros so the total output is exactly `pad`
// columns wide. For negative numbers the sign comes first, then zero
// padding, then digits ("-007"). If the natural form is already at
// least `pad` chars, falls back to write_num.
fn write_num_padded(n: i64, pad: usize) -> bool {
    let mut buf = [0u8; 24];
    let len = fmt_i64(n, &mut buf);
    if len >= pad {
        let off = buf.len() - len;
        let r = unsafe {
            syscall3(sysn::WRITE, STDOUT as u64, buf[off..].as_ptr() as u64, len as u64)
        };
        return r > 0;
    }
    // Build padded form in a fresh buffer.
    let mut out = [0u8; 32];
    let total = pad.min(out.len());
    let off = buf.len() - len;
    let neg = buf[off] == b'-';
    let mut o = 0usize;
    if neg {
        out[o] = b'-';
        o += 1;
    }
    let zeros = total - len;
    for _ in 0..zeros { out[o] = b'0'; o += 1; }
    let digits_off = if neg { off + 1 } else { off };
    let digits_len = if neg { len - 1 } else { len };
    for i in 0..digits_len { out[o] = buf[digits_off + i]; o += 1; }
    let r = unsafe {
        syscall3(sysn::WRITE, STDOUT as u64, out.as_ptr() as u64, o as u64)
    };
    r > 0
}

fn arg_eq(p: *const u8, want: &[u8]) -> bool {
    for (i, &b) in want.iter().enumerate() {
        if unsafe { *p.add(i) } != b { return false; }
    }
    unsafe { *p.add(want.len()) == 0 }
}

const SEP_BUF: usize = 16;

#[unsafe(no_mangle)]
pub extern "C" fn main(argc: i32, argv: *const *const u8, _envp: *const *const u8) -> i32 {
    // Parse leading flags. -s SEP overrides the line separator. We
    // copy the SEP bytes into a local buffer so the borrow checker
    // doesn't complain about reading argv pointers later.
    let mut idx: i32 = 1;
    let mut sep_buf = [0u8; SEP_BUF];
    let mut sep_len: usize = 1;
    sep_buf[0] = b'\n';
    let mut equal_width = false;
    while idx < argc {
        let p = unsafe { *argv.add(idx as usize) };
        if p.is_null() || (p as usize) < 0x10000 { break; }
        if arg_eq(p, b"-w") || arg_eq(p, b"--equal-width") {
            equal_width = true;
            idx += 1;
            continue;
        }
        if arg_eq(p, b"-s") {
            if idx + 1 >= argc {
                write_str(STDERR, b"rust-seq: -s needs a separator\n");
                return 1;
            }
            let sp = unsafe { *argv.add((idx + 1) as usize) };
            if sp.is_null() || (sp as usize) < 0x10000 {
                return 1;
            }
            let sn = cstr_len(sp).min(SEP_BUF);
            for i in 0..sn { sep_buf[i] = unsafe { *sp.add(i) }; }
            sep_len = sn;
            idx += 2;
            continue;
        }
        if arg_eq(p, b"--") { idx += 1; break; }
        if arg_eq(p, b"--help") {
            let help: &[u8] = b"\
Usage: rust-seq [-s SEP] [FIRST [STEP]] LAST
Print integer sequences.

  rust-seq LAST              1..=LAST
  rust-seq FIRST LAST        FIRST..=LAST (step 1)
  rust-seq FIRST STEP LAST   FIRST, FIRST+STEP, ... bounded by LAST
  -s SEP                     join numbers with SEP (default newline)
  -w, --equal-width          pad numbers with leading zeros to equal width
      --help                     show this help and exit

STEP may be negative for descending sequences.
\0";
            let len = help.len() - 1;
            unsafe { let _ = syscall3(sysn::WRITE, STDOUT as u64,
                                       help.as_ptr() as u64, len as u64); }
            return 0;
        }
        break;
    }

    let nargs = argc - idx;
    if nargs < 1 || nargs > 3 {
        write_str(STDERR, b"usage: rust-seq [-s SEP] [<first> [<step>]] <last>\n");
        return 1;
    }
    let mut nums = [0i64; 3];
    for i in 0..nargs as usize {
        let p = unsafe { *argv.add(idx as usize + i) };
        if p.is_null() || (p as usize) < 0x10000 {
            write_str(STDERR, b"rust-seq: invalid argument\n");
            return 1;
        }
        match parse_i64(p) {
            Some(v) => nums[i] = v,
            None => {
                write_str(STDERR, b"rust-seq: invalid integer\n");
                return 1;
            }
        }
    }
    let (first, step, last) = match nargs {
        1 => (1i64, 1i64, nums[0]),
        2 => (nums[0], 1i64, nums[1]),
        3 => (nums[0], nums[1], nums[2]),
        _ => return 1,
    };
    if step == 0 {
        write_str(STDERR, b"rust-seq: step cannot be zero\n");
        return 1;
    }
    let ascending = step > 0;
    // For -w, compute pad width from endpoints. Sequence values stay
    // monotonic, so endpoints have the maximum natural width.
    let pad: usize = if equal_width {
        let mut a = [0u8; 24];
        let mut b = [0u8; 24];
        let la = fmt_i64(first, &mut a);
        let lb = fmt_i64(last, &mut b);
        if la > lb { la } else { lb }
    } else { 0 };
    let mut cur = first;
    let mut first_printed = true;
    loop {
        if ascending && cur > last { break; }
        if !ascending && cur < last { break; }
        if !first_printed {
            write_str(STDOUT, &sep_buf[..sep_len]);
        }
        let ok = if equal_width { write_num_padded(cur, pad) } else { write_num(cur) };
        if !ok { return 1; }
        first_printed = false;
        cur = match cur.checked_add(step) {
            Some(v) => v,
            None => break,
        };
    }
    // GNU seq always ends with a newline, even with a custom -s SEP.
    if !first_printed {
        write_str(STDOUT, b"\n");
    }
    0
}
