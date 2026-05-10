// SPDX-License-Identifier: MPL-2.0
//
// rust-truncate — set a file's size via truncate(2).
//
//   rust-truncate -s <bytes> <file>
//
// If <bytes> is greater than the current size, the file is extended
// with sparse zeros (the kernel reserves no backing for the gap on
// FuturaFS' tmpfs). If smaller, the tail is dropped.
//
// No -c (no-create) yet — truncate(2) creates the file if it doesn't
// exist on Linux generic, which matches the GNU default.

#![no_std]
#![forbid(unsafe_op_in_unsafe_fn)]

use core::panic::PanicInfo;

#[cfg(target_arch = "aarch64")]
mod sysn {
    pub const WRITE: u64 = 64;
    pub const EXIT: u64 = 93;
    pub const TRUNCATE: u64 = 45;
}

#[cfg(target_arch = "x86_64")]
mod sysn {
    pub const WRITE: u64 = 1;
    pub const EXIT: u64 = 60;
    pub const TRUNCATE: u64 = 76;
}

const STDERR: i32 = 2;

#[cfg(target_arch = "aarch64")]
#[inline(always)]
unsafe fn syscall2(nr: u64, a: u64, b: u64) -> i64 {
    let mut ret: i64;
    unsafe {
        core::arch::asm!(
            "svc #0",
            in("x8") nr,
            inout("x0") a => ret,
            in("x1") b,
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
unsafe fn syscall2(nr: u64, a: u64, b: u64) -> i64 {
    let mut ret: i64;
    unsafe {
        core::arch::asm!(
            "syscall",
            inout("rax") nr => ret,
            in("rdi") a,
            in("rsi") b,
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

fn write_str(fd: i32, s: &[u8]) {
    unsafe {
        let _ = syscall3(sysn::WRITE, fd as u64, s.as_ptr() as u64, s.len() as u64);
    }
}

#[panic_handler]
fn panic(_info: &PanicInfo) -> ! {
    write_str(STDERR, b"[rust-truncate] panic\n");
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

// Parse SIZE: decimal digits, optionally followed by a single unit
// suffix. K=1024, M=1024², G=1024³, T=1024⁴ (binary multipliers, GNU
// truncate compat). Returns None on malformed input or overflow.
fn parse_u64(p: *const u8) -> Option<u64> {
    let mut n = 0usize;
    unsafe { while *p.add(n) != 0 { n += 1; } }
    if n == 0 || n > 24 {
        return None;
    }
    let s = unsafe { core::slice::from_raw_parts(p, n) };
    let mut digits_end = n;
    let mut multiplier: u64 = 1;
    if let Some(&last) = s.last() {
        let mult: u64 = match last {
            b'K' | b'k' => 1024,
            b'M' | b'm' => 1024 * 1024,
            b'G' | b'g' => 1024 * 1024 * 1024,
            b'T' | b't' => 1024u64 * 1024 * 1024 * 1024,
            b'B' | b'b' => 1,
            _ => 0,
        };
        if mult != 0 {
            multiplier = mult;
            digits_end -= 1;
        }
    }
    if digits_end == 0 { return None; }
    let mut v: u64 = 0;
    for &c in &s[..digits_end] {
        if !(b'0'..=b'9').contains(&c) {
            return None;
        }
        v = match v.checked_mul(10).and_then(|x| x.checked_add((c - b'0') as u64)) {
            Some(x) => x,
            None => return None,
        };
    }
    v.checked_mul(multiplier)
}

#[unsafe(no_mangle)]
pub extern "C" fn main(argc: i32, argv: *const *const u8, _envp: *const *const u8) -> i32 {
    let mut size_p: Option<*const u8> = None;
    let mut no_create = false;
    let mut idx: i32 = 1;
    while idx < argc {
        let p = unsafe { *argv.add(idx as usize) };
        if p.is_null() || (p as usize) < 0x10000 { break; }
        if cstr_eq(p, b"--help") {
            let help: &[u8] = b"\
Usage: rust-truncate [-c] -s NUM[KMGT] FILE [FILE...]
Set the size of each FILE to exactly NUM bytes (truncating or
extending with zeros as needed).

  -c, --no-create   skip files that don't exist (don't auto-create)
  -s, --size=NUM    target size; suffix K/M/G/T = 1024^1..^4
      --help        show this help and exit
\0";
            let len = help.len() - 1;
            unsafe { let _ = syscall3(sysn::WRITE, 1, help.as_ptr() as u64, len as u64); }
            return 0;
        }
        if cstr_eq(p, b"-c") || cstr_eq(p, b"--no-create") {
            no_create = true;
            idx += 1;
            continue;
        }
        if cstr_eq(p, b"-s") || cstr_eq(p, b"--size") {
            if idx + 1 >= argc {
                write_str(STDERR, b"rust-truncate: -s needs a size\n");
                return 1;
            }
            let np = unsafe { *argv.add((idx + 1) as usize) };
            if np.is_null() || (np as usize) < 0x10000 { return 1; }
            size_p = Some(np);
            idx += 2;
            continue;
        }
        // --size=NUM (long form with embedded =)
        let p_n = {
            let mut k = 0usize;
            unsafe { while *p.add(k) != 0 { k += 1; } }
            k
        };
        if p_n >= 7 && unsafe {
            let want = b"--size=";
            let mut ok = true;
            for j in 0..want.len() { if *p.add(j) != want[j] { ok = false; break; } }
            ok
        } {
            size_p = Some(unsafe { p.add(7) });
            idx += 1;
            continue;
        }
        if cstr_eq(p, b"--") { idx += 1; break; }
        break;
    }
    let size = match size_p {
        Some(p) => match parse_u64(p) {
            Some(v) => v,
            None => {
                write_str(STDERR, b"rust-truncate: invalid size\n");
                return 1;
            }
        },
        None => {
            write_str(STDERR, b"usage: rust-truncate [-c] -s <bytes>[KMGT] <file>...\n");
            return 1;
        }
    };
    if idx >= argc {
        write_str(STDERR, b"rust-truncate: at least one FILE required\n");
        return 1;
    }

    // ENOENT on Linux is -2.
    const ENOENT_NEG: i64 = -2;
    let mut had_error = false;
    for ai in idx..argc {
        let path = unsafe { *argv.add(ai as usize) };
        if path.is_null() || (path as usize) < 0x10000 {
            had_error = true;
            continue;
        }
        let r = unsafe { syscall2(sysn::TRUNCATE, path as u64, size) };
        if r < 0 {
            if no_create && r == ENOENT_NEG {
                continue;  // -c: silently skip non-existent files
            }
            write_str(STDERR, b"rust-truncate: cannot truncate '");
            let mut n = 0usize;
            unsafe { while *path.add(n) != 0 { n += 1; } }
            unsafe { let _ = syscall3(sysn::WRITE, STDERR as u64, path as u64, n as u64); }
            write_str(STDERR, b"'\n");
            had_error = true;
        }
    }
    if had_error { 1 } else { 0 }
}
