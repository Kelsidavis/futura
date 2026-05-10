// SPDX-License-Identifier: MPL-2.0
//
// rust-basename — print the file name component of a path.
//
//   rust-basename <path> [suffix]
//
// Mirrors POSIX basename(1):
//   basename "/a/b/c"        -> "c"
//   basename "/a/b/c.txt" .txt -> "c"
//   basename "/"             -> "/"
//   basename ""              -> "."
//
// Trailing slashes (other than on the lone "/" path) are stripped
// before the last-component search.

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
    write_str(STDERR, b"[rust-basename] panic\n");
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

fn ends_with(s: &[u8], suffix: &[u8]) -> bool {
    if suffix.is_empty() || suffix.len() >= s.len() {
        return false;
    }
    let off = s.len() - suffix.len();
    for i in 0..suffix.len() {
        if s[off + i] != suffix[i] {
            return false;
        }
    }
    true
}

// Compute basename(path) and optionally strip a trailing suffix.
// Writes the result + `term` to stdout.
fn emit_basename(path_p: *const u8, suffix: Option<&[u8]>, term: u8) {
    let path_n = cstr_len(path_p);
    let path = unsafe { core::slice::from_raw_parts(path_p, path_n) };
    if path.is_empty() {
        let buf = [b'.', term];
        write_str(STDOUT, &buf);
        return;
    }
    let mut end = path.len();
    while end > 1 && path[end - 1] == b'/' { end -= 1; }
    if end == 1 && path[0] == b'/' {
        let buf = [b'/', term];
        write_str(STDOUT, &buf);
        return;
    }
    let mut start = 0usize;
    let mut i = end;
    while i > 0 {
        if path[i - 1] == b'/' { start = i; break; }
        i -= 1;
    }
    let mut name = &path[start..end];
    if let Some(s) = suffix {
        if !s.is_empty() && name.len() > s.len() && ends_with(name, s) {
            name = &name[..name.len() - s.len()];
        }
    }
    write_str(STDOUT, name);
    let buf = [term];
    write_str(STDOUT, &buf);
}

#[unsafe(no_mangle)]
pub extern "C" fn main(argc: i32, argv: *const *const u8, _envp: *const *const u8) -> i32 {
    let mut multiple = false;
    let mut zero_term = false;
    let mut suffix_p: Option<*const u8> = None;
    let mut idx: i32 = 1;
    while idx < argc {
        let p = unsafe { *argv.add(idx as usize) };
        if p.is_null() || (p as usize) < 0x10000 { break; }
        let n = cstr_len(p);
        // --help
        if n == 6 && {
            let want = b"--help";
            let mut ok = true;
            for i in 0..want.len() { if unsafe { *p.add(i) } != want[i] { ok = false; break; } }
            ok
        } {
            let help: &[u8] = b"\
Usage: rust-basename PATH [SUFFIX]
       rust-basename -a [-s SUFFIX] [-z] PATH [PATH...]
Print PATH with any leading directory and trailing SUFFIX removed.

  -a, --multiple         support multiple PATH arguments
  -s, --suffix=SUFFIX    strip SUFFIX from each PATH (implies -a)
  -z, --zero             end each output line with NUL, not newline
      --help             show this help and exit
\0";
            let len = help.len() - 1;
            unsafe { let _ = syscall3(sysn::WRITE, 1, help.as_ptr() as u64, len as u64); }
            return 0;
        }
        // -a / --multiple
        let is_a = n == 2 && unsafe { *p == b'-' && *p.add(1) == b'a' };
        let is_amlong = n == 10 && {
            let want = b"--multiple";
            let mut ok = true;
            for i in 0..want.len() { if unsafe { *p.add(i) } != want[i] { ok = false; break; } }
            ok
        };
        if is_a || is_amlong { multiple = true; idx += 1; continue; }
        // -z / --zero
        let is_z = n == 2 && unsafe { *p == b'-' && *p.add(1) == b'z' };
        let is_zlong = n == 6 && {
            let want = b"--zero";
            let mut ok = true;
            for i in 0..want.len() { if unsafe { *p.add(i) } != want[i] { ok = false; break; } }
            ok
        };
        if is_z || is_zlong { zero_term = true; idx += 1; continue; }
        // -s SUFFIX
        let is_s = n == 2 && unsafe { *p == b'-' && *p.add(1) == b's' };
        if is_s {
            if idx + 1 >= argc {
                write_str(STDERR, b"rust-basename: -s needs a suffix\n");
                return 1;
            }
            let sp = unsafe { *argv.add((idx + 1) as usize) };
            if sp.is_null() || (sp as usize) < 0x10000 { return 1; }
            suffix_p = Some(sp);
            multiple = true;  // -s implies -a per GNU
            idx += 2;
            continue;
        }
        // --suffix=SUFFIX (long form with embedded =)
        if n >= 9 && unsafe {
            let want = b"--suffix=";
            let mut ok = true;
            for i in 0..want.len() { if *p.add(i) != want[i] { ok = false; break; } }
            ok
        } {
            suffix_p = Some(unsafe { p.add(9) });
            multiple = true;
            idx += 1;
            continue;
        }
        if n == 2 && unsafe { *p == b'-' && *p.add(1) == b'-' } {
            idx += 1;
            break;
        }
        break;
    }
    let term = if zero_term { 0u8 } else { b'\n' };
    if idx >= argc {
        write_str(STDERR, b"usage: rust-basename [-a] [-s SUFFIX] [-z] <path>...\n");
        return 1;
    }
    let suffix_slice: Option<&[u8]> = suffix_p.map(|p| {
        let n = cstr_len(p);
        unsafe { core::slice::from_raw_parts(p, n) }
    });
    if multiple {
        for ai in idx..argc {
            let p = unsafe { *argv.add(ai as usize) };
            if p.is_null() || (p as usize) < 0x10000 { continue; }
            emit_basename(p, suffix_slice, term);
        }
    } else {
        // Classic 1-or-2-arg form: PATH [SUFFIX].
        let path_p = unsafe { *argv.add(idx as usize) };
        if path_p.is_null() || (path_p as usize) < 0x10000 {
            write_str(STDERR, b"rust-basename: invalid argument\n");
            return 1;
        }
        let suf: Option<&[u8]> = if idx + 1 < argc {
            let sp = unsafe { *argv.add((idx + 1) as usize) };
            if sp.is_null() || (sp as usize) < 0x10000 { None }
            else {
                let sn = cstr_len(sp);
                Some(unsafe { core::slice::from_raw_parts(sp, sn) })
            }
        } else {
            None
        };
        emit_basename(path_p, suf, term);
    }
    0
}
