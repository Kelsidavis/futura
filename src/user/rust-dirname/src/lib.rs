// SPDX-License-Identifier: MPL-2.0
//
// rust-dirname — print the directory portion of a path.
//
//   rust-dirname /a/b/c     -> "/a/b"
//   rust-dirname /a/b/c/    -> "/a/b"
//   rust-dirname c          -> "."
//   rust-dirname /          -> "/"
//   rust-dirname ""         -> "."
//
// POSIX algorithm: strip trailing slashes (keeping a lone "/"),
// then strip the last component, then strip the slashes that
// separated it (again keeping a lone "/").

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
    write_str(STDERR, b"[rust-dirname] panic\n");
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

// Compute dirname(path) and emit it followed by `term`.
fn emit_dirname(p: *const u8, term: u8) {
    let n = cstr_len(p);
    let path = unsafe { core::slice::from_raw_parts(p, n) };
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
    let mut last_slash: Option<usize> = None;
    let mut i = end;
    while i > 0 {
        if path[i - 1] == b'/' { last_slash = Some(i - 1); break; }
        i -= 1;
    }
    let cut = match last_slash {
        None => { let buf = [b'.', term]; write_str(STDOUT, &buf); return; }
        Some(idx) => idx,
    };
    let mut e = cut;
    while e > 1 && path[e - 1] == b'/' { e -= 1; }
    if e == 0 {
        let buf = [b'/', term];
        write_str(STDOUT, &buf);
        return;
    }
    write_str(STDOUT, &path[..e]);
    let buf = [term];
    write_str(STDOUT, &buf);
}

#[unsafe(no_mangle)]
pub extern "C" fn main(argc: i32, argv: *const *const u8, _envp: *const *const u8) -> i32 {
    let mut zero_term = false;
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
Usage: rust-dirname [-z] PATH [PATH...]
Print each PATH with the trailing component removed.

  -z, --zero    end each output line with NUL, not newline
      --help    show this help and exit
\0";
            let len = help.len() - 1;
            unsafe { let _ = syscall3(sysn::WRITE, 1, help.as_ptr() as u64, len as u64); }
            return 0;
        }
        let is_z = n == 2 && unsafe { *p == b'-' && *p.add(1) == b'z' };
        let is_zlong = n == 6 && {
            let want = b"--zero";
            let mut ok = true;
            for i in 0..want.len() { if unsafe { *p.add(i) } != want[i] { ok = false; break; } }
            ok
        };
        if is_z || is_zlong { zero_term = true; idx += 1; continue; }
        if n == 2 && unsafe { *p == b'-' && *p.add(1) == b'-' } {
            idx += 1;
            break;
        }
        break;
    }
    if idx >= argc {
        write_str(STDERR, b"usage: rust-dirname [-z] <path>...\n");
        return 1;
    }
    let term = if zero_term { 0u8 } else { b'\n' };
    for ai in idx..argc {
        let p = unsafe { *argv.add(ai as usize) };
        if p.is_null() || (p as usize) < 0x10000 { continue; }
        emit_dirname(p, term);
    }
    0
}
