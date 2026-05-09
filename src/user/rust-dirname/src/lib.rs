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

#[unsafe(no_mangle)]
pub extern "C" fn main(argc: i32, argv: *const *const u8, _envp: *const *const u8) -> i32 {
    if argc == 2 {
        let pp = unsafe { *argv.add(1) };
        if !pp.is_null() && (pp as usize) >= 0x10000 {
            let want = b"--help";
            let mut n = 0; unsafe { while *pp.add(n) != 0 { n += 1; } }
            if n == want.len() {
                let mut ok = true;
                for i in 0..want.len() { if unsafe { *pp.add(i) } != want[i] { ok = false; break; } }
                if ok {
                    let help: &[u8] = b"\
Usage: rust-dirname PATH
Print PATH with the trailing component removed.

  --help    show this help and exit
\0";
                    let len = help.len() - 1;
                    unsafe { let _ = syscall3(sysn::WRITE, 1, help.as_ptr() as u64, len as u64); }
                    return 0;
                }
            }
        }
    }
    if argc < 2 {
        write_str(STDERR, b"usage: rust-dirname <path>\n");
        return 1;
    }
    let p = unsafe { *argv.add(1) };
    if p.is_null() || (p as usize) < 0x10000 {
        write_str(STDERR, b"rust-dirname: invalid argument\n");
        return 1;
    }
    let n = cstr_len(p);
    let path = unsafe { core::slice::from_raw_parts(p, n) };

    if path.is_empty() {
        write_str(STDOUT, b".\n");
        return 0;
    }

    // 1) Strip trailing slashes, keeping a lone "/".
    let mut end = path.len();
    while end > 1 && path[end - 1] == b'/' {
        end -= 1;
    }
    if end == 1 && path[0] == b'/' {
        write_str(STDOUT, b"/\n");
        return 0;
    }

    // 2) Strip the last path component (everything after the last '/' before `end`).
    let mut last_slash: Option<usize> = None;
    let mut i = end;
    while i > 0 {
        if path[i - 1] == b'/' {
            last_slash = Some(i - 1);
            break;
        }
        i -= 1;
    }
    let cut = match last_slash {
        // No slash at all -> "."
        None => {
            write_str(STDOUT, b".\n");
            return 0;
        }
        Some(idx) => idx,
    };

    // 3) Strip the slashes between dirname and basename, but keep the
    // root '/' if `cut` is at index 0 (e.g. "/foo" -> "/", not "").
    let mut e = cut;
    while e > 1 && path[e - 1] == b'/' {
        e -= 1;
    }
    if e == 0 {
        write_str(STDOUT, b"/\n");
        return 0;
    }

    write_str(STDOUT, &path[..e]);
    write_str(STDOUT, b"\n");
    0
}
