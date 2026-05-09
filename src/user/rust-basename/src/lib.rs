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

#[unsafe(no_mangle)]
pub extern "C" fn main(argc: i32, argv: *const *const u8, _envp: *const *const u8) -> i32 {
    if argc == 2 {
        let p = unsafe { *argv.add(1) };
        if !p.is_null() && (p as usize) >= 0x10000 {
            let want = b"--help";
            let mut n = 0; unsafe { while *p.add(n) != 0 { n += 1; } }
            if n == want.len() {
                let mut ok = true;
                for i in 0..want.len() { if unsafe { *p.add(i) } != want[i] { ok = false; break; } }
                if ok {
                    let help: &[u8] = b"\
Usage: rust-basename PATH [SUFFIX]
Print PATH with any leading directory and trailing SUFFIX removed.

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
        write_str(STDERR, b"usage: rust-basename <path> [suffix]\n");
        return 1;
    }
    let path_p = unsafe { *argv.add(1) };
    if path_p.is_null() || (path_p as usize) < 0x10000 {
        write_str(STDERR, b"rust-basename: invalid argument\n");
        return 1;
    }
    let path_n = cstr_len(path_p);
    let path = unsafe { core::slice::from_raw_parts(path_p, path_n) };

    // Empty path -> "."
    if path.is_empty() {
        write_str(STDOUT, b".\n");
        return 0;
    }

    // Strip trailing slashes, except keep a lone "/" intact.
    let mut end = path.len();
    while end > 1 && path[end - 1] == b'/' {
        end -= 1;
    }

    // If everything was "///...", end is now 1 and path[0]=='/'. Print "/".
    if end == 1 && path[0] == b'/' {
        write_str(STDOUT, b"/\n");
        return 0;
    }

    // Find the last '/' before `end`.
    let mut start = 0usize;
    let mut i = end;
    while i > 0 {
        if path[i - 1] == b'/' {
            start = i;
            break;
        }
        i -= 1;
    }

    let mut name = &path[start..end];

    // Optional suffix arg.
    if argc >= 3 {
        let sp = unsafe { *argv.add(2) };
        if !sp.is_null() && (sp as usize) >= 0x10000 {
            let sn = cstr_len(sp);
            let suffix = unsafe { core::slice::from_raw_parts(sp, sn) };
            if ends_with(name, suffix) {
                name = &name[..name.len() - suffix.len()];
            }
        }
    }

    write_str(STDOUT, name);
    write_str(STDOUT, b"\n");
    0
}
