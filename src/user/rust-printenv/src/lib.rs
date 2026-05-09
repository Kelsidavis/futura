// SPDX-License-Identifier: MPL-2.0
//
// rust-printenv — print environment variables.
//
//   rust-printenv          dump every NAME=VALUE one per line
//   rust-printenv NAME...  print the value of each named variable
//                          on its own line; exit 1 if any are unset.
//
// Differs from rust-env in that the named-args form prints VALUE only
// (no NAME= prefix) — matches GNU printenv(1).

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
    write_str(STDERR, b"[rust-printenv] panic\n");
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

// Look up a NAME in envp. Returns Some((value_ptr, value_len)) when
// found, None otherwise. Matches against the literal name; doesn't
// support '=' inside the name.
fn env_lookup(envp: *const *const u8, name: &[u8]) -> Option<(*const u8, usize)> {
    if envp.is_null() {
        return None;
    }
    let mut i = 0usize;
    loop {
        let entry = unsafe { *envp.add(i) };
        if entry.is_null() {
            return None;
        }
        if (entry as usize) < 0x10000 {
            return None;
        }
        let mut ok = true;
        for j in 0..name.len() {
            if unsafe { *entry.add(j) } != name[j] {
                ok = false;
                break;
            }
        }
        if ok && unsafe { *entry.add(name.len()) } == b'=' {
            let v = unsafe { entry.add(name.len() + 1) };
            let n = cstr_len(v);
            return Some((v, n));
        }
        i += 1;
    }
}

fn arg_eq(p: *const u8, want: &[u8]) -> bool {
    for (i, &b) in want.iter().enumerate() {
        if unsafe { *p.add(i) } != b { return false; }
    }
    unsafe { *p.add(want.len()) == 0 }
}

#[unsafe(no_mangle)]
pub extern "C" fn main(argc: i32, argv: *const *const u8, envp: *const *const u8) -> i32 {
    // Parse leading flags. -0 / --null switches the separator from
    // '\n' to '\0' so output can feed `xargs -0`-style consumers
    // without ambiguity over names containing newlines.
    let mut sep: u8 = b'\n';
    let mut idx: i32 = 1;
    while idx < argc {
        let p = unsafe { *argv.add(idx as usize) };
        if p.is_null() || (p as usize) < 0x10000 { break; }
        if arg_eq(p, b"-0") || arg_eq(p, b"--null") {
            sep = 0;
            idx += 1;
            continue;
        }
        if arg_eq(p, b"--") { idx += 1; break; }
        if arg_eq(p, b"--help") {
            let help: &[u8] = b"\
Usage: rust-printenv [-0] [VAR...]
Print the named environment variables. With no VAR, dump them all.

  -0, --null   separate entries with NUL instead of newline
      --help       show this help and exit
\0";
            let len = help.len() - 1;
            unsafe { let _ = syscall3(sysn::WRITE, STDOUT as u64,
                                       help.as_ptr() as u64, len as u64); }
            return 0;
        }
        break;
    }

    if idx >= argc {
        // Dump every entry.
        if envp.is_null() {
            return 0;
        }
        let mut i = 0usize;
        loop {
            let e = unsafe { *envp.add(i) };
            if e.is_null() {
                break;
            }
            if (e as usize) < 0x10000 {
                break;
            }
            let n = cstr_len(e);
            unsafe {
                let _ = syscall3(sysn::WRITE, STDOUT as u64, e as u64, n as u64);
            }
            let term = [sep];
            unsafe {
                let _ = syscall3(sysn::WRITE, STDOUT as u64, term.as_ptr() as u64, 1);
            }
            i += 1;
        }
        return 0;
    }

    // Print value of each named var. Exit 1 if any are unset.
    let mut had_missing = false;
    for ai in idx..argc {
        let p = unsafe { *argv.add(ai as usize) };
        if p.is_null() || (p as usize) < 0x10000 {
            had_missing = true;
            continue;
        }
        let nlen = cstr_len(p);
        let name = unsafe { core::slice::from_raw_parts(p, nlen) };
        match env_lookup(envp, name) {
            Some((vp, vn)) => {
                unsafe {
                    let _ = syscall3(sysn::WRITE, STDOUT as u64, vp as u64, vn as u64);
                }
                let term = [sep];
                unsafe {
                    let _ = syscall3(sysn::WRITE, STDOUT as u64, term.as_ptr() as u64, 1);
                }
            }
            None => {
                had_missing = true;
            }
        }
    }
    if had_missing { 1 } else { 0 }
}
