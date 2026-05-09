// SPDX-License-Identifier: MPL-2.0
//
// rust-which — locate an executable on $PATH.
//
//   rust-which <name>       prints the first matching path; exits 0
//                            on hit, 1 on miss, 2 on usage error.
//
// Iterates colon-separated entries of $PATH (defaulting to
// "/bin:/sbin" when the env var is unset). For each entry, builds
// "<entry>/<name>" in a fixed stack buffer and openat(O_RDONLY)
// — present-and-readable is treated as "found", which matches what
// shells use $PATH for. Empty PATH entries mean cwd, mirroring
// POSIX behaviour.

#![no_std]
#![forbid(unsafe_op_in_unsafe_fn)]

use core::panic::PanicInfo;

#[cfg(target_arch = "aarch64")]
mod sysn {
    pub const WRITE: u64 = 64;
    pub const EXIT: u64 = 93;
    pub const OPENAT: u64 = 56;
    pub const CLOSE: u64 = 57;
}

#[cfg(target_arch = "x86_64")]
mod sysn {
    pub const WRITE: u64 = 1;
    pub const EXIT: u64 = 60;
    pub const OPENAT: u64 = 257;
    pub const CLOSE: u64 = 3;
}

const AT_FDCWD: i64 = -100;
const O_RDONLY: u64 = 0;
const STDOUT: i32 = 1;
const STDERR: i32 = 2;

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
    write_str(STDERR, b"[rust-which] panic\n");
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

fn env_lookup_path(envp: *const *const u8) -> Option<*const u8> {
    if envp.is_null() {
        return None;
    }
    let key = b"PATH";
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
        for j in 0..key.len() {
            if unsafe { *entry.add(j) } != key[j] {
                ok = false;
                break;
            }
        }
        if ok && unsafe { *entry.add(key.len()) } == b'=' {
            return Some(unsafe { entry.add(key.len() + 1) });
        }
        i += 1;
    }
}

// Try opening "<dir>/<name>" relative to AT_FDCWD. Returns true if the
// resulting path is openable for read.
fn try_path(dir: &[u8], name: &[u8]) -> bool {
    let mut buf = [0u8; 512];
    let mut n = 0usize;

    let dir_use: &[u8] = if dir.is_empty() { b"." } else { dir };
    if dir_use.len() + 1 + name.len() + 1 > buf.len() {
        return false;
    }
    for &b in dir_use {
        buf[n] = b;
        n += 1;
    }
    if n == 0 || buf[n - 1] != b'/' {
        buf[n] = b'/';
        n += 1;
    }
    for &b in name {
        buf[n] = b;
        n += 1;
    }
    buf[n] = 0;

    let fd = unsafe {
        syscall4(sysn::OPENAT, AT_FDCWD as u64, buf.as_ptr() as u64, O_RDONLY, 0) as i32
    };
    if fd >= 0 {
        unsafe {
            let _ = syscall1(sysn::CLOSE, fd as u64);
        }
        // On success, print the path we just verified.
        write_str(STDOUT, &buf[..n]);
        write_str(STDOUT, b"\n");
        return true;
    }
    false
}

// Look up a single name. Returns true on success (path printed).
fn lookup_one(name_p: *const u8, name: &[u8], path_slice: &[u8]) -> bool {
    // If the name itself contains a slash, treat it as a literal path —
    // POSIX which(1) does the same.
    let mut has_slash = false;
    for &b in name {
        if b == b'/' { has_slash = true; break; }
    }
    if has_slash {
        let fd = unsafe {
            syscall4(sysn::OPENAT, AT_FDCWD as u64, name_p as u64, O_RDONLY, 0) as i32
        };
        if fd >= 0 {
            unsafe { let _ = syscall1(sysn::CLOSE, fd as u64); }
            write_str(STDOUT, name);
            write_str(STDOUT, b"\n");
            return true;
        }
        return false;
    }

    // Walk the colon-separated PATH.
    let mut start = 0usize;
    for i in 0..=path_slice.len() {
        let at_end = i == path_slice.len();
        if at_end || path_slice[i] == b':' {
            let dir = &path_slice[start..i];
            if try_path(dir, name) { return true; }
            start = i + 1;
        }
    }
    false
}

#[unsafe(no_mangle)]
pub extern "C" fn main(argc: i32, argv: *const *const u8, envp: *const *const u8) -> i32 {
    if argc == 2 {
        let first = unsafe { *argv.add(1) };
        if !first.is_null() && (first as usize) >= 0x10000 {
            let want = b"--help";
            let n = cstr_len(first);
            if n == want.len() {
                let mut ok = true;
                for i in 0..want.len() {
                    if unsafe { *first.add(i) } != want[i] { ok = false; break; }
                }
                if ok {
                    let help: &[u8] = b"\
Usage: rust-which NAME [NAME...]
Print the resolved path of each NAME found in $PATH.

  --help    show this help and exit
\0";
                    let len = help.len() - 1;
                    unsafe { let _ = syscall3(sysn::WRITE, STDOUT as u64,
                                              help.as_ptr() as u64, len as u64); }
                    return 0;
                }
            }
        }
    }
    if argc < 2 {
        write_str(STDERR, b"usage: rust-which <name> [<name>...]\n");
        return 2;
    }

    // Resolve PATH once; default to "/bin:/sbin" if unset.
    let path_ptr = env_lookup_path(envp);
    let default_path: &[u8] = b"/bin:/sbin";
    let path_slice: &[u8] = match path_ptr {
        Some(p) => {
            let n = cstr_len(p);
            unsafe { core::slice::from_raw_parts(p, n) }
        }
        None => default_path,
    };

    let mut not_found = 0i32;
    for ai in 1..argc {
        let p = unsafe { *argv.add(ai as usize) };
        if p.is_null() || (p as usize) < 0x10000 {
            not_found += 1;
            continue;
        }
        let n = cstr_len(p);
        let name = unsafe { core::slice::from_raw_parts(p, n) };
        if !lookup_one(p, name, path_slice) {
            not_found += 1;
        }
    }
    // GNU which exits with the count of names that weren't found
    // (clamped to 0/1/2: 0=all found, otherwise 1).
    if not_found == 0 { 0 } else { 1 }
}
