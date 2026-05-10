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

// Look up a single name. Returns true if at least one match was
// printed. With `find_all`, walks the entire PATH and prints every hit.
fn lookup_one(name_p: *const u8, name: &[u8], path_slice: &[u8], find_all: bool) -> bool {
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

    // Walk the colon-separated PATH. With find_all, keep walking after
    // the first hit so every match in PATH is printed.
    let mut start = 0usize;
    let mut any = false;
    for i in 0..=path_slice.len() {
        let at_end = i == path_slice.len();
        if at_end || path_slice[i] == b':' {
            let dir = &path_slice[start..i];
            if try_path(dir, name) {
                any = true;
                if !find_all { return true; }
            }
            start = i + 1;
        }
    }
    any
}

#[unsafe(no_mangle)]
pub extern "C" fn main(argc: i32, argv: *const *const u8, envp: *const *const u8) -> i32 {
    let mut find_all = false;
    let mut quiet = false;
    let mut idx: i32 = 1;
    while idx < argc {
        let p = unsafe { *argv.add(idx as usize) };
        if p.is_null() || (p as usize) < 0x10000 { break; }
        let n = cstr_len(p);
        // --help
        if n == 6 {
            let want = b"--help";
            let mut ok = true;
            for i in 0..want.len() {
                if unsafe { *p.add(i) } != want[i] { ok = false; break; }
            }
            if ok {
                let help: &[u8] = b"\
Usage: rust-which [-a] [-s] NAME [NAME...]
Print the resolved path of each NAME found in $PATH.

  -a, --all      print every match in PATH (not just the first)
  -s, --silent   no output; exit status reflects whether all NAMEs were found
      --help     show this help and exit
\0";
                let hlen = help.len() - 1;
                unsafe { let _ = syscall3(sysn::WRITE, STDOUT as u64,
                                          help.as_ptr() as u64, hlen as u64); }
                return 0;
            }
        }
        // -a / --all
        let is_a = n == 2 && unsafe { *p == b'-' && *p.add(1) == b'a' };
        let is_all = n == 5 && {
            let want = b"--all";
            let mut ok = true;
            for i in 0..want.len() {
                if unsafe { *p.add(i) } != want[i] { ok = false; break; }
            }
            ok
        };
        if is_a || is_all { find_all = true; idx += 1; continue; }
        // -s / --silent
        let is_s = n == 2 && unsafe { *p == b'-' && *p.add(1) == b's' };
        let is_silent = n == 8 && {
            let want = b"--silent";
            let mut ok = true;
            for i in 0..want.len() {
                if unsafe { *p.add(i) } != want[i] { ok = false; break; }
            }
            ok
        };
        if is_s || is_silent { quiet = true; idx += 1; continue; }
        // -- ends options
        if n == 2 && unsafe { *p == b'-' && *p.add(1) == b'-' } {
            idx += 1;
            break;
        }
        break;
    }
    if idx >= argc {
        write_str(STDERR, b"usage: rust-which [-a] [-s] <name> [<name>...]\n");
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

    // -s redirects stdout to /dev/null by stuffing a sentinel: the
    // simpler approach is to just skip the writes inside try_path. We
    // implement quiet by funneling lookup through a wrapper that
    // captures hit/miss without printing.
    let mut not_found = 0i32;
    for ai in idx..argc {
        let p = unsafe { *argv.add(ai as usize) };
        if p.is_null() || (p as usize) < 0x10000 {
            not_found += 1;
            continue;
        }
        let n = cstr_len(p);
        let name = unsafe { core::slice::from_raw_parts(p, n) };
        let hit = if quiet {
            silent_lookup(name, path_slice)
        } else {
            lookup_one(p, name, path_slice, find_all)
        };
        if !hit { not_found += 1; }
    }
    if not_found == 0 { 0 } else { 1 }
}

// Quiet lookup: same PATH walk as try_path, but with no stdout.
// Used by -s/--silent so the caller only has to inspect the exit status.
fn silent_lookup(name: &[u8], path_slice: &[u8]) -> bool {
    let mut has_slash = false;
    for &b in name {
        if b == b'/' { has_slash = true; break; }
    }
    let mut buf = [0u8; 1024];
    if has_slash {
        if name.len() + 1 > buf.len() { return false; }
        for (i, &b) in name.iter().enumerate() { buf[i] = b; }
        buf[name.len()] = 0;
        let fd = unsafe {
            syscall4(sysn::OPENAT, AT_FDCWD as u64, buf.as_ptr() as u64, O_RDONLY, 0) as i32
        };
        if fd >= 0 {
            unsafe { let _ = syscall1(sysn::CLOSE, fd as u64); }
            return true;
        }
        return false;
    }
    let mut start = 0usize;
    for i in 0..=path_slice.len() {
        let at_end = i == path_slice.len();
        if at_end || path_slice[i] == b':' {
            let dir = &path_slice[start..i];
            let dir_use: &[u8] = if dir.is_empty() { b"." } else { dir };
            if dir_use.len() + 1 + name.len() + 1 > buf.len() {
                start = i + 1;
                continue;
            }
            let mut n = 0usize;
            for &b in dir_use { buf[n] = b; n += 1; }
            if n == 0 || buf[n - 1] != b'/' { buf[n] = b'/'; n += 1; }
            for &b in name { buf[n] = b; n += 1; }
            buf[n] = 0;
            let fd = unsafe {
                syscall4(sysn::OPENAT, AT_FDCWD as u64, buf.as_ptr() as u64, O_RDONLY, 0) as i32
            };
            if fd >= 0 {
                unsafe { let _ = syscall1(sysn::CLOSE, fd as u64); }
                return true;
            }
            start = i + 1;
        }
    }
    false
}
