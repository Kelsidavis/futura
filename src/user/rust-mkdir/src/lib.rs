// SPDX-License-Identifier: MPL-2.0
//
// rust-mkdir — fifth user-space Rust program for Futura OS.
//
// Creates directories listed on the command line. Without options
// each path must be a single new component; with -p, missing parent
// components are created along the way (idempotent — already-existing
// dirs are not an error). Mode 0o755 is used for every component.
//
// Exit code is 0 if every requested path exists when we return, 1
// otherwise.

#![no_std]
#![forbid(unsafe_op_in_unsafe_fn)]

use core::panic::PanicInfo;

#[cfg(target_arch = "aarch64")]
mod sysn {
    pub const WRITE: u64 = 64;
    pub const EXIT: u64 = 93;
    pub const MKDIRAT: u64 = 34;
}

#[cfg(target_arch = "x86_64")]
mod sysn {
    pub const WRITE: u64 = 1;
    pub const EXIT: u64 = 60;
    pub const MKDIR: u64 = 83;
}

const AT_FDCWD: i64 = -100;
const STDOUT: i32 = 1;
const STDERR: i32 = 2;

const EEXIST: i64 = -17;

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
unsafe fn sys_mkdir_at(path: *const u8, mode: u32) -> i64 {
    unsafe { syscall3(sysn::MKDIRAT, AT_FDCWD as u64, path as u64, mode as u64) }
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
unsafe fn sys_mkdir_at(path: *const u8, mode: u32) -> i64 {
    unsafe { syscall2(sysn::MKDIR, path as u64, mode as u64) }
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
    write_str(STDERR, b"[rust-mkdir] panic\n");
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

fn argv_get(argc: i32, argv: *const *const u8, idx: usize) -> Option<*const u8> {
    if (idx as i32) >= argc {
        return None;
    }
    unsafe {
        let p = *argv.add(idx);
        if p.is_null() { None } else { Some(p) }
    }
}

fn arg_is(p: *const u8, want: &[u8]) -> bool {
    let n = cstr_len(p);
    if n != want.len() {
        return false;
    }
    for i in 0..n {
        if unsafe { *p.add(i) } != want[i] {
            return false;
        }
    }
    true
}

// Make a single component (no recursion). Treats EEXIST as success
// only when the caller asked for -p semantics; otherwise EEXIST is
// reported as an error like classic mkdir(1).
fn make_one(path_buf: &[u8], permissive: bool, mode: u32) -> bool {
    // Path buffer must be NUL-terminated by the caller.
    let rc = unsafe { sys_mkdir_at(path_buf.as_ptr(), mode) };
    if rc == 0 {
        true
    } else if permissive && rc == EEXIST {
        true
    } else {
        write_str(STDERR, b"rust-mkdir: cannot create '");
        // Trim trailing NUL for the message.
        let mut end = path_buf.len();
        if end > 0 && path_buf[end - 1] == 0 {
            end -= 1;
        }
        write_str(STDERR, &path_buf[..end]);
        write_str(STDERR, b"'\n");
        false
    }
}

// Walk the supplied path component-by-component, creating each
// intermediate directory. The buffer must be at least `path.len + 1`
// bytes so we can NUL-terminate after every prefix slice. Intermediate
// dirs are always created with 0o755 (matches GNU mkdir -p): the
// user-supplied -m only applies to the final component, otherwise a
// restrictive mode like 0700 on the leaf would also lock us out of
// every parent we just made.
fn make_recursive(path: &[u8], buf: &mut [u8], leaf_mode: u32) -> bool {
    if path.is_empty() {
        return true;
    }
    let mut ok = true;
    let mut i = 0usize;
    // Skip leading slashes — root always exists.
    while i < path.len() && path[i] == b'/' {
        buf[i] = path[i];
        i += 1;
    }
    while i < path.len() {
        // Advance to the next '/' (or end).
        while i < path.len() && path[i] != b'/' {
            buf[i] = path[i];
            i += 1;
        }
        if i == 0 {
            // Empty component — ignore.
            continue;
        }
        // NUL-terminate the prefix and create it. Skip empty
        // components produced by "//" runs.
        if i > 0 && buf[i - 1] != b'/' {
            buf[i] = 0;
            // Don't treat root or the trailing slash as a target.
            if !(buf[..i].iter().all(|&c| c == b'/')) {
                let is_leaf = i == path.len();
                let mode = if is_leaf { leaf_mode } else { 0o755 };
                if !make_one(&buf[..=i], true, mode) {
                    ok = false;
                    break;
                }
            }
        }
        // Skip the slash and any consecutive ones.
        while i < path.len() && path[i] == b'/' {
            buf[i] = path[i];
            i += 1;
        }
    }
    ok
}

// Parse a 1-4 digit octal mode string (e.g. "755", "0700"). Returns
// None on a non-octal character. Symbolic modes (u+x, etc.) are not
// supported here.
fn parse_octal_mode(p: *const u8) -> Option<u32> {
    let mut n = 0usize;
    unsafe { while *p.add(n) != 0 { n += 1; } }
    if n == 0 || n > 5 { return None; }
    let mut v: u32 = 0;
    for i in 0..n {
        let c = unsafe { *p.add(i) };
        // Allow a leading '0' but otherwise require octal digits.
        if !(b'0'..=b'7').contains(&c) { return None; }
        v = v.checked_mul(8)?.checked_add((c - b'0') as u32)?;
        if v > 0o7777 { return None; }
    }
    Some(v)
}

#[unsafe(no_mangle)]
pub extern "C" fn main(argc: i32, argv: *const *const u8, _envp: *const *const u8) -> i32 {
    let mut idx: usize = 1;
    let mut p_flag = false;
    let mut verbose = false;
    let mut mode: u32 = 0o755;

    // Parse the optional -p / -m / -v flags.
    while let Some(p) = argv_get(argc, argv, idx) {
        if arg_is(p, b"-p") || arg_is(p, b"--parents") {
            p_flag = true;
            idx += 1;
        } else if arg_is(p, b"-v") || arg_is(p, b"--verbose") {
            verbose = true;
            idx += 1;
        } else if arg_is(p, b"-pv") || arg_is(p, b"-vp") {
            p_flag = true;
            verbose = true;
            idx += 1;
        } else if arg_is(p, b"-m") || arg_is(p, b"--mode") {
            // -m <mode> takes a separate token. --mode <mode> is
            // the GNU long form; --mode=<mode> handled below.
            idx += 1;
            match argv_get(argc, argv, idx) {
                Some(mp) => match parse_octal_mode(mp) {
                    Some(v) => { mode = v; idx += 1; }
                    None => {
                        write_str(STDERR, b"rust-mkdir: -m needs an octal mode (e.g. 755)\n");
                        return 1;
                    }
                },
                None => {
                    write_str(STDERR, b"rust-mkdir: -m needs an argument\n");
                    return 1;
                }
            }
        } else if {
            // --mode=MODE long form with embedded =
            let mut k = 0usize;
            unsafe { while *p.add(k) != 0 { k += 1; } }
            k > 7 && unsafe {
                let want = b"--mode=";
                let mut ok = true;
                for j in 0..want.len() { if *p.add(j) != want[j] { ok = false; break; } }
                ok
            }
        } {
            let mp = unsafe { p.add(7) };
            match parse_octal_mode(mp) {
                Some(v) => { mode = v; idx += 1; }
                None => {
                    write_str(STDERR, b"rust-mkdir: invalid --mode (must be octal, e.g. 755)\n");
                    return 1;
                }
            }
        } else if arg_is(p, b"--") {
            idx += 1;
            break;
        } else if arg_is(p, b"--help") {
            let help: &[u8] = b"\
Usage: rust-mkdir [-pv] [-m MODE] DIR [DIR...]
Create each DIR.

  -p, --parents    create parent directories as needed (no error if exists)
  -m, --mode MODE  set the leaf mode (octal, e.g. 700)
  -v           emit \"created directory '<dir>'\" for each new dir
      --help       show this help and exit
\0";
            let len = help.len() - 1;
            unsafe { let _ = syscall3(sysn::WRITE, STDOUT as u64,
                                       help.as_ptr() as u64, len as u64); }
            return 0;
        } else {
            break;
        }
    }

    if (idx as i32) >= argc {
        write_str(STDERR, b"usage: rust-mkdir [-pv] [-m <mode>] DIR [DIR...]\n");
        return 1;
    }

    let mut had_error = false;
    let mut buf = [0u8; 4096];

    while let Some(p) = argv_get(argc, argv, idx) {
        let n = cstr_len(p);
        if n == 0 || n + 1 > buf.len() {
            write_str(STDERR, b"rust-mkdir: path too long or empty\n");
            had_error = true;
            idx += 1;
            continue;
        }
        // Snapshot the path into our own buffer (we'll NUL-terminate
        // intermediate prefixes for -p in there).
        let mut path = [0u8; 4096];
        for i in 0..n {
            path[i] = unsafe { *p.add(i) };
        }
        // Trailing NUL.
        path[n] = 0;

        let ok = if p_flag {
            make_recursive(&path[..n], &mut buf, mode)
        } else {
            make_one(&path[..=n], false, mode)
        };

        if !ok {
            had_error = true;
        } else if verbose {
            // GNU mkdir -v: "mkdir: created directory '<path>'\n".
            write_str(STDOUT, b"mkdir: created directory '");
            unsafe {
                let _ = syscall3(sysn::WRITE, STDOUT as u64, p as u64, n as u64);
            }
            write_str(STDOUT, b"'\n");
        }
        idx += 1;
    }

    let _ = STDOUT;
    if had_error { 1 } else { 0 }
}
