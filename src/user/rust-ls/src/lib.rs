// SPDX-License-Identifier: MPL-2.0
//
// rust-ls — fourth user-space Rust program for Futura OS.
//
// Lists the entries of a directory using the openat(2)/getdents64(2)
// syscall pair. Default target is "." (i.e. AT_FDCWD on the cwd).
// Exit code 0 on success, 1 on any failure (open / read / write).
//
// Output is one entry per line, sorted by the order the kernel returns
// them. "." and ".." are filtered out so the output matches `ls`'s
// default behaviour.

#![no_std]
#![forbid(unsafe_op_in_unsafe_fn)]

use core::panic::PanicInfo;

#[cfg(target_arch = "aarch64")]
mod sysn {
    pub const WRITE: u64 = 64;
    pub const EXIT: u64 = 93;
    pub const OPENAT: u64 = 56;
    pub const CLOSE: u64 = 57;
    pub const GETDENTS64: u64 = 61;
}

#[cfg(target_arch = "x86_64")]
mod sysn {
    pub const WRITE: u64 = 1;
    pub const EXIT: u64 = 60;
    pub const OPENAT: u64 = 257;
    pub const CLOSE: u64 = 3;
    pub const GETDENTS64: u64 = 217;
}

const AT_FDCWD: i64 = -100;
const O_RDONLY: u64 = 0;
const O_DIRECTORY: u64 = 0o200000; // Linux generic
const STDOUT: i32 = 1;
const STDERR: i32 = 2;

const BUF_LEN: usize = 4096;

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

fn write_all(fd: i32, mut s: &[u8]) -> bool {
    while !s.is_empty() {
        let n = unsafe { syscall3(sysn::WRITE, fd as u64, s.as_ptr() as u64, s.len() as u64) };
        if n <= 0 {
            return false;
        }
        s = &s[n as usize..];
    }
    true
}

fn write_str(fd: i32, s: &[u8]) {
    let _ = write_all(fd, s);
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

#[panic_handler]
fn panic(_info: &PanicInfo) -> ! {
    write_str(STDERR, b"[rust-ls] panic\n");
    unsafe {
        sys_exit(1);
    }
}

// bcmp(3) is provided by libfutura — required because libcore's
// slice-equality lowering on aarch64 emits direct calls to it.

// Hide-policy for dot-prefixed entries.
#[derive(Copy, Clone, PartialEq, Eq)]
enum DotMode { HideAll, ShowAlmostAll, ShowAll }

fn arg_is(p: *const u8, s: &[u8]) -> bool {
    for (i, &b) in s.iter().enumerate() {
        if unsafe { *p.add(i) } != b {
            return false;
        }
    }
    unsafe { *p.add(s.len()) == 0 }
}

#[unsafe(no_mangle)]
pub extern "C" fn main(argc: i32, argv: *const *const u8, _envp: *const *const u8) -> i32 {
    // Parse leading flags. Match GNU ls's default:
    //   no flag   ->  HideAll        (skip every dot-prefixed entry)
    //   -a        ->  ShowAll        (include '.' and '..')
    //   -A        ->  ShowAlmostAll  (include other dot-files but skip '.' and '..')
    // Earlier versions implicitly behaved like -A which surprised
    // anyone running 'ls /etc' and seeing hidden state files.
    let mut mode = DotMode::HideAll;
    let mut idx: i32 = 1;
    while idx < argc {
        let p = unsafe { *argv.add(idx as usize) };
        if p.is_null() || (p as usize) < 0x10000 {
            idx += 1;
            continue;
        }
        if arg_is(p, b"-a") {
            mode = DotMode::ShowAll;
            idx += 1;
        } else if arg_is(p, b"-A") {
            mode = DotMode::ShowAlmostAll;
            idx += 1;
        } else {
            break;
        }
    }

    // Collect every non-flag argv into the path list. Multiple paths
    // each get listed in turn; if the path isn't a directory (e.g. a
    // regular file), GNU ls just echoes the name and that's what we
    // do here too. Without this, `rust-ls /bin/cat` previously failed
    // with "cannot open directory".
    let mut had_error = false;
    let mut paths_seen: i32 = 0;
    // Count first so we can decide whether to emit "<path>:" headers.
    let mut probe = idx as usize;
    while argv_get(argc, argv, probe).is_some() {
        paths_seen += 1;
        probe += 1;
    }

    let mut buf = [0u8; BUF_LEN];

    let list_one = |path_ptr: *const u8,
                    path_len: usize,
                    label_with_header: bool,
                    not_first: bool,
                    buf: &mut [u8; BUF_LEN]| -> bool {
        let fd = unsafe {
            syscall4(
                sysn::OPENAT,
                AT_FDCWD as u64,
                path_ptr as u64,
                O_RDONLY | O_DIRECTORY,
                0,
            )
        };
        if fd < 0 {
            // Not a directory? Try opening without O_DIRECTORY to see
            // if it's a regular file. If so, just echo the name —
            // matches `ls` on a non-dir argv.
            let plain = unsafe {
                syscall4(sysn::OPENAT, AT_FDCWD as u64, path_ptr as u64, O_RDONLY, 0)
            };
            if plain >= 0 {
                let _ = unsafe { syscall1(sysn::CLOSE, plain as u64) };
                if path_len > 0 {
                    if !write_all(STDOUT, unsafe {
                        core::slice::from_raw_parts(path_ptr, path_len)
                    }) {
                        return false;
                    }
                    if !write_all(STDOUT, b"\n") { return false; }
                }
                return true;
            }
            write_str(STDERR, b"rust-ls: cannot open '");
            unsafe {
                let _ = syscall3(sysn::WRITE, STDERR as u64, path_ptr as u64, path_len as u64);
            }
            write_str(STDERR, b"'\n");
            return false;
        }
        let fd = fd as i32;
        if label_with_header {
            if not_first { write_str(STDOUT, b"\n"); }
            unsafe {
                let _ = syscall3(sysn::WRITE, STDOUT as u64, path_ptr as u64, path_len as u64);
            }
            write_str(STDOUT, b":\n");
        }

        let mut local_err = false;
        loop {
            let n = unsafe {
                syscall3(
                    sysn::GETDENTS64,
                    fd as u64,
                    buf.as_mut_ptr() as u64,
                    buf.len() as u64,
                )
            };
            if n < 0 { local_err = true; break; }
            if n == 0 { break; }
            let bytes = n as usize;
            let mut off = 0usize;
            while off < bytes {
                if off + 19 > bytes { break; }
                let lo = buf[off + 16] as usize;
                let hi = buf[off + 17] as usize;
                let reclen = lo | (hi << 8);
                if reclen < 19 || off + reclen > bytes { break; }
                let name_start = off + 19;
                let mut name_end = name_start;
                while name_end < off + reclen && buf[name_end] != 0 {
                    name_end += 1;
                }
                let name = &buf[name_start..name_end];
                let nlen = name.len();
                let is_dot = nlen == 1 && name[0] == b'.';
                let is_dotdot = nlen == 2 && name[0] == b'.' && name[1] == b'.';
                let starts_with_dot = nlen > 0 && name[0] == b'.';
                let skip = match mode {
                    DotMode::HideAll => starts_with_dot,
                    DotMode::ShowAlmostAll => is_dot || is_dotdot,
                    DotMode::ShowAll => false,
                };
                if !skip && nlen > 0 {
                    if !write_all(STDOUT, name) { local_err = true; break; }
                    if !write_all(STDOUT, b"\n") { local_err = true; break; }
                }
                off += reclen;
            }
            if local_err { break; }
        }

        let _ = unsafe { syscall1(sysn::CLOSE, fd as u64) };
        !local_err
    };

    if paths_seen == 0 {
        let dot: [u8; 2] = [b'.', 0];
        if !list_one(dot.as_ptr(), 1, false, false, &mut buf) {
            had_error = true;
        }
    } else {
        let multi = paths_seen > 1;
        let mut printed = 0i32;
        let mut walk = idx as usize;
        while let Some(p) = argv_get(argc, argv, walk) {
            // Skip null/garbage argv entries defensively.
            if (p as usize) < 0x10000 { walk += 1; continue; }
            let mut plen = 0usize;
            unsafe { while *p.add(plen) != 0 { plen += 1; } }
            if !list_one(p, plen, multi, printed > 0, &mut buf) {
                had_error = true;
            }
            printed += 1;
            walk += 1;
        }
    }

    if had_error { 1 } else { 0 }
}
