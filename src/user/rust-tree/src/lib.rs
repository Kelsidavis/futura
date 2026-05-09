// SPDX-License-Identifier: MPL-2.0
//
// rust-tree — recursive directory lister, the simplest cousin of a
// file explorer. Walks the directory tree from argv[1] (or "."),
// printing each entry with indent prefixes that reflect depth.
//
// no_std, no allocator. Recursion is bounded by MAX_DEPTH so the
// fixed-size traversal state can never overflow. Entries past that
// depth are marked with an ellipsis.

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
const O_DIRECTORY: u64 = 0o200000;
const STDOUT: i32 = 1;
const STDERR: i32 = 2;

// Linux DT_DIR value (used in d_type). Same on aarch64 and x86_64.
const DT_DIR: u8 = 4;

const MAX_DEPTH: usize = 8;
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

fn write_all(fd: i32, mut s: &[u8]) {
    while !s.is_empty() {
        let n = unsafe { syscall3(sysn::WRITE, fd as u64, s.as_ptr() as u64, s.len() as u64) };
        if n <= 0 {
            return;
        }
        s = &s[n as usize..];
    }
}

#[panic_handler]
fn panic(_info: &PanicInfo) -> ! {
    write_all(STDERR, b"[rust-tree] panic\n");
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

fn open_dir_fd(path: *const u8) -> i32 {
    let r = unsafe {
        syscall4(
            sysn::OPENAT,
            AT_FDCWD as u64,
            path as u64,
            O_RDONLY | O_DIRECTORY,
            0,
        )
    };
    r as i32
}

fn open_dir_at(parent_fd: i32, name: &[u8]) -> i32 {
    // Compose a NUL-terminated copy on the stack. Linux NAME_MAX is 255.
    let mut buf = [0u8; 256];
    let n = name.len().min(255);
    buf[..n].copy_from_slice(&name[..n]);
    buf[n] = 0;
    let r = unsafe {
        syscall4(
            sysn::OPENAT,
            parent_fd as u64,
            buf.as_ptr() as u64,
            O_RDONLY | O_DIRECTORY,
            0,
        )
    };
    r as i32
}

fn close_fd(fd: i32) {
    unsafe {
        let _ = syscall1(sysn::CLOSE, fd as u64);
    }
}

fn print_indent(depth: usize) {
    // Two spaces per level. Capped at MAX_DEPTH so the static buffer is enough.
    let levels = depth.min(MAX_DEPTH);
    let pad = b"                "; // 32 spaces — covers 2*MAX_DEPTH(8) = 16
    write_all(STDOUT, &pad[..levels * 2]);
    if depth > 0 {
        write_all(STDOUT, b"|- ");
    }
}

// Walk one directory: print its children, recursing into subdirectories
// up to depth+1 < MAX_DEPTH.
fn arg_is(p: *const u8, s: &[u8]) -> bool {
    for (i, &b) in s.iter().enumerate() {
        if unsafe { *p.add(i) } != b {
            return false;
        }
    }
    unsafe { *p.add(s.len()) == 0 }
}

// Hide-policy for dot-prefixed entries (mirrors rust-ls).
#[derive(Copy, Clone, PartialEq, Eq)]
enum DotMode { HideAll, ShowAll }

fn walk(dir_fd: i32, depth: usize, mode: DotMode) {
    let mut buf = [0u8; BUF_LEN];
    loop {
        let n = unsafe {
            syscall3(
                sysn::GETDENTS64,
                dir_fd as u64,
                buf.as_mut_ptr() as u64,
                buf.len() as u64,
            )
        };
        if n <= 0 {
            return;
        }
        let bytes = n as usize;
        let mut off = 0usize;
        while off < bytes {
            if off + 19 > bytes {
                break;
            }
            // d_reclen at offset 16, d_type at offset 18, d_name at offset 19.
            let lo = buf[off + 16] as usize;
            let hi = buf[off + 17] as usize;
            let reclen = lo | (hi << 8);
            if reclen < 19 || off + reclen > bytes {
                break;
            }
            let d_type = buf[off + 18];
            let name_start = off + 19;
            let mut name_end = name_start;
            while name_end < off + reclen && buf[name_end] != 0 {
                name_end += 1;
            }
            let name = &buf[name_start..name_end];
            let nlen = name.len();
            // Always skip '.' and '..'; with HideAll skip every other
            // dot-prefixed entry too (matches GNU tree's default).
            let is_dot = nlen == 1 && name[0] == b'.';
            let is_dotdot = nlen == 2 && name[0] == b'.' && name[1] == b'.';
            let starts_with_dot = nlen > 0 && name[0] == b'.';
            let skip = nlen == 0
                || is_dot
                || is_dotdot
                || (mode == DotMode::HideAll && starts_with_dot);
            if !skip {
                print_indent(depth);
                write_all(STDOUT, name);
                if d_type == DT_DIR {
                    write_all(STDOUT, b"/\n");
                    if depth + 1 < MAX_DEPTH {
                        // Open child relative to current dir_fd, so we
                        // don't have to re-construct path strings.
                        let child = open_dir_at(dir_fd, name);
                        if child >= 0 {
                            walk(child, depth + 1, mode);
                            close_fd(child);
                        }
                    } else {
                        print_indent(depth + 1);
                        write_all(STDOUT, b"...\n");
                    }
                } else {
                    write_all(STDOUT, b"\n");
                }
            }
            off += reclen;
        }
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn main(argc: i32, argv: *const *const u8, _envp: *const *const u8) -> i32 {
    // -a includes dot-prefixed entries (excluding '.' and '..' which
    // are always skipped to avoid cycles). Default hides them, matching
    // GNU tree.
    let mut mode = DotMode::HideAll;
    let mut idx: i32 = 1;
    while idx < argc {
        let p = unsafe { *argv.add(idx as usize) };
        if p.is_null() || (p as usize) < 0x10000 { break; }
        if arg_is(p, b"-a") {
            mode = DotMode::ShowAll;
            idx += 1;
        } else if arg_is(p, b"--help") {
            let help: &[u8] = b"\
Usage: rust-tree [-a] [PATH]
Recursively list PATH (or '.') with indent prefixes per depth.

  -a        include dot-prefixed entries (skip only '.' and '..')
      --help    show this help and exit
\0";
            let len = help.len() - 1;
            unsafe { let _ = syscall3(sysn::WRITE, STDOUT as u64,
                                       help.as_ptr() as u64, len as u64); }
            return 0;
        } else {
            break;
        }
    }

    // Pick a root: first non-flag argv if given, else ".".
    let dot: [u8; 2] = [b'.', 0];
    let path: *const u8 = if idx < argc {
        let p = unsafe { *argv.add(idx as usize) };
        if p.is_null() || (p as usize) < 0x10000 {
            dot.as_ptr()
        } else {
            p
        }
    } else {
        dot.as_ptr()
    };

    // Print root header (the path itself, with trailing slash for clarity).
    let n = cstr_len(path);
    let path_bytes = unsafe { core::slice::from_raw_parts(path, n) };
    write_all(STDOUT, path_bytes);
    write_all(STDOUT, b"/\n");

    let fd = open_dir_fd(path);
    if fd < 0 {
        write_all(STDERR, b"rust-tree: cannot open directory\n");
        return 1;
    }
    walk(fd, 1, mode);
    close_fd(fd);
    0
}
