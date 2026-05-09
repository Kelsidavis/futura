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

// libcore's slice equality lowering emits calls to bcmp on aarch64
// even when the user code never compares slices — `Location::eq`,
// `StrSearcher::new`, and friends in the prebuilt libcore drag the
// reference in. Provide a tiny in-crate definition so the freestanding
// link stays self-contained.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn bcmp(a: *const u8, b: *const u8, n: usize) -> i32 {
    let mut i = 0;
    while i < n {
        let av = unsafe { *a.add(i) };
        let bv = unsafe { *b.add(i) };
        if av != bv {
            return (av as i32) - (bv as i32);
        }
        i += 1;
    }
    0
}

#[unsafe(no_mangle)]
pub extern "C" fn main(argc: i32, argv: *const *const u8, _envp: *const *const u8) -> i32 {
    // Pick a directory to list. argv[1] if provided, else NUL-terminated ".".
    let dot: [u8; 2] = [b'.', 0];
    let path_ptr: *const u8 = match argv_get(argc, argv, 1) {
        Some(p) => p,
        None => dot.as_ptr(),
    };

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
        write_str(STDERR, b"rust-ls: cannot open directory\n");
        return 1;
    }
    let fd = fd as i32;

    // getdents64 loop. Each record is variable-length:
    //   u64 d_ino, i64 d_off, u16 d_reclen, u8 d_type, char d_name[]
    let mut buf = [0u8; BUF_LEN];
    let mut had_error = false;
    loop {
        let n = unsafe {
            syscall3(
                sysn::GETDENTS64,
                fd as u64,
                buf.as_mut_ptr() as u64,
                buf.len() as u64,
            )
        };
        if n < 0 {
            had_error = true;
            break;
        }
        if n == 0 {
            break;
        }
        let bytes = n as usize;
        let mut off = 0usize;
        while off < bytes {
            // Defensive: ensure header fits before reading d_reclen.
            if off + 19 > bytes {
                break;
            }
            // d_reclen at offset 16 (after u64 + i64).
            let lo = buf[off + 16] as usize;
            let hi = buf[off + 17] as usize;
            let reclen = lo | (hi << 8);
            if reclen < 19 || off + reclen > bytes {
                break;
            }
            // d_name starts at offset 19 (after d_type byte).
            let name_start = off + 19;
            // Walk to NUL within the record.
            let mut name_end = name_start;
            while name_end < off + reclen && buf[name_end] != 0 {
                name_end += 1;
            }
            let name = &buf[name_start..name_end];
            // Skip "." and ".." like default `ls`. Hand-rolled to avoid
            // pulling in libcore's slice equality (which would land on
            // an undefined `bcmp` in this freestanding link).
            let nlen = name.len();
            let skip = (nlen == 1 && name[0] == b'.')
                || (nlen == 2 && name[0] == b'.' && name[1] == b'.');
            if !skip && nlen > 0 {
                if !write_all(STDOUT, name) {
                    had_error = true;
                    break;
                }
                if !write_all(STDOUT, b"\n") {
                    had_error = true;
                    break;
                }
            }
            off += reclen;
        }
        if had_error {
            break;
        }
    }

    let _ = unsafe { syscall1(sysn::CLOSE, fd as u64) };
    if had_error { 1 } else { 0 }
}
