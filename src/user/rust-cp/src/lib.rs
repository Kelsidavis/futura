// SPDX-License-Identifier: MPL-2.0
//
// rust-cp — copy a single regular file.
//
//   rust-cp [-n] <src> <dst>
//   rust-cp [-n] <src> <dst-dir>/   (DST treated as directory →
//                                    copy goes to <dst-dir>/<basename>)
//
// Reads SRC and writes DST in 4 KiB chunks. Creates DST with mode
// 0644:
//   default: O_WRONLY|O_CREAT|O_TRUNC  (truncate existing content)
//   -n:      O_WRONLY|O_CREAT|O_EXCL   (no-clobber — refuse to
//                                       overwrite an existing DST)
//
// If DST is an existing directory, the copy lands at DST/<basename>
// (matches POSIX cp behavior). No recursive copy, no preserve flags.
// Errors are written to stderr with a short prefix and exit code 1.

#![no_std]
#![forbid(unsafe_op_in_unsafe_fn)]

use core::panic::PanicInfo;

#[cfg(target_arch = "aarch64")]
mod sysn {
    pub const WRITE: u64 = 64;
    pub const EXIT: u64 = 93;
    pub const OPENAT: u64 = 56;
    pub const CLOSE: u64 = 57;
    pub const READ: u64 = 63;
}

#[cfg(target_arch = "x86_64")]
mod sysn {
    pub const WRITE: u64 = 1;
    pub const EXIT: u64 = 60;
    pub const OPENAT: u64 = 257;
    pub const CLOSE: u64 = 3;
    pub const READ: u64 = 0;
}

const AT_FDCWD: i64 = -100;
const O_RDONLY: u64 = 0;
const O_WRONLY: u64 = 1;
const O_CREAT: u64 = 0o100;
const O_EXCL: u64 = 0o200;
const O_TRUNC: u64 = 0o1000;
// Linux generic O_DIRECTORY value; matches the kernel's flag bit.
const O_DIRECTORY: u64 = 0o200_000;

const STDOUT: i32 = 1;
const STDERR: i32 = 2;

const BUF: usize = 4096;

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
    write_str(STDERR, b"[rust-cp] panic\n");
    unsafe {
        sys_exit(1);
    }
}

fn open_read(path: *const u8) -> i32 {
    unsafe { syscall4(sysn::OPENAT, AT_FDCWD as u64, path as u64, O_RDONLY, 0) as i32 }
}

fn open_write(path: *const u8, no_clobber: bool) -> i32 {
    let flags = if no_clobber {
        O_WRONLY | O_CREAT | O_EXCL
    } else {
        O_WRONLY | O_CREAT | O_TRUNC
    };
    unsafe { syscall4(sysn::OPENAT, AT_FDCWD as u64, path as u64, flags, 0o644) as i32 }
}

fn arg_is(p: *const u8, s: &[u8]) -> bool {
    for (i, &b) in s.iter().enumerate() {
        if unsafe { *p.add(i) } != b {
            return false;
        }
    }
    unsafe { *p.add(s.len()) == 0 }
}

fn close_fd(fd: i32) {
    unsafe {
        let _ = syscall1(sysn::CLOSE, fd as u64);
    }
}

fn copy_loop(src_fd: i32, dst_fd: i32) -> bool {
    let mut buf = [0u8; BUF];
    loop {
        let n = unsafe {
            syscall3(sysn::READ, src_fd as u64, buf.as_mut_ptr() as u64, buf.len() as u64)
        };
        if n < 0 {
            return false;
        }
        if n == 0 {
            return true;
        }
        let mut off = 0i64;
        while off < n {
            let w = unsafe {
                syscall3(
                    sysn::WRITE,
                    dst_fd as u64,
                    (buf.as_ptr() as u64).wrapping_add(off as u64),
                    (n - off) as u64,
                )
            };
            if w <= 0 {
                return false;
            }
            off += w;
        }
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn main(argc: i32, argv: *const *const u8, _envp: *const *const u8) -> i32 {
    let mut no_clobber = false;
    let mut idx: i32 = 1;
    if idx < argc {
        let p = unsafe { *argv.add(idx as usize) };
        if !p.is_null() && (p as usize) >= 0x10000 && arg_is(p, b"-n") {
            no_clobber = true;
            idx += 1;
        }
    }
    if argc - idx != 2 {
        write_str(STDERR, b"usage: rust-cp [-n] <src> <dst>\n");
        return 1;
    }
    let src = unsafe { *argv.add(idx as usize) };
    let dst = unsafe { *argv.add((idx + 1) as usize) };
    if src.is_null() || (src as usize) < 0x10000 || dst.is_null() || (dst as usize) < 0x10000 {
        write_str(STDERR, b"rust-cp: invalid arguments\n");
        return 1;
    }

    let src_fd = open_read(src);
    if src_fd < 0 {
        write_str(STDERR, b"rust-cp: cannot open source\n");
        return 1;
    }

    // If DST is an existing directory, the actual write target is
    // "<dst>/<basename(src)>". Detect by trying to open it with
    // O_DIRECTORY — succeeds only for a real directory. Fall back to
    // treating DST as a literal path otherwise.
    let mut composed = [0u8; 1024];
    let mut composed_len = 0usize;
    let dst_open_path: *const u8 = {
        let dir_probe = unsafe {
            syscall4(sysn::OPENAT, AT_FDCWD as u64, dst as u64,
                     O_RDONLY | O_DIRECTORY, 0)
        };
        if dir_probe >= 0 {
            close_fd(dir_probe as i32);
            // Compose <dst>/<basename(src)>.
            let mut dlen = 0usize;
            unsafe { while *dst.add(dlen) != 0 { dlen += 1; } }
            let mut slen = 0usize;
            unsafe { while *src.add(slen) != 0 { slen += 1; } }
            let mut bstart = slen;
            while bstart > 0 && unsafe { *src.add(bstart - 1) } != b'/' {
                bstart -= 1;
            }
            let basename_len = slen - bstart;
            let need_sep = dlen > 0 && unsafe { *dst.add(dlen - 1) } != b'/';
            let total = dlen + (if need_sep { 1 } else { 0 }) + basename_len;
            if total + 1 > composed.len() || basename_len == 0 {
                close_fd(src_fd);
                write_str(STDERR, b"rust-cp: composed path too long or basename empty\n");
                return 1;
            }
            for i in 0..dlen { composed[i] = unsafe { *dst.add(i) }; }
            let mut pos = dlen;
            if need_sep { composed[pos] = b'/'; pos += 1; }
            for i in 0..basename_len {
                composed[pos + i] = unsafe { *src.add(bstart + i) };
            }
            composed[pos + basename_len] = 0;
            composed_len = pos + basename_len;
            composed.as_ptr()
        } else {
            dst
        }
    };
    let _ = composed_len;

    let dst_fd = open_write(dst_open_path, no_clobber);
    if dst_fd < 0 {
        close_fd(src_fd);
        if no_clobber {
            write_str(STDERR, b"rust-cp: destination exists (use without -n to overwrite)\n");
        } else {
            write_str(STDERR, b"rust-cp: cannot create destination\n");
        }
        return 1;
    }

    let ok = copy_loop(src_fd, dst_fd);
    close_fd(src_fd);
    close_fd(dst_fd);

    if !ok {
        write_str(STDERR, b"rust-cp: copy failed\n");
        return 1;
    }
    let _ = STDOUT;
    0
}
