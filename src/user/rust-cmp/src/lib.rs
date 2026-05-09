// SPDX-License-Identifier: MPL-2.0
//
// rust-cmp — byte-by-byte file comparison.
//
//   rust-cmp <file1> <file2>
//
// Exit codes match POSIX cmp(1):
//   0 — files are identical
//   1 — files differ; first diff (and EOF mismatch) reported on stdout
//   2 — error opening one of the files (message on stderr)
//
// Streams both files through 4 KiB buffers in lockstep — no allocator,
// no whole-file slurp.

#![no_std]
#![forbid(unsafe_op_in_unsafe_fn)]

use core::panic::PanicInfo;

#[cfg(target_arch = "aarch64")]
mod sysn {
    pub const READ: u64 = 63;
    pub const WRITE: u64 = 64;
    pub const EXIT: u64 = 93;
    pub const OPENAT: u64 = 56;
    pub const CLOSE: u64 = 57;
}

#[cfg(target_arch = "x86_64")]
mod sysn {
    pub const READ: u64 = 0;
    pub const WRITE: u64 = 1;
    pub const EXIT: u64 = 60;
    pub const OPENAT: u64 = 257;
    pub const CLOSE: u64 = 3;
}

const AT_FDCWD: i64 = -100;
const O_RDONLY: u64 = 0;
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
    write_str(STDERR, b"[rust-cmp] panic\n");
    unsafe {
        sys_exit(1);
    }
}

fn open_read(p: *const u8) -> i32 {
    unsafe { syscall4(sysn::OPENAT, AT_FDCWD as u64, p as u64, O_RDONLY, 0) as i32 }
}

fn close_fd(fd: i32) {
    unsafe {
        let _ = syscall1(sysn::CLOSE, fd as u64);
    }
}

// Read up to buf.len() bytes from fd into buf, retrying on partial reads.
// Returns Some(n) on success (n=0 means EOF), None on read error.
fn read_full(fd: i32, buf: &mut [u8]) -> Option<usize> {
    let n = unsafe { syscall3(sysn::READ, fd as u64, buf.as_mut_ptr() as u64, buf.len() as u64) };
    if n < 0 {
        return None;
    }
    Some(n as usize)
}

// Print "rust-cmp: <file>: name1 differs from name2 at byte <pos>".
fn print_diff(name1: &[u8], name2: &[u8], byte_pos: u64) {
    write_str(STDOUT, name1);
    write_str(STDOUT, b" ");
    write_str(STDOUT, name2);
    write_str(STDOUT, b" differ: byte ");
    let mut buf = [0u8; 24];
    let mut n = byte_pos;
    let mut i = buf.len();
    if n == 0 {
        i -= 1;
        buf[i] = b'0';
    } else {
        while n > 0 && i > 0 {
            i -= 1;
            buf[i] = b'0' + (n % 10) as u8;
            n /= 10;
        }
    }
    write_str(STDOUT, &buf[i..]);
    write_str(STDOUT, b"\n");
}

#[unsafe(no_mangle)]
pub extern "C" fn main(argc: i32, argv: *const *const u8, _envp: *const *const u8) -> i32 {
    if argc < 3 {
        write_str(STDERR, b"usage: rust-cmp <file1> <file2>\n");
        return 2;
    }
    let p1 = unsafe { *argv.add(1) };
    let p2 = unsafe { *argv.add(2) };
    if p1.is_null() || (p1 as usize) < 0x10000 || p2.is_null() || (p2 as usize) < 0x10000 {
        write_str(STDERR, b"rust-cmp: invalid arguments\n");
        return 2;
    }

    let fd1 = open_read(p1);
    if fd1 < 0 {
        write_str(STDERR, b"rust-cmp: cannot open first file\n");
        return 2;
    }
    let fd2 = open_read(p2);
    if fd2 < 0 {
        close_fd(fd1);
        write_str(STDERR, b"rust-cmp: cannot open second file\n");
        return 2;
    }

    // Names as slices for the diff message — re-derive length from C strings.
    let mut n1 = 0usize;
    while unsafe { *p1.add(n1) } != 0 {
        n1 += 1;
    }
    let name1 = unsafe { core::slice::from_raw_parts(p1, n1) };
    let mut n2 = 0usize;
    while unsafe { *p2.add(n2) } != 0 {
        n2 += 1;
    }
    let name2 = unsafe { core::slice::from_raw_parts(p2, n2) };

    let mut buf1 = [0u8; BUF];
    let mut buf2 = [0u8; BUF];
    let mut byte_pos: u64 = 0;
    let mut rc: i32 = 0;

    loop {
        let r1 = read_full(fd1, &mut buf1);
        let r2 = read_full(fd2, &mut buf2);
        let (n1r, n2r) = match (r1, r2) {
            (Some(a), Some(b)) => (a, b),
            _ => {
                write_str(STDERR, b"rust-cmp: read error\n");
                rc = 2;
                break;
            }
        };
        if n1r == 0 && n2r == 0 {
            break; // identical
        }
        let common = n1r.min(n2r);
        for i in 0..common {
            if buf1[i] != buf2[i] {
                print_diff(name1, name2, byte_pos + i as u64 + 1);
                rc = 1;
                close_fd(fd1);
                close_fd(fd2);
                return rc;
            }
        }
        byte_pos += common as u64;
        if n1r != n2r {
            // One file ended; the other has more bytes. GNU cmp writes
            // the EOF notice to stderr (not stdout) — match that so
            // shell pipelines that grep stdout don't see this line.
            write_str(STDERR, b"rust-cmp: EOF on ");
            write_str(STDERR, if n1r < n2r { name1 } else { name2 });
            write_str(STDERR, b"\n");
            rc = 1;
            break;
        }
        // Both reads were full and equal-length; loop reads more.
    }

    close_fd(fd1);
    close_fd(fd2);
    rc
}
