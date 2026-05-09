// SPDX-License-Identifier: MPL-2.0
//
// rust-stat — print file metadata via newfstatat(2) (POSIX `stat`).
//
//   rust-stat <path> [<path>...]
//
// Output format mirrors a compact `stat` summary:
//
//   File: <path>
//   Size: <bytes>   Blocks: <st_blocks>   IO Block: <st_blksize>   <type>
//   Mode: (<octal>/<rwxrwxrwx>)   Uid: <uid>   Gid: <gid>
//   Inode: <ino>   Links: <nlink>
//   Modify: <mtime epoch>
//
// Per-arch syscall dispatch:
//   aarch64 -> newfstatat(AT_FDCWD, path, &stat, 0) (SYS=79)
//   x86_64  -> stat(path, &stat)                   (SYS=4)
//
// stat-buffer layout follows the Linux x86_64 layout (matches what
// FuturaFS fills in). aarch64's struct stat layout is identical for
// every field we inspect.

#![no_std]
#![forbid(unsafe_op_in_unsafe_fn)]

use core::panic::PanicInfo;

#[cfg(target_arch = "aarch64")]
mod sysn {
    pub const WRITE: u64 = 64;
    pub const EXIT: u64 = 93;
    pub const NEWFSTATAT: u64 = 79;
}

#[cfg(target_arch = "x86_64")]
mod sysn {
    pub const WRITE: u64 = 1;
    pub const EXIT: u64 = 60;
    pub const STAT: u64 = 4;
}

#[cfg(target_arch = "aarch64")]
const AT_FDCWD: i64 = -100;
const STDOUT: i32 = 1;
const STDERR: i32 = 2;

// Matches the kernel's struct fut_stat (kernel/include/kernel/fut_vfs.h).
// Both the aarch64 newfstatat path and the x86_64 stat path write
// this layout, so we don't need per-arch shapes here.
#[repr(C)]
#[derive(Default, Copy, Clone)]
struct StatBuf {
    st_dev:     u64,   //   0
    st_ino:     u64,   //   8
    st_mode:    u32,   //  16
    st_nlink:   u32,   //  20
    st_uid:     u32,   //  24
    st_gid:     u32,   //  28
    st_size:    u64,   //  32
    st_blksize: u64,   //  40
    st_blocks:  u64,   //  48
    st_atime:   u64,   //  56
    _atime_ns:  u32,   //  64
    _atime_pad: u32,   //  68
    st_mtime:   u64,   //  72
    _mtime_ns:  u32,   //  80
    _mtime_pad: u32,   //  84
    st_ctime:   u64,   //  88
    _ctime_ns:  u32,   //  96
    _ctime_pad: u32,   // 100
}                       // total 104 bytes

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
    write_str(STDERR, b"[rust-stat] panic\n");
    unsafe { sys_exit(1); }
}

fn cstr_len(p: *const u8) -> usize {
    let mut n = 0;
    unsafe { while *p.add(n) != 0 { n += 1; } }
    n
}

// Render an unsigned u64 right-justified into a 24-byte scratch and
// return the slice that's actually populated.
fn fmt_u64(mut n: u64, buf: &mut [u8; 24]) -> &[u8] {
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
    &buf[i..]
}


// Render mode as 4-char octal padded ("0644").
fn fmt_octal_mode(mode: u32, buf: &mut [u8; 6]) -> &[u8] {
    let m = mode & 0o7777;
    buf[0] = b'0';
    buf[1] = b'0' + ((m >> 9) & 0o7) as u8;
    buf[2] = b'0' + ((m >> 6) & 0o7) as u8;
    buf[3] = b'0' + ((m >> 3) & 0o7) as u8;
    buf[4] = b'0' + (m & 0o7) as u8;
    &buf[..5]
}

// Compose the rwx triplets for u/g/o into a 9-byte slice.
fn fmt_perms(mode: u32, buf: &mut [u8; 10]) -> &[u8] {
    let bits = [
        (0o400, b'r'), (0o200, b'w'), (0o100, b'x'),
        (0o040, b'r'), (0o020, b'w'), (0o010, b'x'),
        (0o004, b'r'), (0o002, b'w'), (0o001, b'x'),
    ];
    for (i, &(mask, ch)) in bits.iter().enumerate() {
        buf[i] = if mode & mask != 0 { ch } else { b'-' };
    }
    &buf[..9]
}

fn type_name(mode: u32) -> &'static [u8] {
    let t = mode & 0o170_000;
    match t {
        0o040_000 => b"directory",
        0o100_000 => b"regular file",
        0o020_000 => b"character device",
        0o060_000 => b"block device",
        0o120_000 => b"symbolic link",
        0o010_000 => b"fifo",
        0o140_000 => b"socket",
        _         => b"unknown",
    }
}

// First char of the perm-string (GNU `ls -l` / `stat` style).
fn type_char(mode: u32) -> u8 {
    match mode & 0o170_000 {
        0o040_000 => b'd',
        0o020_000 => b'c',
        0o060_000 => b'b',
        0o120_000 => b'l',
        0o010_000 => b'p',
        0o140_000 => b's',
        _         => b'-',  // regular file or unknown
    }
}

fn do_stat(path: *const u8) -> bool {
    let st = StatBuf::default();
    let stp = &st as *const StatBuf as u64;
    let r;
    #[cfg(target_arch = "aarch64")]
    {
        r = unsafe { syscall4(sysn::NEWFSTATAT, AT_FDCWD as u64, path as u64, stp, 0) };
    }
    #[cfg(target_arch = "x86_64")]
    {
        r = unsafe { syscall2(sysn::STAT, path as u64, stp) };
    }
    if r < 0 {
        write_str(STDERR, b"rust-stat: cannot stat '");
        let n = cstr_len(path);
        write_str(STDERR, unsafe { core::slice::from_raw_parts(path, n) });
        write_str(STDERR, b"'\n");
        return false;
    }

    let n = cstr_len(path);
    let path_slice = unsafe { core::slice::from_raw_parts(path, n) };

    let mut nb = [0u8; 24];
    let mut mb = [0u8; 6];
    let mut pb = [0u8; 10];

    write_str(STDOUT, b"  File: ");
    write_str(STDOUT, path_slice);
    write_str(STDOUT, b"\n");

    write_str(STDOUT, b"  Size: ");
    write_str(STDOUT, fmt_u64(st.st_size, &mut nb));
    write_str(STDOUT, b"\tBlocks: ");
    write_str(STDOUT, fmt_u64(st.st_blocks, &mut nb));
    write_str(STDOUT, b"\tIO Block: ");
    write_str(STDOUT, fmt_u64(st.st_blksize, &mut nb));
    write_str(STDOUT, b"\t");
    write_str(STDOUT, type_name(st.st_mode));
    write_str(STDOUT, b"\n");

    write_str(STDOUT, b"Device: ");
    write_str(STDOUT, fmt_u64(st.st_dev, &mut nb));
    write_str(STDOUT, b"\tInode: ");
    write_str(STDOUT, fmt_u64(st.st_ino, &mut nb));
    write_str(STDOUT, b"\tLinks: ");
    write_str(STDOUT, fmt_u64(st.st_nlink as u64, &mut nb));
    write_str(STDOUT, b"\n");

    write_str(STDOUT, b"Access: (");
    write_str(STDOUT, fmt_octal_mode(st.st_mode, &mut mb));
    write_str(STDOUT, b"/");
    let tc = [type_char(st.st_mode)];
    write_str(STDOUT, &tc);
    write_str(STDOUT, fmt_perms(st.st_mode, &mut pb));
    write_str(STDOUT, b")\tUid: ");
    write_str(STDOUT, fmt_u64(st.st_uid as u64, &mut nb));
    write_str(STDOUT, b"\tGid: ");
    write_str(STDOUT, fmt_u64(st.st_gid as u64, &mut nb));
    write_str(STDOUT, b"\n");

    write_str(STDOUT, b"Modify: ");
    write_str(STDOUT, fmt_u64(st.st_mtime, &mut nb));
    write_str(STDOUT, b"\n");
    true
}

#[unsafe(no_mangle)]
pub extern "C" fn main(argc: i32, argv: *const *const u8, _envp: *const *const u8) -> i32 {
    if argc < 2 {
        write_str(STDERR, b"usage: rust-stat <path> [<path>...]\n");
        return 1;
    }
    let mut had_error = false;
    for ai in 1..argc {
        let p = unsafe { *argv.add(ai as usize) };
        if p.is_null() || (p as usize) < 0x10000 {
            had_error = true;
            continue;
        }
        if !do_stat(p) { had_error = true; }
    }
    if had_error { 1 } else { 0 }
}
