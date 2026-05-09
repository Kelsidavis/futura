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

// Linux x86_64 struct stat (size 144). aarch64's struct stat from the
// generic UAPI is the same shape for everything we look at; we read
// 144 bytes either way and only touch fields whose offsets match on
// both archs.
#[repr(C)]
#[derive(Default, Copy, Clone)]
struct StatBuf {
    st_dev:     u64,   //   0
    st_ino:     u64,   //   8
    st_nlink:   u64,   //  16  (x86_64) — aarch64 places nlink at +16 in newfstatat too
    st_mode:    u32,   //  24
    st_uid:     u32,   //  28
    st_gid:     u32,   //  32
    _pad0:      u32,   //  36
    st_rdev:    u64,   //  40
    st_size:    i64,   //  48
    st_blksize: i64,   //  56
    st_blocks:  i64,   //  64
    st_atime:   i64,   //  72
    _atime_ns:  u64,   //  80
    st_mtime:   i64,   //  88
    _mtime_ns:  u64,   //  96
    st_ctime:   i64,   // 104
    _ctime_ns:  u64,   // 112
    _unused:    [i64; 3],  // 120..144
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

fn fmt_i64(n: i64, buf: &mut [u8; 24]) -> &[u8] {
    if n >= 0 {
        return fmt_u64(n as u64, buf);
    }
    // Render negatives via the unsigned magnitude.
    let mag = (n as i128).unsigned_abs() as u64;
    let mut i = buf.len();
    let mut v = mag;
    if v == 0 { i -= 1; buf[i] = b'0'; }
    while v > 0 && i > 0 {
        i -= 1;
        buf[i] = b'0' + (v % 10) as u8;
        v /= 10;
    }
    if i > 0 { i -= 1; buf[i] = b'-'; }
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
    write_str(STDOUT, fmt_i64(st.st_size, &mut nb));
    write_str(STDOUT, b"\tBlocks: ");
    write_str(STDOUT, fmt_i64(st.st_blocks, &mut nb));
    write_str(STDOUT, b"\tIO Block: ");
    write_str(STDOUT, fmt_i64(st.st_blksize, &mut nb));
    write_str(STDOUT, b"\t");
    write_str(STDOUT, type_name(st.st_mode));
    write_str(STDOUT, b"\n");

    write_str(STDOUT, b"Device: ");
    write_str(STDOUT, fmt_u64(st.st_dev, &mut nb));
    write_str(STDOUT, b"\tInode: ");
    write_str(STDOUT, fmt_u64(st.st_ino, &mut nb));
    write_str(STDOUT, b"\tLinks: ");
    write_str(STDOUT, fmt_u64(st.st_nlink, &mut nb));
    write_str(STDOUT, b"\n");

    write_str(STDOUT, b"Access: (");
    write_str(STDOUT, fmt_octal_mode(st.st_mode, &mut mb));
    write_str(STDOUT, b"/-");
    write_str(STDOUT, fmt_perms(st.st_mode, &mut pb));
    write_str(STDOUT, b")\tUid: ");
    write_str(STDOUT, fmt_u64(st.st_uid as u64, &mut nb));
    write_str(STDOUT, b"\tGid: ");
    write_str(STDOUT, fmt_u64(st.st_gid as u64, &mut nb));
    write_str(STDOUT, b"\n");

    write_str(STDOUT, b"Modify: ");
    write_str(STDOUT, fmt_i64(st.st_mtime, &mut nb));
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
