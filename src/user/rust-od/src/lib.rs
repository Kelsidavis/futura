// SPDX-License-Identifier: MPL-2.0
//
// rust-od — hex + ASCII dump of stdin or a file.
//
//   rust-od [<file>]
//
// Output is `od -A x -t x1z -v` shape: 7-digit hex offset, 16 bytes
// per line as space-separated lower-case hex pairs, then "  |…|" with
// printable ASCII (non-printable -> '.'). Final line shows the next
// offset (file length) and exits.
//
// Stream-style: 4 KiB read buffer, fixed line buffer, no allocator.

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
const STDIN: i32 = 0;
const STDOUT: i32 = 1;
const STDERR: i32 = 2;
const READ_BUF: usize = 4096;
const COL: usize = 16;

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

#[panic_handler]
fn panic(_info: &PanicInfo) -> ! {
    write_str(STDERR, b"[rust-od] panic\n");
    unsafe {
        sys_exit(1);
    }
}

const HEX: &[u8; 16] = b"0123456789abcdef";

// Render `n` as a 7-char zero-padded lowercase hex.
fn fmt_off(n: u64, out: &mut [u8; 7]) {
    for i in (0..7).rev() {
        out[i] = HEX[(n >> ((6 - i) * 4) & 0xF) as usize];
    }
}

// Render one row given the offset and 1..=16 raw bytes.
fn emit_row(offset: u64, row: &[u8]) -> bool {
    // 7-char hex offset + ' '
    let mut off_buf = [0u8; 7];
    fmt_off(offset, &mut off_buf);
    if !write_all(STDOUT, &off_buf) { return false; }
    if !write_all(STDOUT, b" ") { return false; }

    // 16 hex pairs, space-separated, with an extra space between bytes
    // 7 and 8 to match GNU od's two-half-rows layout. Each pair takes
    // 3 chars (XX + space); the gutter at index 24 gets one extra
    // space pushed in by `extra`. Total len = COL*3 + 1 = 49.
    let mut hex_buf = [b' '; COL * 3 + 1];
    for i in 0..COL {
        let extra = if i >= COL / 2 { 1 } else { 0 };
        let off = i * 3 + extra;
        if i < row.len() {
            hex_buf[off] = HEX[(row[i] >> 4) as usize];
            hex_buf[off + 1] = HEX[(row[i] & 0xF) as usize];
        } else {
            // pad missing bytes with two spaces — keeps the ASCII column
            // aligned even when the final row is short.
            hex_buf[off] = b' ';
            hex_buf[off + 1] = b' ';
        }
        hex_buf[off + 2] = b' ';
    }
    if !write_all(STDOUT, &hex_buf) { return false; }

    // ASCII gutter: " |xxxxxxxxxxxxxxxx|\n"
    if !write_all(STDOUT, b" |") { return false; }
    let mut ascii_buf = [b'.'; COL];
    for i in 0..row.len() {
        let c = row[i];
        ascii_buf[i] = if (0x20..=0x7e).contains(&c) { c } else { b'.' };
    }
    if !write_all(STDOUT, &ascii_buf[..row.len()]) { return false; }
    if !write_all(STDOUT, b"|\n") { return false; }
    true
}

// Pump an fd into the running-offset/row state. Multiple files share
// the same state so the offsets line up as one concatenated stream
// (matching GNU od's `od file1 file2`).
struct OdState {
    row: [u8; COL],
    row_len: usize,
    offset: u64,
}

fn dump_fd(fd: i32, st: &mut OdState) -> bool {
    let mut buf = [0u8; READ_BUF];
    loop {
        let n = unsafe {
            syscall3(sysn::READ, fd as u64, buf.as_mut_ptr() as u64, buf.len() as u64)
        };
        if n < 0 { return false; }
        if n == 0 { break; }
        let chunk = &buf[..n as usize];
        for &b in chunk {
            st.row[st.row_len] = b;
            st.row_len += 1;
            if st.row_len == COL {
                if !emit_row(st.offset, &st.row[..st.row_len]) { return false; }
                st.offset += COL as u64;
                st.row_len = 0;
            }
        }
    }
    true
}

fn finalize(st: &mut OdState) -> bool {
    if st.row_len > 0 {
        if !emit_row(st.offset, &st.row[..st.row_len]) { return false; }
        st.offset += st.row_len as u64;
        st.row_len = 0;
    }
    // Final "next offset" line mirrors GNU od's terminating address.
    let mut off_buf = [0u8; 7];
    fmt_off(st.offset, &mut off_buf);
    if !write_all(STDOUT, &off_buf) { return false; }
    if !write_all(STDOUT, b"\n") { return false; }
    true
}

#[unsafe(no_mangle)]
pub extern "C" fn main(argc: i32, argv: *const *const u8, _envp: *const *const u8) -> i32 {
    if argc >= 2 {
        let first = unsafe { *argv.add(1) };
        if !first.is_null() && (first as usize) >= 0x10000 {
            let want = b"--help";
            let mut ok = true;
            for i in 0..want.len() {
                if unsafe { *first.add(i) } != want[i] { ok = false; break; }
            }
            if ok && unsafe { *first.add(want.len()) } == 0 {
                let help: &[u8] = b"\
Usage: rust-od [FILE]...
Dump each FILE as 16-byte hex rows with a 7-digit hex offset. With
multiple FILEs the offset is continuous (concatenated-stream view).
With no FILE (or FILE = '-') reads stdin.

  --help    show this help and exit
\0";
                let len = help.len() - 1;
                unsafe { let _ = syscall3(sysn::WRITE, STDOUT as u64,
                                          help.as_ptr() as u64, len as u64); }
                return 0;
            }
        }
    }
    let mut st = OdState { row: [0u8; COL], row_len: 0, offset: 0 };
    let mut had_error = false;

    if argc < 2 {
        if !dump_fd(STDIN, &mut st) { had_error = true; }
    } else {
        for ai in 1..argc {
            let p = unsafe { *argv.add(ai as usize) };
            if p.is_null() || (p as usize) < 0x10000 {
                had_error = true;
                continue;
            }
            // "-" reads stdin (matches GNU od convention).
            let mut nlen = 0usize;
            unsafe { while *p.add(nlen) != 0 { nlen += 1; } }
            let is_dash = nlen == 1 && unsafe { *p } == b'-';
            if is_dash {
                if !dump_fd(STDIN, &mut st) { had_error = true; }
                continue;
            }
            let fd = unsafe {
                syscall4(sysn::OPENAT, AT_FDCWD as u64, p as u64, O_RDONLY, 0) as i32
            };
            if fd < 0 {
                write_str(STDERR, b"rust-od: cannot open '");
                unsafe { let _ = syscall3(sysn::WRITE, STDERR as u64, p as u64, nlen as u64); }
                write_str(STDERR, b"'\n");
                had_error = true;
                continue;
            }
            if !dump_fd(fd, &mut st) { had_error = true; }
            unsafe { let _ = syscall1(sysn::CLOSE, fd as u64); }
        }
    }

    if !finalize(&mut st) { had_error = true; }
    if had_error { 1 } else { 0 }
}
