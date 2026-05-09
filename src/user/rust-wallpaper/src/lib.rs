// SPDX-License-Identifier: MPL-2.0
//
// rust-wallpaper — CLI counterpart of the wl-wallpaper GUI picker.
//
//   rust-wallpaper                 list presets, mark the active one
//   rust-wallpaper --get           print the current preset key
//   rust-wallpaper <preset-key>    write the key to /etc/wallpaper.conf
//                                  (falls back to /run/wallpaper.conf)
//
// The compositor's poller reads that file once per second so any
// successful set takes effect within ~1 s. Preset list is kept in
// sync with wl-wallpaper; this is the canonical source for headless
// or scripted use (e.g. /etc/profile chooses the boot wallpaper).

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
const O_TRUNC: u64 = 0o1000;
const STDOUT: i32 = 1;
const STDERR: i32 = 2;

const PRESETS: &[(&[u8], &[u8])] = &[
    (b"nightsky", b"Night Sky (default)"),
    (b"ocean",    b"Deep Ocean"),
    (b"forest",   b"Forest Dawn"),
    (b"sunset",   b"Sunset Dunes"),
    (b"lavender", b"Lavender Dusk"),
    (b"slate",    b"Slate Studio"),
    (b"solarl",   b"Solarized Light"),
    (b"solard",   b"Solarized Dark"),
];

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

#[panic_handler]
fn panic(_info: &PanicInfo) -> ! {
    write_str(STDERR, b"[rust-wallpaper] panic\n");
    unsafe {
        sys_exit(1);
    }
}

fn cstr_eq(p: *const u8, s: &[u8]) -> bool {
    for (i, &b) in s.iter().enumerate() {
        if unsafe { *p.add(i) } != b {
            return false;
        }
    }
    unsafe { *p.add(s.len()) == 0 }
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

fn open_read(path: &[u8]) -> i32 {
    unsafe {
        syscall4(sysn::OPENAT, AT_FDCWD as u64, path.as_ptr() as u64, O_RDONLY, 0) as i32
    }
}

fn open_write(path: &[u8]) -> i32 {
    unsafe {
        syscall4(
            sysn::OPENAT,
            AT_FDCWD as u64,
            path.as_ptr() as u64,
            O_WRONLY | O_CREAT | O_TRUNC,
            0o644,
        ) as i32
    }
}

fn close_fd(fd: i32) {
    unsafe {
        let _ = syscall1(sysn::CLOSE, fd as u64);
    }
}

// Read /etc/wallpaper.conf (or /run/...) into buf, return slice of the
// first non-empty line (without trailing whitespace). Empty if missing.
fn read_active<'a>(buf: &'a mut [u8; 64]) -> &'a [u8] {
    let mut fd = open_read(b"/etc/wallpaper.conf\0");
    if fd < 0 {
        fd = open_read(b"/run/wallpaper.conf\0");
    }
    if fd < 0 {
        return &[];
    }
    let n = unsafe { syscall3(sysn::READ, fd as u64, buf.as_mut_ptr() as u64, buf.len() as u64) };
    close_fd(fd);
    if n <= 0 {
        return &[];
    }
    let n = n as usize;
    let mut end = 0usize;
    while end < n {
        let c = buf[end];
        if c == b'\n' || c == b'\r' || c == b' ' || c == b'\t' || c == 0 {
            break;
        }
        end += 1;
    }
    &buf[..end]
}

fn slice_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    for i in 0..a.len() {
        if a[i] != b[i] {
            return false;
        }
    }
    true
}

fn list_presets() -> i32 {
    let mut buf = [0u8; 64];
    let active = read_active(&mut buf);
    write_str(STDOUT, b"Available wallpaper presets:\n");
    for &(key, label) in PRESETS {
        let mark: &[u8] = if slice_eq(active, key) { b"  * " } else { b"    " };
        write_str(STDOUT, mark);
        write_str(STDOUT, key);
        // Pad to a fixed column for the label.
        let pad = b"                ";
        let pad_n = if key.len() < 12 { 12 - key.len() } else { 1 };
        write_str(STDOUT, &pad[..pad_n]);
        write_str(STDOUT, label);
        write_str(STDOUT, b"\n");
    }
    if active.is_empty() {
        write_str(STDOUT, b"\n(no wallpaper.conf yet - compositor will use default)\n");
    }
    0
}

fn print_active() -> i32 {
    let mut buf = [0u8; 64];
    let active = read_active(&mut buf);
    if active.is_empty() {
        write_str(STDOUT, b"(default)\n");
    } else {
        write_str(STDOUT, active);
        write_str(STDOUT, b"\n");
    }
    0
}

fn set_active(key: &[u8]) -> i32 {
    // Validate against the preset table so we don't silently write
    // garbage that the compositor would log as "unknown preset".
    let mut ok = false;
    for &(k, _) in PRESETS {
        if slice_eq(k, key) {
            ok = true;
            break;
        }
    }
    if !ok {
        write_str(STDERR, b"rust-wallpaper: unknown preset '");
        write_str(STDERR, key);
        write_str(STDERR, b"'\n");
        write_str(STDERR, b"run rust-wallpaper without arguments to list valid keys.\n");
        return 1;
    }
    let mut fd = open_write(b"/etc/wallpaper.conf\0");
    if fd < 0 {
        fd = open_write(b"/run/wallpaper.conf\0");
    }
    if fd < 0 {
        write_str(STDERR, b"rust-wallpaper: cannot open wallpaper.conf for write\n");
        return 1;
    }
    let mut wrote_ok = write_all(fd, key);
    if wrote_ok {
        wrote_ok = write_all(fd, b"\n");
    }
    close_fd(fd);
    if !wrote_ok {
        write_str(STDERR, b"rust-wallpaper: short write to wallpaper.conf\n");
        return 1;
    }
    write_str(STDOUT, b"wallpaper set to ");
    write_str(STDOUT, key);
    write_str(STDOUT, b"\n");
    0
}

#[unsafe(no_mangle)]
pub extern "C" fn main(argc: i32, argv: *const *const u8, _envp: *const *const u8) -> i32 {
    if argc < 2 {
        return list_presets();
    }
    let arg = unsafe { *argv.add(1) };
    if arg.is_null() || (arg as usize) < 0x10000 {
        return list_presets();
    }
    if cstr_eq(arg, b"--get") || cstr_eq(arg, b"-g") {
        return print_active();
    }
    if cstr_eq(arg, b"--list") || cstr_eq(arg, b"-l") {
        return list_presets();
    }
    if cstr_eq(arg, b"--help") || cstr_eq(arg, b"-h") {
        write_str(
            STDOUT,
            b"usage: rust-wallpaper [--list | --get | <preset-key>]\n",
        );
        return 0;
    }
    let n = cstr_len(arg);
    let key = unsafe { core::slice::from_raw_parts(arg, n) };
    set_active(key)
}
